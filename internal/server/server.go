package server

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gorilla/websocket"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runnerfleet/internal/backups"
	"runnerfleet/internal/capacity"
	"runnerfleet/internal/github"
	"runnerfleet/internal/security"
	"runnerfleet/internal/store"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Config struct {
	DataDir, Origin, AgentURL, WebDir string
	Dev                               bool
}
type Server struct {
	Store    *store.Store
	Cfg      Config
	Key      []byte
	CA       *security.CA
	mu       sync.Mutex
	channels map[string]*websocket.Conn
	limits   map[string]*limit
	ctx      context.Context
	ghClient *github.Client
}
type limit struct {
	count int
	until time.Time
}

func New(cfg Config) (*Server, error) {
	s, e := store.Open(filepath.Join(cfg.DataDir, "fleet.sqlite"))
	if e != nil {
		return nil, e
	}
	key, e := security.Key(filepath.Join(cfg.DataDir, "master.key"))
	if e != nil {
		return nil, e
	}
	ca, e := security.LoadCA(filepath.Join(cfg.DataDir, "identity"))
	if e != nil {
		return nil, e
	}
	v := &Server{Store: s, Cfg: cfg, Key: key, CA: ca, channels: map[string]*websocket.Conn{}, limits: map[string]*limit{}}
	if s.Get("installation_id") == "" {
		s.Set("installation_id", security.Random(16))
	}
	return v, nil
}
func (s *Server) SetupCode() (string, error) {
	var n int
	s.Store.DB.QueryRow(`SELECT COUNT(*) FROM admin`).Scan(&n)
	if n > 0 {
		return "", errors.New("administrator already exists")
	}
	code := security.Random(32)
	return code, s.Store.Set("setup", store.JSON(map[string]any{"hash": security.Hash(code), "expires": time.Now().Add(30 * time.Minute).Unix()}))
}
func (s *Server) Recover() (string, error) {
	s.Store.DB.Exec(`DELETE FROM sessions`)
	code := security.Random(32)
	e := s.Store.Set("recover", store.JSON(map[string]any{"hash": security.Hash(code), "expires": time.Now().Add(15 * time.Minute).Unix()}))
	s.Store.Audit("local-cli", "recovery.create", "admin", "sessions invalidated")
	return code, e
}
func write(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
func fail(w http.ResponseWriter, status int, msg string) {
	write(w, status, map[string]any{"error": msg})
}
func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 2<<20)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if e := d.Decode(v); e != nil {
		fail(w, 400, "invalid request: "+e.Error())
		return false
	}
	if e := d.Decode(new(any)); e != io.EOF {
		fail(w, 400, "one JSON object required")
		return false
	}
	return true
}
func (s *Server) Handler() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("GET /api/health", func(w http.ResponseWriter, r *http.Request) { write(w, 200, map[string]any{"ok": true, "protocol": 1}) })
	m.HandleFunc("GET /api/auth/status", s.authStatus)
	m.HandleFunc("POST /api/auth/setup", s.setup)
	m.HandleFunc("POST /api/auth/login", s.login)
	m.HandleFunc("POST /api/auth/recover", s.recover)
	m.HandleFunc("POST /api/enroll", s.enroll)
	m.HandleFunc("POST /api/github/webhook", s.webhook)
	for _, route := range []struct {
		pattern string
		fn      http.HandlerFunc
	}{
		{"GET /api/state", s.state}, {"GET /api/events", s.events}, {"POST /api/auth/logout", s.logout}, {"POST /api/auth/reauth", s.reauth}, {"POST /api/auth/totp/start", s.totpStart}, {"POST /api/auth/totp/enable", s.totpEnable}, {"GET /api/audit", s.audit},
		{"GET /api/settings", s.settingsGet}, {"PUT /api/settings", s.settingsPut}, {"PUT /api/github/app", s.appPut}, {"POST /api/github/groups", s.createGroup}, {"POST /api/github/refresh", s.refresh}, {"POST /api/github/scan", s.scanRequest}, {"POST /api/github/migration", s.migration}, {"GET /api/jobs/{id}/logs", s.jobLogs},
		{"POST /api/enrollment", s.enrollment}, {"PUT /api/machines/{id}", s.machinePut}, {"POST /api/machines/{id}/revoke", s.machineRevoke}, {"POST /api/machines/{id}/drain", s.machineDrain}, {"POST /api/machines/{id}/resume", s.machineResume}, {"POST /api/machines/{id}/doctor", s.machineDoctor}, {"POST /api/machines/{id}/update", s.machineUpdate},
		{"POST /api/pools", s.poolPut}, {"PUT /api/pools/{id}", s.poolPut}, {"DELETE /api/pools/{id}", s.poolDelete}, {"POST /api/instances/{id}/drain", s.instanceDrain},
		{"POST /api/alerts/{id}/ack", s.alertAck}, {"PUT /api/backups/config", s.backupConfig}, {"POST /api/backups/run", s.backupRequest}, {"POST /api/bootstrap/ssh", s.sshBootstrap}, {"GET /api/export", s.export},
	} {
		m.Handle(route.pattern, s.auth(route.fn))
	}
	m.HandleFunc("GET /", s.static)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'")
		if strings.HasPrefix(r.URL.Path, "/api/") {
			w.Header().Set("Cache-Control", "no-store")
		}
		if r.Method != "GET" && r.URL.Path != "/api/github/webhook" && r.URL.Path != "/api/enroll" {
			origin := r.Header.Get("Origin")
			if origin != "" && origin != s.Cfg.Origin {
				fail(w, 403, "origin denied")
				return
			}
		}
		m.ServeHTTP(w, r)
	})
}
func (s *Server) static(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/api/") {
		fail(w, 404, "not found")
		return
	}
	p := filepath.Join(s.Cfg.WebDir, filepath.Clean("/"+r.URL.Path))
	if f, e := os.Stat(p); e != nil || f.IsDir() {
		p = filepath.Join(s.Cfg.WebDir, "index.html")
	}
	if strings.HasSuffix(p, ".html") {
		if b, e := os.ReadFile(p); e == nil {
			hashes := []string{}
			pattern := regexp.MustCompile(`(?s)<script[^>]*>(.*?)</script>`)
			for _, match := range pattern.FindAllSubmatch(b, -1) {
				if len(match[1]) == 0 {
					continue
				}
				h := sha256.Sum256(match[1])
				hashes = append(hashes, "'sha256-"+base64.StdEncoding.EncodeToString(h[:])+"'")
			}
			w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' "+strings.Join(hashes, " ")+"; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'")
		}
	}
	http.ServeFile(w, r, p)
}
func (s *Server) allowed(key string, max int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	v := s.limits[key]
	if v == nil || now.After(v.until) {
		v = &limit{until: now.Add(5 * time.Minute)}
		s.limits[key] = v
	}
	v.count++
	if len(s.limits) > 10000 {
		for k, a := range s.limits {
			if now.After(a.until) {
				delete(s.limits, k)
			}
		}
	}
	return v.count <= max
}
func ip(r *http.Request) string { h, _, _ := net.SplitHostPort(r.RemoteAddr); return h }
func (s *Server) auth(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, e := r.Cookie("rf_session")
		if e != nil {
			fail(w, 401, "authentication required")
			return
		}
		var csrf string
		var expires int64
		if e = s.Store.DB.QueryRow(`SELECT csrf,expires FROM sessions WHERE hash=?`, security.Hash(c.Value)).Scan(&csrf, &expires); e != nil || expires < time.Now().Unix() {
			fail(w, 401, "session expired")
			return
		}
		if r.Method != "GET" && !security.Equal(csrf, r.Header.Get("X-CSRF-Token")) {
			fail(w, 403, "CSRF token required")
			return
		}
		next(w, r)
	})
}
func (s *Server) elevated(w http.ResponseWriter, r *http.Request) bool {
	c, _ := r.Cookie("rf_session")
	if c == nil {
		fail(w, 401, "authentication required")
		return false
	}
	v, _ := strconv.ParseInt(s.Store.Get("elevated:"+security.Hash(c.Value)), 10, 64)
	if v < time.Now().Unix() {
		fail(w, 403, "reauthentication required")
		return false
	}
	return true
}
func (s *Server) authStatus(w http.ResponseWriter, r *http.Request) {
	var n int
	s.Store.DB.QueryRow(`SELECT COUNT(*) FROM admin`).Scan(&n)
	v := map[string]any{"setup_required": n == 0, "authenticated": false}
	if c, e := r.Cookie("rf_session"); e == nil {
		var csrf string
		var expires int64
		if s.Store.DB.QueryRow(`SELECT csrf,expires FROM sessions WHERE hash=?`, security.Hash(c.Value)).Scan(&csrf, &expires) == nil && expires > time.Now().Unix() {
			v["authenticated"] = true
			v["csrf"] = csrf
			var email, totp string
			s.Store.DB.QueryRow(`SELECT email,totp FROM admin WHERE id=1`).Scan(&email, &totp)
			v["email"] = email
			v["totp_enabled"] = totp != ""
		}
	}
	write(w, 200, v)
}
func (s *Server) setup(w http.ResponseWriter, r *http.Request) {
	if !s.allowed("setup:"+ip(r), 5) {
		fail(w, 429, "try later")
		return
	}
	var v struct{ Code, Email, Password string }
	if !decode(w, r, &v) {
		return
	}
	if len(v.Password) < 12 || !strings.Contains(v.Email, "@") {
		fail(w, 400, "email and password (12+ characters) required")
		return
	}
	var code struct {
		Hash    string
		Expires int64
	}
	json.Unmarshal([]byte(s.Store.Get("setup")), &code)
	if code.Expires < time.Now().Unix() || !security.Equal(code.Hash, security.Hash(v.Code)) {
		fail(w, 403, "invalid setup code")
		return
	}
	tx, e := s.Store.DB.Begin()
	if e != nil {
		fail(w, 500, "database unavailable")
		return
	}
	defer tx.Rollback()
	if _, e = tx.Exec(`INSERT INTO admin(id,email,password) VALUES(1,?,?)`, v.Email, security.Password(v.Password)); e != nil {
		fail(w, 409, "setup already completed")
		return
	}
	tx.Exec(`DELETE FROM kv WHERE key='setup'`)
	if e = tx.Commit(); e != nil {
		fail(w, 500, "setup failed")
		return
	}
	s.Store.Audit("setup", "admin.create", "admin", "success")
	write(w, 201, map[string]any{"ok": true})
}
func (s *Server) credentials(password, otp string) bool {
	var hash, secret, rec string
	if s.Store.DB.QueryRow(`SELECT password,totp,recovery FROM admin WHERE id=1`).Scan(&hash, &secret, &rec) != nil || !security.Verify(hash, password) {
		return false
	}
	if secret == "" {
		return true
	}
	plain, e := security.Open(s.Key, secret)
	if e != nil {
		return false
	}
	if security.TOTP(string(plain), otp, time.Now()) {
		return true
	}
	var codes []string
	json.Unmarshal([]byte(rec), &codes)
	for i, c := range codes {
		if security.Equal(c, security.Hash(otp)) {
			codes = append(codes[:i], codes[i+1:]...)
			res, e := s.Store.DB.Exec(`UPDATE admin SET recovery=? WHERE id=1 AND recovery=?`, store.JSON(codes), rec)
			if e != nil {
				return false
			}
			n, _ := res.RowsAffected()
			return n == 1
		}
	}
	return false
}
func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	if !s.allowed("login:"+ip(r), 15) {
		fail(w, 429, "try later")
		return
	}
	var v struct{ Email, Password, OTP string }
	if !decode(w, r, &v) {
		return
	}
	var email string
	s.Store.DB.QueryRow(`SELECT email FROM admin WHERE id=1`).Scan(&email)
	if !security.Equal(email, v.Email) || !s.credentials(v.Password, v.OTP) {
		fail(w, 401, "invalid credentials")
		return
	}
	sid, csrf := security.Random(32), security.Random(32)
	s.Store.DB.Exec(`INSERT INTO sessions VALUES(?,?,?)`, security.Hash(sid), csrf, time.Now().Add(12*time.Hour).Unix())
	http.SetCookie(w, &http.Cookie{Name: "rf_session", Value: sid, Path: "/", Secure: !s.Cfg.Dev, HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: 43200})
	s.Store.Audit("admin", "login", "session", "success")
	write(w, 200, map[string]any{"csrf": csrf})
}
func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	c, _ := r.Cookie("rf_session")
	s.Store.DB.Exec(`DELETE FROM sessions WHERE hash=?`, security.Hash(c.Value))
	http.SetCookie(w, &http.Cookie{Name: "rf_session", Path: "/", MaxAge: -1, Secure: !s.Cfg.Dev, HttpOnly: true})
	write(w, 200, map[string]any{"ok": true})
}
func (s *Server) reauth(w http.ResponseWriter, r *http.Request) {
	if !s.allowed("reauth:"+ip(r), 10) {
		fail(w, 429, "try later")
		return
	}
	var v struct{ Password, OTP string }
	if !decode(w, r, &v) {
		return
	}
	if !s.credentials(v.Password, v.OTP) {
		fail(w, 401, "invalid credentials")
		return
	}
	c, _ := r.Cookie("rf_session")
	s.Store.Set("elevated:"+security.Hash(c.Value), fmt.Sprint(time.Now().Add(5*time.Minute).Unix()))
	write(w, 200, map[string]any{"ok": true})
}
func (s *Server) recover(w http.ResponseWriter, r *http.Request) {
	if !s.allowed("recover:"+ip(r), 5) {
		fail(w, 429, "try later")
		return
	}
	var v struct{ Code, Password string }
	if !decode(w, r, &v) {
		return
	}
	raw := s.Store.Get("recover")
	var code struct {
		Hash    string
		Expires int64
	}
	json.Unmarshal([]byte(raw), &code)
	if len(v.Password) < 12 || code.Expires < time.Now().Unix() || !security.Equal(code.Hash, security.Hash(v.Code)) {
		fail(w, 403, "invalid recovery")
		return
	}
	tx, e := s.Store.DB.Begin()
	if e != nil {
		fail(w, 500, "database error")
		return
	}
	defer tx.Rollback()
	res, e := tx.Exec(`DELETE FROM kv WHERE key='recover' AND value=?`, raw)
	if e != nil {
		fail(w, 500, "recovery failed")
		return
	}
	n, _ := res.RowsAffected()
	if n != 1 {
		fail(w, 403, "code already used")
		return
	}
	_, e = tx.Exec(`UPDATE admin SET password=?,totp='',recovery='[]' WHERE id=1`, security.Password(v.Password))
	if e != nil {
		fail(w, 500, "recovery failed")
		return
	}
	tx.Exec(`DELETE FROM sessions`)
	if e = tx.Commit(); e != nil {
		fail(w, 500, "recovery failed")
		return
	}
	s.Store.Audit("recovery", "admin.reset", "admin", "success")
	write(w, 200, map[string]any{"ok": true})
}
func (s *Server) totpStart(w http.ResponseWriter, r *http.Request) {
	if !s.elevated(w, r) {
		return
	}
	secret := security.Secret()
	enc, _ := security.Seal(s.Key, []byte(secret))
	s.Store.Set("totp_pending", enc)
	s.Store.Set("totp_pending_exp", fmt.Sprint(time.Now().Add(10*time.Minute).Unix()))
	write(w, 200, map[string]any{"secret": secret, "uri": "otpauth://totp/RunnerFleet:admin?secret=" + secret + "&issuer=RunnerFleet"})
}
func (s *Server) totpEnable(w http.ResponseWriter, r *http.Request) {
	if !s.elevated(w, r) {
		return
	}
	var v struct{ OTP string }
	if !decode(w, r, &v) {
		return
	}
	secret, e := security.Open(s.Key, s.Store.Get("totp_pending"))
	exp, _ := strconv.ParseInt(s.Store.Get("totp_pending_exp"), 10, 64)
	if e != nil || exp < time.Now().Unix() || !security.TOTP(string(secret), v.OTP, time.Now()) {
		fail(w, 400, "invalid or expired TOTP")
		return
	}
	codes, hashes := []string{}, []string{}
	for i := 0; i < 10; i++ {
		c := security.Random(12)
		codes = append(codes, c)
		hashes = append(hashes, security.Hash(c))
	}
	s.Store.DB.Exec(`UPDATE admin SET totp=?,recovery=? WHERE id=1`, s.Store.Get("totp_pending"), store.JSON(hashes))
	s.Store.Set("totp_pending", "")
	s.Store.Audit("admin", "totp.enable", "admin", "success")
	write(w, 200, map[string]any{"recovery_codes": codes})
}
func (s *Server) snapshot() map[string]any {
	v := map[string]any{}
	for _, k := range []string{"machine", "pool", "installation", "repository", "workflow", "job", "runner", "group", "scan", "alert", "backup", "agentlog"} {
		a, e := s.Store.List(k)
		if e != nil {
			v[k] = []any{}
			v[k+"_error"] = e.Error()
		} else {
			v[k] = a
		}
	}
	instances, e := capacity.List(s.Store)
	if e == nil {
		v["instances"] = instances
	}
	v["analytics"] = s.analytics()
	v["time"] = time.Now().Unix()
	return v
}
func (s *Server) state(w http.ResponseWriter, r *http.Request) { write(w, 200, s.snapshot()) }
func (s *Server) events(w http.ResponseWriter, r *http.Request) {
	f, ok := w.(http.Flusher)
	if !ok {
		fail(w, 500, "stream unsupported")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("X-Accel-Buffering", "no")
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	deadline := time.NewTimer(10 * time.Minute)
	defer deadline.Stop()
	for {
		fmt.Fprintf(w, "event: state\ndata: %s\n\n", store.JSON(s.snapshot()))
		f.Flush()
		select {
		case <-r.Context().Done():
			return
		case <-deadline.C:
			return
		case <-t.C:
		}
	}
}
func (s *Server) audit(w http.ResponseWriter, r *http.Request) {
	a, e := s.Store.AuditList()
	if e != nil {
		fail(w, 500, "audit unavailable")
		return
	}
	write(w, 200, a)
}
func (s *Server) settingsGet(w http.ResponseWriter, r *http.Request) {
	var v map[string]any
	json.Unmarshal([]byte(s.Store.Get("settings")), &v)
	if v == nil {
		v = map[string]any{"log_days": 14, "history_days": 90, "audit_days": 180, "scan_days": 30, "scan_hours": 6, "org_max_slots": 8, "alert_webhook": ""}
	}
	v["github_configured"] = s.Store.Get("github_app") != ""
	v["agent_url"] = s.Cfg.AgentURL
	var cfg backups.Config
	s.secretGet("backup_config", &cfg)
	v["backup_configured"] = cfg.Password != ""
	write(w, 200, v)
}
func (s *Server) settingsPut(w http.ResponseWriter, r *http.Request) {
	if !s.elevated(w, r) {
		return
	}
	var v struct {
		LogDays             int     `json:"log_days"`
		HistoryDays         int     `json:"history_days"`
		AuditDays           int     `json:"audit_days"`
		ScanDays            int     `json:"scan_days"`
		ScanHours           int     `json:"scan_hours"`
		OrgMaxSlots         int     `json:"org_max_slots"`
		AlertWebhook        string  `json:"alert_webhook"`
		LinuxPricePerMinute float64 `json:"linux_price_per_minute"`
		PriceReference      string  `json:"price_reference"`
	}
	if !decode(w, r, &v) {
		return
	}
	if v.LogDays < 1 || v.HistoryDays < 1 || v.AuditDays < 1 || v.ScanDays < 1 || v.ScanDays > 90 || v.ScanHours < 1 || v.OrgMaxSlots < 1 {
		fail(w, 400, "invalid retention or capacity")
		return
	}
	if v.AlertWebhook != "" {
		u, e := url.Parse(v.AlertWebhook)
		if e != nil || u.Scheme != "https" || u.Hostname() == "" {
			fail(w, 400, "HTTPS webhook required")
			return
		}
	}
	s.Store.Set("settings", store.JSON(v))
	s.Store.Audit("admin", "settings.update", "settings", "success")
	write(w, 200, map[string]any{"ok": true})
}
func (s *Server) secretPut(key string, v any) error {
	b, e := security.Seal(s.Key, []byte(store.JSON(v)))
	if e != nil {
		return e
	}
	return s.Store.Set(key, b)
}
func (s *Server) secretGet(key string, v any) error {
	b, e := security.Open(s.Key, s.Store.Get(key))
	if e != nil {
		return e
	}
	return json.Unmarshal(b, v)
}

type appConfig struct {
	AppID         string `json:"app_id"`
	PrivateKey    string `json:"private_key"`
	WebhookSecret string `json:"webhook_secret"`
}

func (s *Server) gh() (*github.Client, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ghClient != nil {
		return s.ghClient, nil
	}
	var v appConfig
	if e := s.secretGet("github_app", &v); e != nil {
		return nil, errors.New("GitHub App not configured")
	}
	c := github.New(v.AppID, v.PrivateKey)
	if _, e := c.JWT(); e != nil {
		return nil, e
	}
	s.ghClient = c
	return c, nil
}
func (s *Server) appPut(w http.ResponseWriter, r *http.Request) {
	if !s.elevated(w, r) {
		return
	}
	var v appConfig
	if !decode(w, r, &v) {
		return
	}
	if _, e := github.New(v.AppID, v.PrivateKey).JWT(); e != nil || len(v.WebhookSecret) < 24 {
		fail(w, 400, "valid RSA PEM, App ID and strong webhook secret required")
		return
	}
	if e := s.secretPut("github_app", v); e != nil {
		fail(w, 500, "save failed")
		return
	}
	s.mu.Lock()
	s.ghClient = nil
	s.mu.Unlock()
	s.Store.Audit("admin", "github.configure", "app", "success")
	write(w, 200, map[string]any{"ok": true})
}
func (s *Server) refresh(w http.ResponseWriter, r *http.Request) {
	id := security.Random(12)
	s.Store.Task(id, "refresh", nil)
	write(w, 202, map[string]any{"task": id})
}
func (s *Server) scanRequest(w http.ResponseWriter, r *http.Request) {
	var v struct {
		Installation int64 `json:"installation"`
	}
	if !decode(w, r, &v) {
		return
	}
	if v.Installation < 1 {
		fail(w, 400, "installation required")
		return
	}
	id := security.Random(12)
	s.Store.Task(id, "scan", v)
	write(w, 202, map[string]any{"task": id})
}
func (s *Server) enrollment(w http.ResponseWriter, r *http.Request) {
	if !s.elevated(w, r) {
		return
	}
	c := security.Random(32)
	s.Store.DB.Exec(`INSERT INTO enrollment(hash,expires) VALUES(?,?)`, security.Hash(c), time.Now().Add(15*time.Minute).Unix())
	s.Store.Audit("admin", "machine.enrollment.create", "machine", "success")
	write(w, 201, map[string]any{"code": c, "expires_in": 900, "server": s.Cfg.Origin, "agent_url": s.Cfg.AgentURL})
}
func (s *Server) enroll(w http.ResponseWriter, r *http.Request) {
	if !s.allowed("enroll:"+ip(r), 10) {
		fail(w, 429, "try later")
		return
	}
	var v struct{ Code, CSR, Name, Arch string }
	if !decode(w, r, &v) {
		return
	}
	if v.Name == "" || len(v.Name) > 100 || v.Arch != "amd64" && v.Arch != "arm64" {
		fail(w, 400, "invalid machine")
		return
	}
	id := security.Random(16)
	cert, serial, e := s.CA.Issue(v.CSR, id)
	if e != nil {
		fail(w, 400, "invalid CSR")
		return
	}
	tx, e := s.Store.DB.Begin()
	if e != nil {
		fail(w, 500, "database unavailable")
		return
	}
	defer tx.Rollback()
	res, e := tx.Exec(`UPDATE enrollment SET used=1 WHERE hash=? AND used=0 AND expires>?`, security.Hash(v.Code), time.Now().Unix())
	if e != nil {
		fail(w, 500, "enrollment failed")
		return
	}
	n, _ := res.RowsAffected()
	if n != 1 {
		fail(w, 403, "invalid/used/expired enrollment code")
		return
	}
	m := capacity.Machine{ID: id, Name: v.Name, Arch: v.Arch, State: "enrolling", Serials: []string{serial}, MaxSlots: 1, CPU: 1, MemoryMB: 2048, DiskMB: 4096, Shared: true, Timezone: "UTC", Doctor: map[string]any{}, Telemetry: map[string]any{}}
	_, e = tx.Exec(`INSERT INTO resources VALUES('machine',?,?,?)`, id, store.JSON(m), time.Now().Unix())
	if e != nil {
		fail(w, 500, "enrollment failed")
		return
	}
	if e = tx.Commit(); e != nil {
		fail(w, 500, "enrollment failed")
		return
	}
	s.Store.Audit("enrollment", "machine.create", id, "success")
	write(w, 201, map[string]any{"id": id, "cert": cert, "ca": string(s.CA.PEM), "agent_url": s.Cfg.AgentURL})
}
func (s *Server) machinePut(w http.ResponseWriter, r *http.Request) {
	var v struct {
		Name      string  `json:"name"`
		MaxSlots  int     `json:"max_slots"`
		CPU       float64 `json:"cpu"`
		MemoryMB  int64   `json:"memory_mb"`
		DiskMB    int64   `json:"disk_mb"`
		Shared    bool    `json:"shared"`
		Timezone  string  `json:"timezone"`
		StartHour int     `json:"start_hour"`
		EndHour   int     `json:"end_hour"`
	}
	if !decode(w, r, &v) {
		return
	}
	var m capacity.Machine
	if s.Store.Read("machine", r.PathValue("id"), &m) != nil {
		fail(w, 404, "machine not found")
		return
	}
	if v.MaxSlots < 1 || v.MaxSlots > 100 || v.CPU <= 0 || v.MemoryMB < 512 || v.DiskMB < 1024 || v.StartHour < 0 || v.StartHour > 23 || v.EndHour < 0 || v.EndHour > 23 {
		fail(w, 400, "invalid limits")
		return
	}
	if _, e := time.LoadLocation(v.Timezone); e != nil {
		fail(w, 400, "invalid timezone")
		return
	}
	m.Name = v.Name
	m.MaxSlots = v.MaxSlots
	m.CPU = v.CPU
	m.MemoryMB = v.MemoryMB
	m.DiskMB = v.DiskMB
	m.Shared = v.Shared
	m.Timezone = v.Timezone
	m.StartHour = v.StartHour
	m.EndHour = v.EndHour
	s.Store.Put("machine", m.ID, m)
	s.Store.Audit("admin", "machine.update", m.ID, "success")
	write(w, 200, m)
}
func (s *Server) machineRevoke(w http.ResponseWriter, r *http.Request) {
	if !s.elevated(w, r) {
		return
	}
	var m capacity.Machine
	if s.Store.Read("machine", r.PathValue("id"), &m) != nil {
		fail(w, 404, "machine not found")
		return
	}
	m.State = "revoked"
	s.Store.Put("machine", m.ID, m)
	s.mu.Lock()
	if c := s.channels[m.ID]; c != nil {
		c.Close()
	}
	s.mu.Unlock()
	s.Store.Audit("admin", "machine.revoke", m.ID, "success; reservations preserved")
	write(w, 200, m)
}
func (s *Server) machineDrain(w http.ResponseWriter, r *http.Request) {
	s.machineState(w, r, "draining")
}
func (s *Server) machineResume(w http.ResponseWriter, r *http.Request) {
	s.machineState(w, r, "online")
}
func (s *Server) machineState(w http.ResponseWriter, r *http.Request, state string) {
	var m capacity.Machine
	if s.Store.Read("machine", r.PathValue("id"), &m) != nil {
		fail(w, 404, "not found")
		return
	}
	if m.State == "revoked" {
		fail(w, 409, "revoked identity cannot resume")
		return
	}
	m.State = state
	s.Store.Put("machine", m.ID, m)
	if state == "draining" {
		a, _ := capacity.List(s.Store)
		for _, v := range a {
			if v.Machine == m.ID && capacity.Active(v.State) {
				capacity.Command(s.Store, m.ID, "drain", map[string]any{"instance": v.ID})
			}
		}
	}
	s.Store.Audit("admin", "machine."+state, m.ID, "success")
	write(w, 200, m)
}
func (s *Server) machineDoctor(w http.ResponseWriter, r *http.Request) {
	var m capacity.Machine
	if s.Store.Read("machine", r.PathValue("id"), &m) != nil {
		fail(w, 404, "not found")
		return
	}
	id, e := capacity.Command(s.Store, m.ID, "doctor", nil)
	if e != nil {
		fail(w, 500, "command failed")
		return
	}
	write(w, 202, map[string]any{"command": id})
}
func (s *Server) poolPut(w http.ResponseWriter, r *http.Request) {
	var p capacity.Pool
	if !decode(w, r, &p) {
		return
	}
	if e := capacity.Validate(p); e != nil {
		fail(w, 400, e.Error())
		return
	}
	if _, e := github.Scope(p.Scope, p.Target); e != nil {
		fail(w, 400, e.Error())
		return
	}
	if p.Weight < 1 {
		p.Weight = 1
	}
	id := r.PathValue("id")
	if id == "" {
		id = security.Random(12)
	}
	p.ID = id
	for _, m := range p.Machines {
		var v capacity.Machine
		if s.Store.Read("machine", m, &v) != nil {
			fail(w, 400, "unknown machine")
			return
		}
	}
	if e := s.Store.Put("pool", id, p); e != nil {
		fail(w, 500, "save failed")
		return
	}
	if !p.Enabled {
		instances, _ := capacity.List(s.Store)
		for _, v := range instances {
			if v.Pool == id && capacity.Active(v.State) {
				capacity.Command(s.Store, v.Machine, "drain", map[string]any{"instance": v.ID})
			}
		}
	}
	s.Store.Audit("admin", "pool.save", id, "success")
	write(w, 200, p)
}
func (s *Server) poolDelete(w http.ResponseWriter, r *http.Request) {
	a, _ := capacity.List(s.Store)
	for _, v := range a {
		if v.Pool == r.PathValue("id") && capacity.Active(v.State) {
			fail(w, 409, "drain instances before deleting pool")
			return
		}
	}
	s.Store.Delete("pool", r.PathValue("id"))
	s.Store.Audit("admin", "pool.delete", r.PathValue("id"), "success")
	write(w, 200, map[string]any{"ok": true})
}
func (s *Server) instanceDrain(w http.ResponseWriter, r *http.Request) {
	v, e := capacity.Get(s.Store, r.PathValue("id"))
	if e != nil {
		fail(w, 404, "not found")
		return
	}
	capacity.Command(s.Store, v.Machine, "drain", map[string]any{"instance": v.ID})
	write(w, 202, map[string]any{"ok": true})
}
func (s *Server) alertAck(w http.ResponseWriter, r *http.Request) {
	var v map[string]any
	if s.Store.Read("alert", r.PathValue("id"), &v) != nil {
		fail(w, 404, "not found")
		return
	}
	v["acknowledged"] = true
	s.Store.Put("alert", r.PathValue("id"), v)
	write(w, 200, v)
}
func (s *Server) backupConfig(w http.ResponseWriter, r *http.Request) {
	if !s.elevated(w, r) {
		return
	}
	var v backups.Config
	if !decode(w, r, &v) {
		return
	}
	if len(v.Password) < 12 || v.IntervalHours < 1 || v.RetentionDays < 1 {
		fail(w, 400, "password 12+, interval and retention required")
		return
	}
	if v.Endpoint != "" {
		u, e := url.Parse(v.Endpoint)
		if e != nil || u.Scheme != "https" {
			fail(w, 400, "HTTPS S3 endpoint required")
			return
		}
	}
	v.Installation = s.Store.Get("installation_id")
	s.secretPut("backup_config", v)
	s.Store.Audit("admin", "backup.configure", "backup", "success")
	write(w, 200, map[string]any{"ok": true})
}
func (s *Server) backupRequest(w http.ResponseWriter, r *http.Request) {
	if !s.elevated(w, r) {
		return
	}
	var c backups.Config
	if s.secretGet("backup_config", &c) != nil {
		fail(w, 400, "configure backups first")
		return
	}
	id := security.Random(12)
	s.Store.Task(id, "backup", nil)
	write(w, 202, map[string]any{"task": id})
}
func (s *Server) export(w http.ResponseWriter, r *http.Request) {
	v := s.snapshot()
	v["audit"], _ = s.Store.AuditList()
	w.Header().Set("Content-Disposition", "attachment; filename=runner-fleet-export.json")
	write(w, 200, v)
}
func (s *Server) webhook(w http.ResponseWriter, r *http.Request) {
	var cfg appConfig
	if s.secretGet("github_app", &cfg) != nil {
		fail(w, 503, "App not configured")
		return
	}
	body, e := io.ReadAll(http.MaxBytesReader(w, r.Body, 2<<20))
	if e != nil {
		fail(w, 413, "payload too large")
		return
	}
	mac := hmac.New(sha256.New, []byte(cfg.WebhookSecret))
	mac.Write(body)
	sig := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	if !security.Equal(sig, r.Header.Get("X-Hub-Signature-256")) {
		fail(w, 403, "invalid signature")
		return
	}
	id := r.Header.Get("X-GitHub-Delivery")
	if id == "" || len(id) > 200 {
		fail(w, 400, "delivery ID required")
		return
	}
	tx, e := s.Store.DB.Begin()
	if e != nil {
		fail(w, 500, "database unavailable")
		return
	}
	defer tx.Rollback()
	res, e := tx.Exec(`INSERT OR IGNORE INTO deliveries VALUES(?,?)`, id, time.Now().Unix())
	if e != nil {
		fail(w, 500, "delivery failed")
		return
	}
	n, _ := res.RowsAffected()
	if n == 1 {
		event := r.Header.Get("X-GitHub-Event")
		_, e = tx.Exec(`INSERT INTO tasks(id,kind,data,state,next) VALUES(?,?,?,'pending',?)`, id, "webhook:"+event, string(body), time.Now().Unix())
		if e != nil {
			fail(w, 500, "delivery failed")
			return
		}
	}
	if e = tx.Commit(); e != nil {
		fail(w, 500, "delivery failed")
		return
	}
	write(w, 202, map[string]any{"accepted": true, "duplicate": n == 0})
}
func (s *Server) AgentTLS() *tls.Config {
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(s.CA.PEM)
	return &tls.Config{MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool}
}

var _ = context.Background
var _ = sql.ErrNoRows

func (s *Server) machineUpdate(w http.ResponseWriter, r *http.Request) {
	if !s.elevated(w, r) {
		return
	}
	var v struct {
		URL string `json:"url"`
	}
	if !decode(w, r, &v) {
		return
	}
	if !strings.HasPrefix(v.URL, "https://") {
		fail(w, 400, "HTTPS release directory required")
		return
	}
	var m capacity.Machine
	if s.Store.Read("machine", r.PathValue("id"), &m) != nil {
		fail(w, 404, "machine not found")
		return
	}
	instances, _ := capacity.List(s.Store)
	for _, v := range instances {
		if v.Machine == m.ID && capacity.Active(v.State) {
			fail(w, 409, "drain all instances before update")
			return
		}
	}
	id, e := capacity.Command(s.Store, m.ID, "update", v)
	if e != nil {
		fail(w, 500, "update command failed")
		return
	}
	s.Store.Audit("admin", "agent.update", m.ID, "scheduled signed release")
	write(w, 202, map[string]any{"command": id})
}
