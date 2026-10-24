package server

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/gorilla/websocket"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runnerfleet/internal/capacity"
	"runnerfleet/internal/github"
	"runnerfleet/internal/security"
	"strings"
	"testing"
	"time"
)

func testServer(t *testing.T) *Server {
	t.Helper()
	s, e := New(Config{DataDir: t.TempDir(), Origin: "http://localhost:8080", Dev: true})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.Store.DB.Close() })
	return s
}
func request(t *testing.T, s *Server, method, path string, v any, cookie *http.Cookie, csrf string) (int, map[string]any, *http.Cookie) {
	t.Helper()
	b, _ := json.Marshal(v)
	r := httptest.NewRequest(method, path, bytes.NewReader(b))
	r.RemoteAddr = "127.0.0.1:1000"
	r.Header.Set("Content-Type", "application/json")
	if cookie != nil {
		r.AddCookie(cookie)
	}
	r.Header.Set("X-CSRF-Token", csrf)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	out := map[string]any{}
	json.Unmarshal(w.Body.Bytes(), &out)
	var c *http.Cookie
	if a := w.Result().Cookies(); len(a) > 0 {
		c = a[0]
	}
	return w.Code, out, c
}
func TestSetupLoginCSRFAndRecovery(t *testing.T) {
	s := testServer(t)
	code, e := s.SetupCode()
	if e != nil {
		t.Fatal(e)
	}
	status, _, _ := request(t, s, "POST", "/api/auth/setup", map[string]any{"code": code, "email": "a@example.com", "password": "a secure password"}, nil, "")
	if status != 201 {
		t.Fatal(status)
	}
	status, _, _ = request(t, s, "POST", "/api/auth/setup", map[string]any{"code": code, "email": "a@example.com", "password": "a secure password"}, nil, "")
	if status < 400 {
		t.Fatal("setup replay accepted")
	}
	status, body, cookie := request(t, s, "POST", "/api/auth/login", map[string]any{"email": "a@example.com", "password": "a secure password"}, nil, "")
	if status != 200 || cookie == nil {
		t.Fatal(status, body)
	}
	csrf := text(body["csrf"])
	status, _, _ = request(t, s, "POST", "/api/enrollment", nil, cookie, "")
	if status != 403 {
		t.Fatal("CSRF accepted", status)
	}
	status, _, _ = request(t, s, "POST", "/api/enrollment", nil, cookie, csrf)
	if status != 403 {
		t.Fatal("elevation bypassed")
	}
	status, _, _ = request(t, s, "POST", "/api/auth/reauth", map[string]any{"password": "a secure password"}, cookie, csrf)
	if status != 200 {
		t.Fatal(status)
	}
	status, _, _ = request(t, s, "POST", "/api/enrollment", nil, cookie, csrf)
	if status != 201 {
		t.Fatal(status)
	}
	recovery, e := s.Recover()
	if e != nil {
		t.Fatal(e)
	}
	status, _, _ = request(t, s, "GET", "/api/state", nil, cookie, "")
	if status != 401 {
		t.Fatal("old session survives recovery")
	}
	status, _, _ = request(t, s, "POST", "/api/auth/recover", map[string]any{"code": recovery, "password": "new secure password"}, nil, "")
	if status != 200 {
		t.Fatal(status)
	}
	status, _, _ = request(t, s, "POST", "/api/auth/recover", map[string]any{"code": recovery, "password": "new secure password"}, nil, "")
	if status != 403 {
		t.Fatal("recovery replay")
	}
}
func enrollTest(t *testing.T, s *Server) (tls.Certificate, string) {
	t.Helper()
	code := security.Random(32)
	s.Store.DB.Exec(`INSERT INTO enrollment(hash,expires) VALUES(?,?)`, security.Hash(code), time.Now().Add(time.Minute).Unix())
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csr, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	v := map[string]any{"code": code, "name": "host", "arch": "amd64", "csr": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr}))}
	status, body, _ := request(t, s, "POST", "/api/enroll", v, nil, "")
	if status != 201 {
		t.Fatal(status, body)
	}
	status, _, _ = request(t, s, "POST", "/api/enroll", v, nil, "")
	if status != 403 {
		t.Fatal("enrollment replay accepted")
	}
	der, _ := x509.MarshalECPrivateKey(key)
	cert, e := tls.X509KeyPair([]byte(text(body["cert"])), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}))
	if e != nil {
		t.Fatal(e)
	}
	return cert, text(body["id"])
}
func TestMTLSHeartbeatAndRevocation(t *testing.T) {
	s := testServer(t)
	s.Cfg.AgentURL = "wss://agents.example.com/agent"
	cert, id := enrollTest(t, s)
	ts := httptest.NewUnstartedServer(s.AgentHandler())
	ts.TLS = s.AgentTLS()
	ts.StartTLS()
	defer ts.Close()
	roots := x509.NewCertPool()
	roots.AddCert(ts.Certificate())
	dial := websocket.Dialer{TLSClientConfig: &tls.Config{RootCAs: roots}}
	if conn, _, e := dial.Dial("wss"+ts.URL[5:]+"/agent", nil); e == nil {
		conn.Close()
		t.Fatal("client without certificate accepted")
	}
	dial.TLSClientConfig.Certificates = []tls.Certificate{cert}
	conn, _, e := dial.Dial("wss"+ts.URL[5:]+"/agent", nil)
	if e != nil {
		t.Fatal(e)
	}
	defer conn.Close()
	e = conn.WriteJSON(map[string]any{"type": "heartbeat", "data": map[string]any{"doctor": map[string]any{"ready": true}, "telemetry": map[string]any{}, "instances": []any{}}})
	if e != nil {
		t.Fatal(e)
	}
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	var out map[string]any
	if e = conn.ReadJSON(&out); e != nil || text(out["type"]) != "policy" {
		t.Fatal(e, out)
	}
	var m capacity.Machine
	s.Store.Read("machine", id, &m)
	if m.State != "online" || m.LastSeen == 0 {
		t.Fatal(m)
	}
	m.State = "revoked"
	s.Store.Put("machine", id, m)
	if c, _, e := dial.Dial("wss"+ts.URL[5:]+"/agent", nil); e == nil {
		c.Close()
		t.Fatal("revoked identity accepted")
	}
}
func TestWebhookDurabilityDedupAndMonotonicJobs(t *testing.T) {
	s := testServer(t)
	s.secretPut("github_app", appConfig{WebhookSecret: "012345678901234567890123456789"})
	payload := []byte(`{"workflow_job":{"id":42,"status":"completed","conclusion":"success"},"repository":{"full_name":"org/api"},"installation":{"id":1}}`)
	mac := hmac.New(sha256.New, []byte("012345678901234567890123456789"))
	mac.Write(payload)
	for i := 0; i < 2; i++ {
		r := httptest.NewRequest("POST", "/api/github/webhook", bytes.NewReader(payload))
		r.Header.Set("X-Hub-Signature-256", "sha256="+hex.EncodeToString(mac.Sum(nil)))
		r.Header.Set("X-GitHub-Delivery", "delivery")
		r.Header.Set("X-GitHub-Event", "workflow_job")
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != 202 {
			t.Fatal(w.Code)
		}
	}
	var n int
	s.Store.DB.QueryRow(`SELECT COUNT(*) FROM tasks`).Scan(&n)
	if n != 1 {
		t.Fatal("duplicate task", n)
	}
	if e := s.processWebhook(t.Context(), "webhook:workflow_job", string(payload)); e != nil {
		t.Fatal(e)
	}
	s.putJob(map[string]any{"id": float64(42), "status": "queued"})
	var job map[string]any
	s.Store.Read("job", "42", &job)
	if job["status"] != "completed" {
		t.Fatal("job regressed")
	}
	r := httptest.NewRequest("POST", "/api/github/webhook", bytes.NewReader(payload))
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("unsigned webhook accepted")
	}
}

var _ = io.EOF

func TestDiscoveryThroughGitHubAPIFixture(t *testing.T) {
	s := testServer(t)
	private, _ := rsa.GenerateKey(rand.Reader, 2048)
	raw, _ := x509.MarshalPKCS8PrivateKey(private)
	client := github.New("7", string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: raw})))
	workflow := "jobs:\n  build:\n    runs-on: ubuntu-latest\n    steps: []\n"
	tokenCalls := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/app/installations/7/access_tokens":
			tokenCalls++
			fmt.Fprintf(w, `{"token":"scoped","expires_at":%q}`, time.Now().Add(time.Hour).UTC().Format(time.RFC3339))
		case "/installation/repositories":
			fmt.Fprint(w, `{"repositories":[{"id":1,"full_name":"acme/api","private":true,"default_branch":"main"}]}`)
		case "/repos/acme/api/contents/.github/workflows":
			fmt.Fprint(w, `[{"path":".github/workflows/build.yml"}]`)
		case "/repos/acme/api/contents/.github/workflows/build.yml":
			fmt.Fprintf(w, `{"sha":"source-sha","content":%q}`, base64.StdEncoding.EncodeToString([]byte(workflow)))
		case "/repos/acme/api/actions/runs":
			fmt.Fprint(w, `{"workflow_runs":[{"id":99,"run_attempt":1}]}`)
		case "/repos/acme/api/actions/runs/99/attempts/1/jobs":
			fmt.Fprint(w, `{"jobs":[{"id":42,"name":"build","status":"completed","conclusion":"success","labels":["ubuntu-latest"],"runner_name":"GitHub Actions 1","started_at":"2026-10-13T10:00:00Z","completed_at":"2026-10-13T10:02:00Z"}]}`)
		case "/repos/acme/api/actions/runners", "/orgs/acme/actions/runners":
			fmt.Fprint(w, `{"runners":[],"total_count":0}`)
		case "/orgs/acme/actions/runner-groups":
			fmt.Fprint(w, `{"runner_groups":[],"total_count":0}`)
		default:
			t.Errorf("unexpected GitHub endpoint %s", r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	defer ts.Close()
	client.Base = ts.URL
	s.ghClient = client
	s.Store.Put("installation", "7", map[string]any{"id": 7, "owner": "acme", "scope_type": "Organization", "active": true})
	if e := s.scanInstallation(t.Context(), 7); e != nil {
		t.Fatal(e)
	}
	workflows, _ := s.Store.List("workflow")
	jobs, _ := s.Store.List("job")
	if len(workflows) != 1 || len(jobs) != 1 || tokenCalls != 1 {
		t.Fatal(len(workflows), len(jobs), tokenCalls)
	}
	var scan map[string]any
	s.Store.Read("scan", "7", &scan)
	if scan["state"] != "completed" {
		t.Fatal(scan)
	}
	analytics := s.analytics()
	if analytics["hosted_minutes"] != float64(2) || analytics["peak_concurrency"] != 1 {
		t.Fatal(analytics)
	}
}

func TestStaticBootstrapGetsExactCSPHash(t *testing.T) {
	s := testServer(t)
	s.Cfg.WebDir = t.TempDir()
	script := "\nconsole.log('boot');\n"
	os.WriteFile(filepath.Join(s.Cfg.WebDir, "index.html"), []byte("<html><script>"+script+"</script></html>"), 0600)
	r := httptest.NewRequest("GET", "/setup", nil)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	sum := sha256.Sum256([]byte(script))
	if w.Code != 200 || !strings.Contains(w.Header().Get("Content-Security-Policy"), "'sha256-"+base64.StdEncoding.EncodeToString(sum[:])+"'") {
		t.Fatal("bootstrap blocked by CSP", w.Code, w.Header())
	}
}
