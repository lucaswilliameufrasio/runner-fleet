package server

import (
	"fmt"
	"net/http"
	"net/url"
	"runnerfleet/internal/bootstrap"
	"runnerfleet/internal/security"
	"strings"
	"time"
)

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'" }
func (s *Server) sshBootstrap(w http.ResponseWriter, r *http.Request) {
	if !s.elevated(w, r) {
		return
	}
	var v struct {
		Host        string `json:"host"`
		Port        int    `json:"port"`
		User        string `json:"user"`
		PrivateKey  string `json:"private_key"`
		Fingerprint string `json:"fingerprint"`
		Name        string `json:"name"`
	}
	if !decode(w, r, &v) {
		return
	}
	if v.Port == 0 {
		v.Port = 22
	}
	u, e := url.Parse(s.Cfg.Origin)
	if e != nil || u.Scheme != "https" {
		fail(w, 400, "HTTPS public origin required for bootstrap")
		return
	}
	code := security.Random(32)
	s.Store.DB.Exec(`INSERT INTO enrollment(hash,expires) VALUES(?,?)`, security.Hash(code), time.Now().Add(15*time.Minute).Unix())
	script := fmt.Sprintf("set -eu\numask 077\nwork=$(mktemp -d)\ntrap 'rm -rf \"$work\"' EXIT\nprintf '%%s' %s > \"$work/code\"\ncurl -fsS --proto '=https' %s -o \"$work/install.sh\"\nRF_SERVER=%s RF_CODE_FILE=\"$work/code\" RF_NAME=%s sh \"$work/install.sh\"\n", shellQuote(code), shellQuote(s.Cfg.Origin+"/downloads/install.sh"), shellQuote(s.Cfg.Origin), shellQuote(v.Name))
	out, e := bootstrap.Install(r.Context(), bootstrap.Request{Host: v.Host, Port: v.Port, User: v.User, PrivateKey: v.PrivateKey, Fingerprint: v.Fingerprint, Installer: script})
	s.Store.DB.Exec(`DELETE FROM enrollment WHERE hash=?`, security.Hash(code))
	if e != nil {
		s.Store.Audit("admin", "bootstrap.ssh", v.Host, "failed")
		fail(w, 502, e.Error())
		return
	}
	s.Store.Audit("admin", "bootstrap.ssh", v.Host, "installed")
	write(w, 200, map[string]any{"result": out})
}
