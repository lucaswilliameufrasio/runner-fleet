package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
)

func download(ctx context.Context, url string, max int64) ([]byte, error) {
	if !strings.HasPrefix(url, "https://") {
		return nil, errors.New("HTTPS required")
	}
	c := &http.Client{Timeout: 2 * time.Minute}
	r, e := http.NewRequestWithContext(ctx, "GET", url, nil)
	if e != nil {
		return nil, e
	}
	res, e := c.Do(r)
	if e != nil {
		return nil, e
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return nil, fmt.Errorf("artifact HTTP %d", res.StatusCode)
	}
	b, e := io.ReadAll(io.LimitReader(res.Body, max+1))
	if e == nil && int64(len(b)) > max {
		e = errors.New("artifact too large")
	}
	return b, e
}
func (a *Agent) update(ctx context.Context, b json.RawMessage) error {
	var v struct {
		URL string `json:"url"`
	}
	if e := json.Unmarshal(b, &v); e != nil {
		return e
	}
	a.mu.Lock()
	for _, v := range a.Instances {
		if v.Instance.State != "cleaned" {
			a.mu.Unlock()
			return errors.New("drain all instances before update")
		}
	}
	a.mu.Unlock()
	pub, e := os.ReadFile(filepath.Join(a.Cfg.StateDir, "release-public.pem"))
	if e != nil {
		return errors.New("release trust key missing")
	}
	p, _ := pem.Decode(pub)
	if p == nil {
		return errors.New("invalid public key")
	}
	key, e := x509.ParsePKIXPublicKey(p.Bytes)
	if e != nil {
		return e
	}
	ed, ok := key.(ed25519.PublicKey)
	if !ok {
		return errors.New("Ed25519 required")
	}
	base := strings.TrimRight(v.URL, "/")
	manifest, e := download(ctx, base+"/SHA256SUMS", 1<<20)
	if e != nil {
		return e
	}
	sig, e := download(ctx, base+"/SHA256SUMS.sig", 1<<20)
	if e != nil {
		return e
	}
	if !ed25519.Verify(ed, manifest, sig) {
		return errors.New("release signature invalid")
	}
	name := "runner-fleet-agent-linux-" + runtime.GOARCH
	expected := ""
	for _, line := range strings.Split(string(manifest), "\n") {
		f := strings.Fields(line)
		if len(f) == 2 && f[1] == name {
			expected = f[0]
		}
	}
	if len(expected) != 64 {
		return errors.New("binary absent in signed manifest")
	}
	binary, e := download(ctx, base+"/"+name, 100<<20)
	if e != nil {
		return e
	}
	sum := sha256.Sum256(binary)
	if hex.EncodeToString(sum[:]) != expected {
		return errors.New("checksum mismatch")
	}
	exe, e := os.Executable()
	if e != nil {
		return e
	}
	if e = os.WriteFile(exe+".new", binary, 0755); e != nil {
		return e
	}
	old, _ := os.ReadFile(exe)
	if e = os.WriteFile(exe+".previous", old, 0755); e != nil {
		return e
	}
	if e = os.Rename(exe+".new", exe); e != nil {
		return e
	}
	go func() {
		time.Sleep(3 * time.Second)
		if e := syscall.Exec(exe, os.Args, os.Environ()); e != nil {
			fmt.Fprintln(os.Stderr, "update restart failed; use systemd restart")
		}
	}()
	return nil
}
