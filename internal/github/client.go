package github

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

type Client struct {
	AppID      string
	PrivateKey string
	Base       string
	HTTP       *http.Client
	mu         sync.Mutex
	tokens     map[int64]cached
}
type cached struct {
	token   string
	expires time.Time
}

func New(id, key string) *Client {
	return &Client{AppID: id, PrivateKey: key, Base: "https://api.github.com", HTTP: &http.Client{Timeout: 45 * time.Second}, tokens: map[int64]cached{}}
}
func (c *Client) JWT() (string, error) {
	b, _ := pem.Decode([]byte(c.PrivateKey))
	if b == nil {
		return "", errors.New("invalid GitHub App key PEM")
	}
	var k *rsa.PrivateKey
	v, e := x509.ParsePKCS8PrivateKey(b.Bytes)
	if e == nil {
		k, _ = v.(*rsa.PrivateKey)
	} else {
		k, e = x509.ParsePKCS1PrivateKey(b.Bytes)
	}
	if k == nil {
		return "", errors.New("RSA GitHub App key required")
	}
	enc := base64.RawURLEncoding.EncodeToString
	h := enc([]byte(`{"alg":"RS256","typ":"JWT"}`))
	payload, _ := json.Marshal(map[string]any{"iat": time.Now().Add(-time.Minute).Unix(), "exp": time.Now().Add(9 * time.Minute).Unix(), "iss": c.AppID})
	s := h + "." + enc(payload)
	d := sha256.Sum256([]byte(s))
	sig, e := rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, d[:])
	return s + "." + enc(sig), e
}
func (c *Client) raw(ctx context.Context, method, path, token string, in, out any) error {
	var b io.Reader
	if in != nil {
		v, e := json.Marshal(in)
		if e != nil {
			return e
		}
		b = bytes.NewReader(v)
	}
	req, e := http.NewRequestWithContext(ctx, method, c.Base+path, b)
	if e != nil {
		return e
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "runner-fleet")
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, e := c.HTTP.Do(req)
	if e != nil {
		return e
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("GitHub %s %s: HTTP %d (remaining=%s reset=%s)", method, path, resp.StatusCode, resp.Header.Get("X-RateLimit-Remaining"), resp.Header.Get("X-RateLimit-Reset"))
	}
	if out != nil {
		return json.NewDecoder(io.LimitReader(resp.Body, 16<<20)).Decode(out)
	}
	return nil
}
func (c *Client) Token(ctx context.Context, id int64) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if t, ok := c.tokens[id]; ok && time.Until(t.expires) > time.Minute {
		return t.token, nil
	}
	jwt, e := c.JWT()
	if e != nil {
		return "", e
	}
	var v struct {
		Token   string    `json:"token"`
		Expires time.Time `json:"expires_at"`
	}
	e = c.raw(ctx, "POST", fmt.Sprintf("/app/installations/%d/access_tokens", id), jwt, nil, &v)
	if e != nil {
		return "", e
	}
	c.tokens[id] = cached{v.Token, v.Expires}
	return v.Token, nil
}
func (c *Client) Do(ctx context.Context, id int64, method, path string, in, out any) error {
	t, e := c.Token(ctx, id)
	if e != nil {
		return e
	}
	return c.raw(ctx, method, path, t, in, out)
}
func (c *Client) Installations(ctx context.Context) ([]map[string]any, error) {
	t, e := c.JWT()
	if e != nil {
		return nil, e
	}
	a := []map[string]any{}
	for p := 1; ; p++ {
		var b []map[string]any
		if e = c.raw(ctx, "GET", fmt.Sprintf("/app/installations?per_page=100&page=%d", p), t, nil, &b); e != nil {
			return nil, e
		}
		a = append(a, b...)
		if len(b) < 100 {
			break
		}
	}
	return a, nil
}
func Scope(kind, target string) (string, error) {
	parts := strings.Split(target, "/")
	if kind == "org" && len(parts) == 1 && valid(parts[0]) {
		return "/orgs/" + target + "/actions/runners", nil
	}
	if kind == "repo" && len(parts) == 2 && valid(parts[0]) && valid(parts[1]) {
		return "/repos/" + target + "/actions/runners", nil
	}
	return "", errors.New("invalid scope")
}
func valid(s string) bool {
	if s == "" || s == "." || s == ".." {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
			return false
		}
	}
	return true
}
