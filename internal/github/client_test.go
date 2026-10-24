package github

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestInstallationTokensAreScopedAndCached(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	raw, _ := x509.MarshalPKCS8PrivateKey(key)
	client := New("123", string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: raw})))
	tokens := map[string]int{}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			tokens[r.URL.Path]++
			fmt.Fprintf(w, `{"token":%q,"expires_at":%q}`, r.URL.Path, time.Now().Add(time.Hour).UTC().Format(time.RFC3339))
			return
		}
		if r.Header.Get("Authorization") != "Bearer /app/installations/1/access_tokens" && r.Header.Get("Authorization") != "Bearer /app/installations/2/access_tokens" {
			t.Error("bad token")
		}
		fmt.Fprint(w, `{"ok":true}`)
	}))
	defer ts.Close()
	client.Base = ts.URL
	for _, id := range []int64{1, 1, 2, 1} {
		var out map[string]any
		if e := client.Do(t.Context(), id, "GET", "/test", nil, &out); e != nil {
			t.Fatal(e)
		}
	}
	if tokens["/app/installations/1/access_tokens"] != 1 || tokens["/app/installations/2/access_tokens"] != 1 {
		t.Fatal(tokens)
	}
}
func TestScopeRejectsPathInjection(t *testing.T) {
	for _, v := range []string{"foo/../../admin", "foo?x=1", "foo/bar/baz"} {
		if _, e := Scope("repo", v); e == nil {
			t.Fatal("unsafe scope", v)
		}
	}
}
