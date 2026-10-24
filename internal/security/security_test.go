package security

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base32"
	"encoding/pem"
	"testing"
	"time"
)

func TestPasswordAndEncryptedSecrets(t *testing.T) {
	hash := Password("a strong passphrase")
	if !Verify(hash, "a strong passphrase") || Verify(hash, "wrong") || Verify("malformed", "wrong") {
		t.Fatal("password validation")
	}
	key := make([]byte, 32)
	v, e := Seal(key, []byte("private"))
	if e != nil {
		t.Fatal(e)
	}
	b, e := Open(key, v)
	if e != nil || string(b) != "private" {
		t.Fatal(e)
	}
	key[0] = 1
	if _, e = Open(key, v); e == nil {
		t.Fatal("wrong key accepted")
	}
}
func TestTOTPStandardVector(t *testing.T) {
	secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte("12345678901234567890"))
	if !TOTP(secret, "287082", time.Unix(59, 0)) {
		t.Fatal("RFC vector failed")
	}
	if TOTP(secret, "000000", time.Unix(59, 0)) {
		t.Fatal("bad OTP accepted")
	}
}
func TestCARejectsTamperedCSRAndPersists(t *testing.T) {
	dir := t.TempDir()
	ca, e := LoadCA(dir)
	if e != nil {
		t.Fatal(e)
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	b, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	csr := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: b}))
	cert, serial, e := ca.Issue(csr, "machine-1")
	if e != nil || serial == "" {
		t.Fatal(e)
	}
	p, _ := pem.Decode([]byte(cert))
	leaf, _ := x509.ParseCertificate(p.Bytes)
	roots := x509.NewCertPool()
	roots.AddCert(ca.Cert)
	if _, e = leaf.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); e != nil {
		t.Fatal(e)
	}
	ca2, e := LoadCA(dir)
	if e != nil || ca2.Cert.SerialNumber.Cmp(ca.Cert.SerialNumber) != 0 {
		t.Fatal("CA not persisted")
	}
	b[len(b)-1] ^= 1
	if _, _, e = ca.Issue(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: b})), "bad"); e == nil {
		t.Fatal("tampered CSR accepted")
	}
}
