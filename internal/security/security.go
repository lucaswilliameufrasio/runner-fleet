package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"golang.org/x/crypto/argon2"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func Random(n int) string {
	b := make([]byte, n)
	if _, e := rand.Read(b); e != nil {
		panic(e)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
func Hash(s string) string   { b := sha256.Sum256([]byte(s)); return hex.EncodeToString(b[:]) }
func Equal(a, b string) bool { return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1 }
func Password(s string) string {
	salt := make([]byte, 16)
	rand.Read(salt)
	h := argon2.IDKey([]byte(s), salt, 3, 64*1024, 2, 32)
	return base64.RawStdEncoding.EncodeToString(salt) + ":" + base64.RawStdEncoding.EncodeToString(h)
}
func Verify(encoded, s string) bool {
	p := strings.Split(encoded, ":")
	if len(p) != 2 {
		return false
	}
	salt, e := base64.RawStdEncoding.DecodeString(p[0])
	if e != nil {
		return false
	}
	want, e := base64.RawStdEncoding.DecodeString(p[1])
	if e != nil || len(salt) != 16 || len(want) != 32 {
		return false
	}
	return subtle.ConstantTimeCompare(want, argon2.IDKey([]byte(s), salt, 3, 64*1024, 2, 32)) == 1
}
func Secret() string {
	b := make([]byte, 20)
	rand.Read(b)
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)
}
func TOTP(secret, code string, now time.Time) bool {
	k, e := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(secret))
	if e != nil {
		return false
	}
	for d := -1; d <= 1; d++ {
		b := make([]byte, 8)
		binary.BigEndian.PutUint64(b, uint64(now.Unix()/30+int64(d)))
		m := hmac.New(sha1.New, k)
		m.Write(b)
		v := m.Sum(nil)
		o := v[19] & 15
		n := binary.BigEndian.Uint32(v[o:o+4]) & 0x7fffffff
		if Equal(fmt.Sprintf("%06d", n%1000000), code) {
			return true
		}
	}
	return false
}
func Key(path string) ([]byte, error) {
	b, e := os.ReadFile(path)
	if e == nil {
		if len(b) != 32 {
			return nil, errors.New("invalid encryption key")
		}
		return b, nil
	}
	if !os.IsNotExist(e) {
		return nil, e
	}
	if e = os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		return nil, e
	}
	b = make([]byte, 32)
	rand.Read(b)
	return b, os.WriteFile(path, b, 0600)
}
func Seal(key []byte, b []byte) (string, error) {
	block, e := aes.NewCipher(key)
	if e != nil {
		return "", e
	}
	g, e := cipher.NewGCM(block)
	if e != nil {
		return "", e
	}
	n := make([]byte, g.NonceSize())
	rand.Read(n)
	return base64.RawStdEncoding.EncodeToString(g.Seal(n, n, b, nil)), nil
}
func Open(key []byte, s string) ([]byte, error) {
	b, e := base64.RawStdEncoding.DecodeString(s)
	if e != nil {
		return nil, e
	}
	block, e := aes.NewCipher(key)
	if e != nil {
		return nil, e
	}
	g, _ := cipher.NewGCM(block)
	if len(b) < g.NonceSize() {
		return nil, errors.New("ciphertext truncated")
	}
	return g.Open(nil, b[:g.NonceSize()], b[g.NonceSize():], nil)
}

type CA struct {
	Cert *x509.Certificate
	Key  *ecdsa.PrivateKey
	PEM  []byte
}

func LoadCA(dir string) (*CA, error) {
	os.MkdirAll(dir, 0700)
	cp := filepath.Join(dir, "ca.pem")
	kp := filepath.Join(dir, "ca-key.pem")
	b, e := os.ReadFile(cp)
	if e == nil {
		kb, e := os.ReadFile(kp)
		if e != nil {
			return nil, e
		}
		p, _ := pem.Decode(b)
		q, _ := pem.Decode(kb)
		if p == nil || q == nil {
			return nil, errors.New("invalid CA")
		}
		c, e := x509.ParseCertificate(p.Bytes)
		if e != nil {
			return nil, e
		}
		k, e := x509.ParseECPrivateKey(q.Bytes)
		return &CA{c, k, b}, e
	}
	if !os.IsNotExist(e) {
		return nil, e
	}
	k, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		return nil, e
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	t := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "Runner Fleet Machine CA"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().AddDate(10, 0, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	der, e := x509.CreateCertificate(rand.Reader, t, t, &k.PublicKey, k)
	if e != nil {
		return nil, e
	}
	b = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	kd, _ := x509.MarshalECPrivateKey(k)
	if e = os.WriteFile(kp, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd}), 0600); e != nil {
		return nil, e
	}
	if e = os.WriteFile(cp, b, 0600); e != nil {
		return nil, e
	}
	c, _ := x509.ParseCertificate(der)
	return &CA{c, k, b}, nil
}
func (c *CA) Issue(csrPEM, id string) (string, string, error) {
	p, _ := pem.Decode([]byte(csrPEM))
	if p == nil {
		return "", "", errors.New("invalid CSR")
	}
	csr, e := x509.ParseCertificateRequest(p.Bytes)
	if e != nil {
		return "", "", e
	}
	if e = csr.CheckSignature(); e != nil {
		return "", "", e
	}
	switch k := csr.PublicKey.(type) {
	case *ecdsa.PublicKey:
		if k.Curve != elliptic.P256() {
			return "", "", errors.New("P-256 required")
		}
	default:
		return "", "", errors.New("P-256 required")
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	t := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: id}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(30 * 24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, e := x509.CreateCertificate(rand.Reader, t, c.Cert, csr.PublicKey, c.Key)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), serial.String(), e
}
