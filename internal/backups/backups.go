package backups

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"golang.org/x/crypto/argon2"
	"os"
	"path/filepath"
	"runnerfleet/internal/security"
	"runnerfleet/internal/store"
	"strings"
	"time"
)

type Config struct {
	Enabled       bool   `json:"enabled"`
	Endpoint      string `json:"endpoint"`
	Region        string `json:"region"`
	Bucket        string `json:"bucket"`
	Prefix        string `json:"prefix"`
	AccessKey     string `json:"access_key"`
	SecretKey     string `json:"secret_key"`
	Password      string `json:"password"`
	RetentionDays int    `json:"retention_days"`
	IntervalHours int    `json:"interval_hours"`
	Installation  string `json:"installation"`
}
type Envelope struct {
	Version  int    `json:"version"`
	Salt     string `json:"salt"`
	Data     string `json:"data"`
	Checksum string `json:"checksum"`
	Created  int64  `json:"created"`
}

func Encrypt(b []byte, password string) ([]byte, error) {
	if len(password) < 12 {
		return nil, errors.New("backup password minimum 12 characters")
	}
	salt := make([]byte, 16)
	rand.Read(salt)
	key := argon2.IDKey([]byte(password), salt, 3, 64*1024, 2, 32)
	data, e := security.Seal(key, b)
	if e != nil {
		return nil, e
	}
	sum := sha256.Sum256(b)
	return json.Marshal(Envelope{1, base64.RawStdEncoding.EncodeToString(salt), data, fmt.Sprintf("%x", sum), time.Now().Unix()})
}
func Decrypt(b []byte, password string) ([]byte, error) {
	var v Envelope
	if e := json.Unmarshal(b, &v); e != nil {
		return nil, e
	}
	if v.Version != 1 {
		return nil, errors.New("unknown backup version")
	}
	salt, e := base64.RawStdEncoding.DecodeString(v.Salt)
	if e != nil || len(salt) != 16 {
		return nil, errors.New("invalid salt")
	}
	key := argon2.IDKey([]byte(password), salt, 3, 64*1024, 2, 32)
	out, e := security.Open(key, v.Data)
	if e != nil {
		return nil, errors.New("wrong password or corrupted backup")
	}
	sum := sha256.Sum256(out)
	if fmt.Sprintf("%x", sum) != v.Checksum {
		return nil, errors.New("checksum mismatch")
	}
	if !bytes.HasPrefix(out, []byte("SQLite format 3\x00")) {
		return nil, errors.New("not a SQLite snapshot")
	}
	return out, nil
}
func Snapshot(s *store.Store, dir string) ([]byte, error) {
	f, e := os.CreateTemp(dir, "snapshot-*.sqlite")
	if e != nil {
		return nil, e
	}
	path := f.Name()
	f.Close()
	os.Remove(path)
	defer os.Remove(path)
	if _, e = s.DB.Exec(`VACUUM INTO '` + strings.ReplaceAll(path, "'", "''") + `'`); e != nil {
		return nil, e
	}
	return os.ReadFile(path)
}
func client(c Config) *s3.Client {
	cfg := aws.Config{Region: c.Region, Credentials: credentials.NewStaticCredentialsProvider(c.AccessKey, c.SecretKey, "")}
	if cfg.Region == "" {
		cfg.Region = "auto"
	}
	return s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.UsePathStyle = true
		if c.Endpoint != "" {
			o.BaseEndpoint = aws.String(c.Endpoint)
		}
	})
}
func Run(ctx context.Context, s *store.Store, dir string, c Config) (string, error) {
	b, e := Snapshot(s, dir)
	if e != nil {
		return "", e
	}
	encrypted, e := Encrypt(b, c.Password)
	if e != nil {
		return "", e
	}
	name := time.Now().UTC().Format("20060102T150405.000000000Z") + ".rfbackup"
	if c.Bucket == "" {
		path := filepath.Join(dir, "backups", name)
		os.MkdirAll(filepath.Dir(path), 0700)
		if e = os.WriteFile(path, encrypted, 0600); e != nil {
			return "", e
		}
		if c.RetentionDays > 0 {
			entries, _ := os.ReadDir(filepath.Dir(path))
			cut := time.Now().Add(-time.Duration(c.RetentionDays) * 24 * time.Hour)
			for _, entry := range entries {
				if strings.HasSuffix(entry.Name(), ".rfbackup") {
					info, e := entry.Info()
					if e == nil && info.ModTime().Before(cut) {
						os.Remove(filepath.Join(filepath.Dir(path), entry.Name()))
					}
				}
			}
		}
		return path, nil
	}
	prefix := strings.Trim(c.Prefix, "/") + "/runner-fleet/" + c.Installation + "/"
	key := prefix + name
	cl := client(c)
	_, e = cl.PutObject(ctx, &s3.PutObjectInput{Bucket: aws.String(c.Bucket), Key: aws.String(key), Body: bytes.NewReader(encrypted), ContentType: aws.String("application/octet-stream")})
	if e != nil {
		return "", e
	}
	head, headErr := cl.HeadObject(ctx, &s3.HeadObjectInput{Bucket: aws.String(c.Bucket), Key: aws.String(key)})
	if headErr != nil || aws.ToInt64(head.ContentLength) != int64(len(encrypted)) {
		return key, errors.New("backup uploaded but verification failed; retention skipped")
	}
	if c.RetentionDays > 0 {
		cut := time.Now().Add(-time.Duration(c.RetentionDays) * 24 * time.Hour)
		p := s3.NewListObjectsV2Paginator(cl, &s3.ListObjectsV2Input{Bucket: aws.String(c.Bucket), Prefix: aws.String(prefix)})
		for p.HasMorePages() {
			page, e := p.NextPage(ctx)
			if e != nil {
				return key, e
			}
			objects := []types.ObjectIdentifier{}
			for _, v := range page.Contents {
				if v.LastModified != nil && v.LastModified.Before(cut) && strings.HasSuffix(aws.ToString(v.Key), ".rfbackup") {
					objects = append(objects, types.ObjectIdentifier{Key: v.Key})
				}
			}
			if len(objects) > 0 {
				r, e := cl.DeleteObjects(ctx, &s3.DeleteObjectsInput{Bucket: aws.String(c.Bucket), Delete: &types.Delete{Objects: objects}})
				if e != nil {
					return key, e
				}
				if len(r.Errors) > 0 {
					return key, errors.New("backup saved but retention deletion failed")
				}
			}
		}
	}
	return key, nil
}
