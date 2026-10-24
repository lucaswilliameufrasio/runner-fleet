package backups

import (
	"os"
	"path/filepath"
	"runnerfleet/internal/store"
	"testing"
)

func TestOnlineSnapshotEncryptedRoundTrip(t *testing.T) {
	dir := t.TempDir()
	s, e := store.Open(filepath.Join(dir, "live.sqlite"))
	if e != nil {
		t.Fatal(e)
	}
	defer s.DB.Close()
	s.Set("test", "saved-in-wal")
	snapshot, e := Snapshot(s, dir)
	if e != nil {
		t.Fatal(e)
	}
	s.Set("test", "after-snapshot")
	encrypted, e := Encrypt(snapshot, "correct horse battery staple")
	if e != nil {
		t.Fatal(e)
	}
	plain, e := Decrypt(encrypted, "correct horse battery staple")
	if e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(dir, "restored.sqlite")
	os.WriteFile(path, plain, 0600)
	restored, e := store.Open(path)
	if e != nil {
		t.Fatal(e)
	}
	defer restored.DB.Close()
	if restored.Get("test") != "saved-in-wal" {
		t.Fatal("snapshot not consistent")
	}
	if _, e = Decrypt(encrypted, "wrong password"); e == nil {
		t.Fatal("wrong password accepted")
	}
	encrypted[len(encrypted)/2] ^= 1
	if _, e = Decrypt(encrypted, "correct horse battery staple"); e == nil {
		t.Fatal("corruption accepted")
	}
}
