package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	_ "modernc.org/sqlite"
	"os"
	"path/filepath"
	"time"
)

type Store struct{ DB *sql.DB }

func Open(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	for _, q := range []string{`PRAGMA journal_mode=WAL`, `PRAGMA foreign_keys=ON`, `PRAGMA busy_timeout=10000`, schema} {
		if _, err = db.Exec(q); err != nil {
			db.Close()
			return nil, err
		}
	}
	var version int
	if err = db.QueryRow(`SELECT MAX(version) FROM schema_version`).Scan(&version); err != nil || version > 1 {
		db.Close()
		return nil, fmt.Errorf("unsupported database schema version %d", version)
	}
	os.Chmod(path, 0600)
	return &Store{db}, nil
}

const schema = `
CREATE TABLE IF NOT EXISTS schema_version(version INTEGER PRIMARY KEY); INSERT OR IGNORE INTO schema_version VALUES(1);
CREATE TABLE IF NOT EXISTS kv(key TEXT PRIMARY KEY,value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS admin(id INTEGER PRIMARY KEY CHECK(id=1),email TEXT NOT NULL,password TEXT NOT NULL,totp TEXT NOT NULL DEFAULT '',recovery TEXT NOT NULL DEFAULT '[]');
CREATE TABLE IF NOT EXISTS sessions(hash TEXT PRIMARY KEY,csrf TEXT NOT NULL,expires INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS resources(kind TEXT NOT NULL,id TEXT NOT NULL,data TEXT NOT NULL,updated INTEGER NOT NULL,PRIMARY KEY(kind,id));
CREATE TABLE IF NOT EXISTS enrollment(hash TEXT PRIMARY KEY,expires INTEGER NOT NULL,used INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS instances(id TEXT PRIMARY KEY,pool TEXT NOT NULL,machine TEXT NOT NULL,state TEXT NOT NULL,data TEXT NOT NULL,updated INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS commands(id TEXT PRIMARY KEY,machine TEXT NOT NULL,kind TEXT NOT NULL,data TEXT NOT NULL,state TEXT NOT NULL DEFAULT 'pending',expires INTEGER NOT NULL,result TEXT NOT NULL DEFAULT '');
CREATE TABLE IF NOT EXISTS deliveries(id TEXT PRIMARY KEY,created INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS tasks(id TEXT PRIMARY KEY,kind TEXT NOT NULL,data TEXT NOT NULL,state TEXT NOT NULL,attempts INTEGER NOT NULL DEFAULT 0,next INTEGER NOT NULL,error TEXT NOT NULL DEFAULT '');
CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY AUTOINCREMENT,created INTEGER NOT NULL,actor TEXT NOT NULL,action TEXT NOT NULL,target TEXT NOT NULL,result TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS instances_machine ON instances(machine,state);
CREATE INDEX IF NOT EXISTS tasks_due ON tasks(state,next);
`

func JSON(v any) string { b, _ := json.Marshal(v); return string(b) }
func (s *Store) Set(k, v string) error {
	_, e := s.DB.Exec(`INSERT INTO kv VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, k, v)
	return e
}
func (s *Store) Get(k string) string {
	var v string
	s.DB.QueryRow(`SELECT value FROM kv WHERE key=?`, k).Scan(&v)
	return v
}
func (s *Store) Put(kind, id string, v any) error {
	_, e := s.DB.Exec(`INSERT INTO resources VALUES(?,?,?,?) ON CONFLICT(kind,id) DO UPDATE SET data=excluded.data,updated=excluded.updated`, kind, id, JSON(v), time.Now().Unix())
	return e
}
func (s *Store) Read(kind, id string, v any) error {
	var b string
	if e := s.DB.QueryRow(`SELECT data FROM resources WHERE kind=? AND id=?`, kind, id).Scan(&b); e != nil {
		return e
	}
	return json.Unmarshal([]byte(b), v)
}
func (s *Store) List(kind string) ([]json.RawMessage, error) {
	rows, e := s.DB.Query(`SELECT data FROM resources WHERE kind=? ORDER BY updated DESC,id`, kind)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	a := []json.RawMessage{}
	for rows.Next() {
		var b string
		if e = rows.Scan(&b); e != nil {
			return nil, e
		}
		a = append(a, json.RawMessage(b))
	}
	return a, rows.Err()
}
func (s *Store) Delete(kind, id string) error {
	_, e := s.DB.Exec(`DELETE FROM resources WHERE kind=? AND id=?`, kind, id)
	return e
}
func (s *Store) Audit(actor, action, target, result string) {
	s.DB.Exec(`INSERT INTO audit(created,actor,action,target,result) VALUES(?,?,?,?,?)`, time.Now().Unix(), actor, action, target, result)
}
func (s *Store) AuditList() ([]map[string]any, error) {
	r, e := s.DB.Query(`SELECT id,created,actor,action,target,result FROM audit ORDER BY id DESC LIMIT 500`)
	if e != nil {
		return nil, e
	}
	defer r.Close()
	a := []map[string]any{}
	for r.Next() {
		var id, t int64
		var actor, action, target, result string
		r.Scan(&id, &t, &actor, &action, &target, &result)
		a = append(a, map[string]any{"id": id, "created": t, "actor": actor, "action": action, "target": target, "result": result})
	}
	return a, r.Err()
}
func (s *Store) Task(id, kind string, v any) error {
	_, e := s.DB.Exec(`INSERT OR IGNORE INTO tasks(id,kind,data,state,next) VALUES(?,?,?,'pending',?)`, id, kind, JSON(v), time.Now().Unix())
	return e
}
func (s *Store) RecoverTasks() { s.DB.Exec(`UPDATE tasks SET state='pending' WHERE state='running'`) }
func ID(v int64) string        { return fmt.Sprint(v) }
