package capacity

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"runnerfleet/internal/security"
	"runnerfleet/internal/store"
	"strings"
	"time"
)

type Machine struct {
	ID        string         `json:"id"`
	Name      string         `json:"name"`
	Arch      string         `json:"arch"`
	State     string         `json:"state"`
	Serials   []string       `json:"serials"`
	LastSeen  int64          `json:"last_seen"`
	MaxSlots  int            `json:"max_slots"`
	CPU       float64        `json:"cpu"`
	MemoryMB  int64          `json:"memory_mb"`
	DiskMB    int64          `json:"disk_mb"`
	Shared    bool           `json:"shared"`
	Doctor    map[string]any `json:"doctor"`
	Telemetry map[string]any `json:"telemetry"`
	Timezone  string         `json:"timezone"`
	StartHour int            `json:"start_hour"`
	EndHour   int            `json:"end_hour"`
}
type Pool struct {
	ID            string   `json:"id"`
	Name          string   `json:"name"`
	Installation  int64    `json:"installation"`
	Scope         string   `json:"scope"`
	Target        string   `json:"target"`
	Group         string   `json:"group"`
	Labels        []string `json:"labels"`
	Arch          string   `json:"arch"`
	Image         string   `json:"image"`
	Machines      []string `json:"machines"`
	Min           int      `json:"min"`
	Max           int      `json:"max"`
	Weight        int      `json:"weight"`
	CPU           float64  `json:"cpu"`
	MemoryMB      int64    `json:"memory_mb"`
	DiskMB        int64    `json:"disk_mb"`
	Enabled       bool     `json:"enabled"`
	Trusted       bool     `json:"trusted"`
	DockerSidecar bool     `json:"docker_sidecar"`
	DockerImage   string   `json:"docker_image"`
}
type Instance struct {
	ID       string  `json:"id"`
	Name     string  `json:"name"`
	Pool     string  `json:"pool"`
	Machine  string  `json:"machine"`
	State    string  `json:"state"`
	CPU      float64 `json:"cpu"`
	MemoryMB int64   `json:"memory_mb"`
	DiskMB   int64   `json:"disk_mb"`
	RunnerID int64   `json:"runner_id"`
	Created  int64   `json:"created"`
	Error    string  `json:"error,omitempty"`
}
type Spec struct {
	Instance Instance `json:"instance"`
	Pool     Pool     `json:"pool"`
	URL      string   `json:"url"`
	Token    string   `json:"token"`
}

func Match(labels, want []string) bool {
	for _, w := range want {
		found := false
		for _, l := range labels {
			if strings.EqualFold(l, w) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
func Validate(p Pool) error {
	if p.Scope == "org" && p.Enabled && p.Group == "" {
		return errors.New("active organization pools require an explicit runner group")
	}
	if p.Scope == "repo" && p.Group != "" {
		return errors.New("repository runners do not use organization runner groups")
	}
	if p.Installation < 1 || p.Name == "" || p.Max < 1 || p.Max > 100 || p.Min < 0 || p.Min > p.Max || p.CPU <= 0 || p.MemoryMB < 256 || p.DiskMB < 512 || len(p.Machines) == 0 || len(p.Labels) == 0 {
		return errors.New("pool: invalid limits or missing fields")
	}
	if p.Arch != "amd64" && p.Arch != "arm64" {
		return errors.New("unsupported architecture")
	}
	if !strings.Contains(p.Image, "@sha256:") || len(strings.Split(p.Image, "@sha256:")[1]) != 64 {
		return errors.New("image must be pinned by sha256 digest")
	}
	if p.DockerSidecar && (p.CPU < 2 || p.MemoryMB < 2048 || !strings.Contains(p.DockerImage, "@sha256:")) {
		return errors.New("Docker sidecar needs pinned image, 2+ CPUs and 2048+ MB")
	}
	if !p.Trusted {
		return errors.New("trusted workloads must be explicitly acknowledged")
	}
	for _, l := range p.Labels {
		if strings.ContainsAny(l, ",\n\r") || strings.HasPrefix(l, "-") {
			return errors.New("invalid label")
		}
	}
	return nil
}
func Active(s string) bool { return s != "removed" && s != "failed" }
func List(s *store.Store) ([]Instance, error) {
	r, e := s.DB.Query(`SELECT data,state FROM instances ORDER BY updated DESC`)
	if e != nil {
		return nil, e
	}
	defer r.Close()
	a := []Instance{}
	for r.Next() {
		var b, state string
		r.Scan(&b, &state)
		var v Instance
		if e = json.Unmarshal([]byte(b), &v); e != nil {
			return nil, e
		}
		v.State = state
		a = append(a, v)
	}
	return a, r.Err()
}
func Reserve(s *store.Store, p Pool, m Machine, now time.Time) (Instance, error) {
	v := Instance{}
	if p.DockerSidecar && m.Shared {
		return v, errors.New("Docker sidecar requires dedicated machine opt-in")
	}
	if m.State != "online" || now.Unix()-m.LastSeen > 45 || m.Arch != p.Arch {
		return v, errors.New("machine unavailable")
	}
	if p.CPU > m.CPU || p.MemoryMB > m.MemoryMB || p.DiskMB > m.DiskMB {
		return v, errors.New("insufficient budget")
	}
	if m.StartHour != m.EndHour {
		zone, e := time.LoadLocation(m.Timezone)
		if e != nil {
			return v, e
		}
		h := now.In(zone).Hour()
		allowed := h >= m.StartHour && h < m.EndHour
		if m.StartHour > m.EndHour {
			allowed = h >= m.StartHour || h < m.EndHour
		}
		if !allowed {
			return v, errors.New("outside schedule")
		}
	}
	if ok, _ := m.Doctor["ready"].(bool); !ok {
		return v, errors.New("doctor not ready")
	}
	if m.Shared {
		if ok, _ := m.Doctor["enforcement"].(bool); !ok {
			return v, errors.New("resource enforcement unavailable")
		}
	}
	if low, _ := m.Telemetry["pressure"].(bool); low {
		return v, errors.New("resource pressure")
	}
	tx, e := s.DB.Begin()
	if e != nil {
		return v, e
	}
	defer tx.Rollback()
	rows, e := tx.Query(`SELECT data,state FROM instances WHERE state NOT IN ('removed','failed')`)
	if e != nil {
		return v, e
	}
	slots, pools := 0, 0
	cpu := 0.0
	var mem, disk int64
	for rows.Next() {
		var b, state string
		rows.Scan(&b, &state)
		var a Instance
		json.Unmarshal([]byte(b), &a)
		if a.Pool == p.ID {
			pools++
		}
		if a.Machine == m.ID {
			slots++
			cpu += a.CPU
			mem += a.MemoryMB
			disk += a.DiskMB
		}
	}
	if e = rows.Err(); e != nil {
		rows.Close()
		return v, e
	}
	rows.Close()
	if slots >= m.MaxSlots || pools >= p.Max || cpu+p.CPU > m.CPU || mem+p.MemoryMB > m.MemoryMB || disk+p.DiskMB > m.DiskMB {
		return v, errors.New("capacity reserved")
	}
	id := security.Random(12)
	v = Instance{ID: id, Name: "rf-" + id, Pool: p.ID, Machine: m.ID, State: "reserved", CPU: p.CPU, MemoryMB: p.MemoryMB, DiskMB: p.DiskMB, Created: now.Unix()}
	_, e = tx.Exec(`INSERT INTO instances VALUES(?,?,?,?,?,?)`, id, p.ID, m.ID, v.State, store.JSON(v), now.Unix())
	if e != nil {
		return v, e
	}
	return v, tx.Commit()
}
func Update(s *store.Store, id, state, msg string) error {
	var b string
	e := s.DB.QueryRow(`SELECT data FROM instances WHERE id=?`, id).Scan(&b)
	if e != nil {
		return e
	}
	var v Instance
	json.Unmarshal([]byte(b), &v)
	v.State = state
	v.Error = msg
	_, e = s.DB.Exec(`UPDATE instances SET state=?,data=?,updated=? WHERE id=?`, state, store.JSON(v), time.Now().Unix(), id)
	return e
}
func Command(s *store.Store, machine, kind string, data any) (string, error) {
	id := security.Random(12)
	_, e := s.DB.Exec(`INSERT INTO commands(id,machine,kind,data,expires) VALUES(?,?,?,?,?)`, id, machine, kind, store.JSON(data), time.Now().Add(10*time.Minute).Unix())
	return id, e
}
func Get(s *store.Store, id string) (Instance, error) {
	var v Instance
	var b, state string
	e := s.DB.QueryRow(`SELECT data,state FROM instances WHERE id=?`, id).Scan(&b, &state)
	if e == nil {
		e = json.Unmarshal([]byte(b), &v)
		v.State = state
	}
	return v, e
}
func QueueReason(pools []Pool, labels []string, target string) string {
	for _, p := range pools {
		scope := p.Target == target || p.Scope == "org" && strings.HasPrefix(target, p.Target+"/")
		if scope && Match(p.Labels, labels) {
			if !p.Enabled {
				return "pool pausado"
			}
			return "aguardando capacidade; confirmar grupo/acesso no GitHub"
		}
	}
	return "nenhum pool com escopo e labels compatíveis"
}

var _ = *new(sql.DB)
var _ = fmt.Sprint
