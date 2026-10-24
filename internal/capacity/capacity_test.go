package capacity

import (
	"path/filepath"
	"runnerfleet/internal/store"
	"sync"
	"testing"
	"time"
)

func fixture(t *testing.T) (*store.Store, Pool, Machine) {
	t.Helper()
	s, e := store.Open(filepath.Join(t.TempDir(), "test.sqlite"))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.DB.Close() })
	p := Pool{ID: "p", Max: 10, CPU: 1, MemoryMB: 512, DiskMB: 1024, Arch: "amd64"}
	m := Machine{ID: "m", Arch: "amd64", State: "online", LastSeen: time.Now().Unix(), MaxSlots: 2, CPU: 2, MemoryMB: 1024, DiskMB: 2048, Shared: true, Doctor: map[string]any{"ready": true, "enforcement": true}}
	return s, p, m
}
func TestConcurrentReservationsRespectGlobalCapacity(t *testing.T) {
	s, p, m := fixture(t)
	var wg sync.WaitGroup
	var mu sync.Mutex
	success := 0
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, e := Reserve(s, p, m, time.Now()); e == nil {
				mu.Lock()
				success++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if success != 2 {
		t.Fatalf("reserved %d, want 2", success)
	}
	a, e := List(s)
	if e != nil || len(a) != 2 {
		t.Fatal(a, e)
	}
}
func TestIdleAndOfflineReservationsRemainCharged(t *testing.T) {
	s, p, m := fixture(t)
	v, e := Reserve(s, p, m, time.Now())
	if e != nil {
		t.Fatal(e)
	}
	Update(s, v.ID, "idle", "")
	v2, e := Reserve(s, p, m, time.Now())
	if e != nil {
		t.Fatal(e)
	}
	Update(s, v2.ID, "cleaning", "")
	if _, e = Reserve(s, p, m, time.Now()); e == nil {
		t.Fatal("idle/cleaning capacity reused")
	}
	Update(s, v.ID, "removed", "")
	if _, e = Reserve(s, p, m, time.Now()); e != nil {
		t.Fatal(e)
	}
	m.State = "offline"
	if _, e = Reserve(s, p, m, time.Now()); e == nil {
		t.Fatal("offline machine allowed")
	}
}
func TestScheduleAcrossMidnightAndEnforcement(t *testing.T) {
	s, p, m := fixture(t)
	now := time.Date(2026, 10, 13, 23, 0, 0, 0, time.UTC)
	m.LastSeen = now.Unix()
	m.StartHour = 22
	m.EndHour = 6
	m.Timezone = "UTC"
	if _, e := Reserve(s, p, m, now); e != nil {
		t.Fatal(e)
	}
	m.Doctor["enforcement"] = false
	if _, e := Reserve(s, p, m, now); e == nil {
		t.Fatal("shared machine without enforcement allowed")
	}
	m.Doctor["enforcement"] = true
	now = now.Add(12 * time.Hour)
	m.LastSeen = now.Unix()
	if _, e := Reserve(s, p, m, now); e == nil {
		t.Fatal("outside schedule allowed")
	}
}
func TestAllLabelsAndScopes(t *testing.T) {
	if !Match([]string{"SELF-HOSTED", "Linux", "X64"}, []string{"linux", "x64"}) {
		t.Fatal("case insensitive matching")
	}
	if Match([]string{"linux"}, []string{"linux", "gpu"}) {
		t.Fatal("partial match")
	}
	p := Pool{Scope: "org", Target: "acme", Labels: []string{"self-hosted", "linux"}, Enabled: true}
	if QueueReason([]Pool{p}, []string{"linux"}, "other/api") == "aguardando capacidade; confirmar grupo/acesso no GitHub" {
		t.Fatal("cross-org matching")
	}
}
