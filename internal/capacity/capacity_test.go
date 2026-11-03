package capacity

import (
	"path/filepath"
	"runnerfleet/internal/store"
	"strings"
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

func TestSpotPoolValidationAndFallbackPairing(t *testing.T) {
	pool := Pool{
		ID: "spot", Name: "Spot", Installation: 1, Scope: "repo", Target: "acme/build",
		Labels: []string{"self-hosted", "linux", "x64"}, Arch: "amd64", Image: "registry.test/runner@sha256:" + strings.Repeat("a", 64),
		Min: 1, Max: 4, CPU: 1, MemoryMB: 1024, DiskMB: 2048, Trusted: true,
		Spot: &SpotConfig{
			Region: "us-east-1", ImageID: "ami-0123456789abcdef0", ImageMode: "bootstrap",
			SubnetIDs: []string{"subnet-0123456789abcdef0"}, SecurityGroupIDs: []string{"sg-0123456789abcdef0"},
			SpotInstanceTypes: []string{"m7i.large"}, SlotsPerMachine: 2, MaxMachines: 2, IdleMinutes: 10, RootVolumeGiB: 40,
		},
	}
	if err := Validate(pool); err != nil {
		t.Fatalf("valid Spot pool rejected: %v", err)
	}
	pool.Spot.OnDemandInstanceTypes = []string{"m7i.large"}
	if err := Validate(pool); err == nil {
		t.Fatal("fallback types without a fallback delay accepted")
	}
	pool.Spot.FallbackAfterSeconds = 60
	if err := Validate(pool); err != nil {
		t.Fatalf("valid configured fallback rejected: %v", err)
	}
	pool.Min = 3
	pool.Spot.MaxMachines = 1
	if err := Validate(pool); err == nil {
		t.Fatal("pool minimum greater than cloud capacity accepted")
	}
}

func TestServicePoolReservesWithoutDocker(t *testing.T) {
	s, _, machine := fixture(t)
	service := Pool{
		ID: "svc", Name: "Service", Installation: 1, Scope: "repo", Target: "acme/build",
		Labels: []string{"self-hosted", "linux"}, Arch: "amd64", Execution: "service",
		RunnerVersion: "2.321.0", RunnerSHA256AMD64: strings.Repeat("a", 64), RunnerSHA256ARM64: strings.Repeat("b", 64),
		Machines: []string{"m"}, Max: 2, CPU: 1, MemoryMB: 512, DiskMB: 1024, Trusted: true,
	}
	if err := Validate(service); err != nil {
		t.Fatal(err)
	}
	machine.Doctor = map[string]any{"service_ready": true, "service_enforcement": true, "ready": false}
	if _, err := Reserve(s, service, machine, time.Now()); err != nil {
		t.Fatal(err)
	}
	machine.Doctor["service_enforcement"] = false
	if _, err := Reserve(s, service, machine, time.Now()); err == nil {
		t.Fatal("shared service machine without enforcement reserved")
	}
	container := service
	container.ID = "box"
	container.Execution = ""
	container.Image = ""
	if err := Validate(container); err == nil {
		t.Fatal("container pool without a digest accepted")
	}
	container.Image = "registry.test/runner@sha256:" + strings.Repeat("c", 64)
	if err := Validate(container); err != nil {
		t.Fatal(err)
	}
	if _, err := Reserve(s, container, machine, time.Now()); err == nil {
		t.Fatal("container pool reserved on a machine without rootless Docker")
	}
	service.DockerSidecar = true
	if err := Validate(service); err == nil {
		t.Fatal("service pool accepted a Docker sidecar")
	}
	service.DockerSidecar = false
	service.RunnerVersion = "2.1"
	if err := Validate(service); err == nil {
		t.Fatal("service pool accepted a partial runner version")
	}
}
