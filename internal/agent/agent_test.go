package agent

import (
	"context"
	"os"
	"path/filepath"
	"runnerfleet/internal/capacity"
	"runnerfleet/internal/store"
	"strings"
	"testing"
)

func TestAgentIdempotenceLocalQuotaAndPersistentRecovery(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "docker")
	log := filepath.Join(dir, "calls")
	script := "#!/bin/sh\nprintf '%s\\n' \"$*\" >> " + log + "\nexit 0\n"
	os.WriteFile(bin, []byte(script), 0755)
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
	os.WriteFile(filepath.Join(dir, "config.json"), []byte(store.JSON(Config{ID: "machine", URL: "wss://example.test/agent"})), 0600)
	a, e := New(dir)
	if e != nil {
		t.Fatal(e)
	}
	a.Policy = capacity.Machine{ID: "machine", State: "online", MaxSlots: 1, CPU: 2, MemoryMB: 4096, DiskMB: 8192}
	a.DoctorData = map[string]any{"ready": true}
	p := capacity.Pool{ID: "pool", Name: "Build", Installation: 1, Scope: "org", Target: "acme", Labels: []string{"self-hosted", "linux", "x64"}, Arch: "amd64", Image: "example/runner@sha256:" + strings.Repeat("0", 64), Machines: []string{"machine"}, Max: 1, CPU: 1, MemoryMB: 1024, DiskMB: 2048, Trusted: true}
	spec := capacity.Spec{Instance: capacity.Instance{ID: "instance", Name: "rf-instance", Machine: "machine", Pool: "pool", CPU: 1, MemoryMB: 1024, DiskMB: 2048}, Pool: p, URL: "https://github.com/acme", Token: "registration-secret"}
	if e = a.start(context.Background(), "cmd", spec); e != nil {
		t.Fatal(e)
	}
	before, _ := os.ReadFile(log)
	if e = a.start(context.Background(), "same-command", spec); e != nil {
		t.Fatal(e)
	}
	after, _ := os.ReadFile(log)
	if string(before) != string(after) {
		t.Fatal("duplicate runtime start")
	}
	spec.Instance.ID = "second"
	if e = a.start(context.Background(), "second-command", spec); e == nil {
		t.Fatal("local quota exceeded")
	}
	recovered, e := New(dir)
	if e != nil || recovered.Instances["instance"] == nil {
		t.Fatal("state lost", e)
	}
	state, _ := os.ReadFile(filepath.Join(dir, "state.json"))
	if strings.Contains(string(state), "registration-secret") || strings.Contains(string(after), "registration-secret") {
		t.Fatal("secret persisted or in process arguments")
	}
	if _, e = os.Stat(filepath.Join(dir, "bootstrap", "instance")); !os.IsNotExist(e) {
		t.Fatal("bootstrap token file not cleaned")
	}
}

func TestCleanupCannotReleaseUnknownDockerState(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "docker"), []byte("#!/bin/sh\necho 'Cannot connect to Docker daemon' >&2\nexit 1\n"), 0755)
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
	a := &Agent{}
	if e := a.cleanupContainers(context.Background(), Local{Container: "runner"}); e == nil {
		t.Fatal("unreachable Docker daemon treated as clean")
	}
}
