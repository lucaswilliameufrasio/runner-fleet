package agent

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"runnerfleet/internal/capacity"
)

func useServiceDirs(t *testing.T) (string, string) {
	t.Helper()
	requests := filepath.Join(t.TempDir(), "requests")
	status := filepath.Join(t.TempDir(), "status")
	if err := os.MkdirAll(requests, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(status, 0700); err != nil {
		t.Fatal(err)
	}
	previousRequests := serviceRequestDirectory
	previousStatus := serviceStatusDirectory
	previousPoll := servicePollInterval
	previousTimeout := serviceStartTimeout
	serviceRequestDirectory = requests
	serviceStatusDirectory = status
	t.Cleanup(func() {
		serviceRequestDirectory = previousRequests
		serviceStatusDirectory = previousStatus
		servicePollInterval = previousPoll
		serviceStartTimeout = previousTimeout
	})
	return requests, status
}

func serviceSpec() capacity.Spec {
	return capacity.Spec{
		Instance: capacity.Instance{ID: "svc1", Name: "rf-svc1", Machine: "machine", Pool: "pool", CPU: 1, MemoryMB: 1024, DiskMB: 2048},
		Pool: capacity.Pool{
			ID: "pool", Name: "Build", Installation: 1, Scope: "org", Target: "acme",
			Labels: []string{"self-hosted", "linux", "x64"}, Arch: "amd64", Execution: "service",
			RunnerVersion: "2.321.0", RunnerSHA256AMD64: strings.Repeat("a", 64), RunnerSHA256ARM64: strings.Repeat("b", 64),
			Group: "Linux builds", Machines: []string{"machine"}, Max: 1, CPU: 1, MemoryMB: 1024, DiskMB: 2048, Trusted: true,
		},
		URL:   "https://github.com/acme",
		Token: "registration-secret",
	}
}

func TestServiceRequestSelectsChecksumAndRejectsCallerURL(t *testing.T) {
	spec := serviceSpec()
	amd64, err := serviceRequest(spec, "amd64")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(amd64), "sha256="+strings.Repeat("a", 64)) || strings.Contains(string(amd64), strings.Repeat("b", 64)) {
		t.Fatal("amd64 request did not use the amd64 checksum")
	}
	arm64, err := serviceRequest(spec, "arm64")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(arm64), "sha256="+strings.Repeat("b", 64)) || strings.Contains(string(arm64), "releases/download") {
		t.Fatal("arm64 request was not pinned to the configured checksum")
	}
	if !strings.Contains(string(arm64), "group=Linux builds") {
		t.Fatal("runner group was not preserved")
	}
	spec.URL = "https://evil.example/runner"
	if _, err = serviceRequest(spec, "amd64"); err == nil {
		t.Fatal("caller download host accepted")
	}
	spec = serviceSpec()
	spec.Pool.RunnerVersion = "latest"
	if _, err = serviceRequest(spec, "amd64"); err == nil {
		t.Fatal("unpinned runner version accepted")
	}
	spec = serviceSpec()
	spec.Token = "bad token"
	if _, err = serviceRequest(spec, runtime.GOARCH); err == nil {
		t.Fatal("token with a space accepted")
	}
}

func TestServiceStartDoesNotUseDocker(t *testing.T) {
	requests, status := useServiceDirs(t)
	dir := t.TempDir()
	log := filepath.Join(dir, "docker-calls")
	if err := os.WriteFile(filepath.Join(dir, "docker"), []byte("#!/bin/sh\nprintf '%s\\n' \"$*\" >> "+log+"\nexit 1\n"), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	if err := os.WriteFile(filepath.Join(status, "svc1.status"), []byte("state=ready\nunit=actions.runner.acme.build.svc1.service\nbusy=no\nerror=\n"), 0600); err != nil {
		t.Fatal(err)
	}
	a := &Agent{
		Cfg:        Config{ID: "machine", StateDir: t.TempDir()},
		Instances:  map[string]*Local{},
		Completed:  map[string]bool{},
		running:    map[string]bool{},
		Policy:     capacity.Machine{ID: "machine", State: "online", MaxSlots: 2, CPU: 2, MemoryMB: 4096, DiskMB: 8192},
		DoctorData: map[string]any{"service_ready": true, "ready": false},
	}
	if err := a.start(context.Background(), "cmd", serviceSpec()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(log); !os.IsNotExist(err) {
		t.Fatal("service start invoked docker")
	}
	if a.Instances["svc1"] == nil || a.Instances["svc1"].Kind != "service" || a.Instances["svc1"].Instance.State != "idle" {
		t.Fatal("service runner was not marked idle")
	}
	state, err := os.ReadFile(filepath.Join(a.Cfg.StateDir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(state), "registration-secret") {
		t.Fatal("registration token persisted in agent state")
	}
	request, err := os.ReadFile(filepath.Join(requests, "svc1.request"))
	if err != nil || !strings.Contains(string(request), "action=install") || strings.Contains(string(request), "releases/download") {
		t.Fatal("service request was not written")
	}
	container := serviceSpec()
	container.Pool.Execution = ""
	container.Pool.Image = "example/runner@sha256:" + strings.Repeat("c", 64)
	container.Instance.ID = "box1"
	container.Instance.Name = "rf-box1"
	if err := a.start(context.Background(), "other", container); err == nil || err.Error() != "doctor not ready" {
		t.Fatal("container start bypassed the rootless docker doctor")
	}
}

func TestServiceRemovalIsRequestedOnceAndErrorsStayFixed(t *testing.T) {
	requests, status := useServiceDirs(t)
	dir := t.TempDir()
	a := &Agent{Cfg: Config{ID: "machine", StateDir: dir}, Instances: map[string]*Local{}, Completed: map[string]bool{}, running: map[string]bool{}}
	local := &Local{Instance: capacity.Instance{ID: "svc1", State: "idle"}, Kind: "service", Draining: true, Deadline: time.Now().Add(time.Hour).Unix()}
	a.Instances[local.Instance.ID] = local
	if err := os.WriteFile(filepath.Join(status, "svc1.status"), []byte("state=ready\nbusy=yes\nerror=\n"), 0600); err != nil {
		t.Fatal(err)
	}
	a.observeService(*local)
	if _, err := os.Stat(filepath.Join(requests, "svc1.request")); !os.IsNotExist(err) {
		t.Fatal("busy service runner was removed")
	}
	if a.Instances["svc1"].Instance.State != "busy" {
		t.Fatal("busy service runner was not observed")
	}
	if err := os.WriteFile(filepath.Join(status, "svc1.status"), []byte("state=ready\nbusy=no\nerror=\n"), 0600); err != nil {
		t.Fatal(err)
	}
	a.observeService(*a.Instances["svc1"])
	if err := os.WriteFile(filepath.Join(requests, "svc1.request"), []byte("action=stale\n"), 0600); err != nil {
		t.Fatal(err)
	}
	a.observeService(*a.Instances["svc1"])
	current, err := os.ReadFile(filepath.Join(requests, "svc1.request"))
	if err != nil || string(current) != "action=stale\n" {
		t.Fatal("remove request was repeated")
	}
	if err := os.WriteFile(filepath.Join(status, "svc1.status"), []byte("state=error\nerror=registration-secret\n"), 0600); err != nil {
		t.Fatal(err)
	}
	a.observeService(*a.Instances["svc1"])
	if a.Instances["svc1"].Instance.Error != "runner configuration failed" {
		t.Fatal("status error was copied into agent state")
	}
	state, err := os.ReadFile(filepath.Join(dir, "state.json"))
	if err != nil || strings.Contains(string(state), "registration-secret") {
		t.Fatal("status file secret persisted in agent state")
	}
}

func TestServiceStartDeadlineDoesNotKeepWaiting(t *testing.T) {
	useServiceDirs(t)
	servicePollInterval = time.Millisecond
	serviceStartTimeout = 15 * time.Millisecond
	dir := t.TempDir()
	a := &Agent{
		Cfg:        Config{ID: "machine", StateDir: dir},
		Instances:  map[string]*Local{},
		Completed:  map[string]bool{},
		running:    map[string]bool{},
		Policy:     capacity.Machine{ID: "machine", State: "online", MaxSlots: 1, CPU: 2, MemoryMB: 4096, DiskMB: 8192},
		DoctorData: map[string]any{"service_ready": true},
	}
	err := a.start(context.Background(), "cmd", serviceSpec())
	if err == nil {
		t.Fatal("missing service helper was treated as ready")
	}
	state, readErr := os.ReadFile(filepath.Join(dir, "state.json"))
	if readErr != nil || strings.Contains(string(state), "registration-secret") {
		t.Fatal("registration token persisted after a service timeout")
	}
}

func TestServiceDoctorGate(t *testing.T) {
	if !serviceSystemd("degraded") || !serviceSystemd("running") || serviceSystemd("maintenance") {
		t.Fatal("systemd state was classified incorrectly")
	}
	if !serviceReady(true, "active", nil, true) {
		t.Fatal("ready service helper was rejected")
	}
	if serviceReady(true, "inactive", os.ErrClosed, true) || serviceReady(false, "active", nil, true) || serviceReady(true, "active", nil, false) {
		t.Fatal("incomplete service helper was accepted")
	}
	requests, _ := useServiceDirs(t)
	previous := serviceRequestDirectory
	serviceRequestDirectory = requests
	if !serviceRequestsWritable() {
		t.Fatal("request directory was not writable")
	}
	serviceRequestDirectory = filepath.Join(t.TempDir(), "missing")
	if serviceRequestsWritable() {
		t.Fatal("missing request directory was writable")
	}
	serviceRequestDirectory = previous
}
