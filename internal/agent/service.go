package agent

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"runnerfleet/internal/capacity"
)

var (
	serviceRequestDirectory = "/var/lib/runner-fleet-agent/service-requests"
	serviceStatusDirectory  = "/var/lib/runner-fleet-agent/service-status"
	servicePollInterval     = time.Second
	serviceStartTimeout     = 10 * time.Minute
)

var (
	serviceIDPattern      = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
	serviceVersionPattern = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)
	serviceSHAPattern     = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)
	serviceURLPattern     = regexp.MustCompile(`^https://github\.com/[A-Za-z0-9._/-]+$`)
	serviceTokenPattern   = regexp.MustCompile(`^[A-Za-z0-9._~+/=-]{1,512}$`)
	serviceNamePattern    = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)
	serviceLabelPattern   = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)
	serviceGroupPattern   = regexp.MustCompile(`^[A-Za-z0-9._ -]{0,128}$`)
)

func markService(v map[string]any) {
	v["systemd"] = false
	v["service_ready"] = false
	v["service_enforcement"] = false
	if runtime.GOOS != "linux" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	running, _ := cmd(ctx, "systemctl", "is-system-running")
	active, activeErr := cmd(ctx, "systemctl", "is-active", "runner-fleet-service.service")
	systemd := serviceSystemd(running)
	v["systemd"] = systemd
	v["service_enforcement"] = systemd
	v["service_ready"] = serviceReady(systemd, active, activeErr, serviceRequestsWritable())
}

func serviceSystemd(text string) bool {
	return text == "running" || text == "degraded"
}

func serviceReady(systemd bool, active string, activeErr error, writable bool) bool {
	if !systemd || !writable {
		return false
	}
	if activeErr != nil || active != "active" {
		return false
	}
	return true
}

func serviceRequestsWritable() bool {
	info, err := os.Stat(serviceRequestDirectory)
	if err != nil || !info.IsDir() {
		return false
	}
	probe := filepath.Join(serviceRequestDirectory, fmt.Sprintf(".probe-%d", os.Getpid()))
	file, err := os.OpenFile(probe, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return false
	}
	file.Close()
	os.Remove(probe)
	return true
}

func serviceRequest(spec capacity.Spec, arch string) ([]byte, error) {
	if spec.Pool.Execution != "service" {
		return nil, errors.New("not a service pool")
	}
	if !serviceIDPattern.MatchString(spec.Instance.ID) {
		return nil, errors.New("invalid instance id")
	}
	if !serviceVersionPattern.MatchString(spec.Pool.RunnerVersion) {
		return nil, errors.New("invalid runner version")
	}
	checksum := spec.Pool.RunnerSHA256AMD64
	if arch == "arm64" {
		checksum = spec.Pool.RunnerSHA256ARM64
	} else if arch != "amd64" {
		return nil, errors.New("unsupported architecture")
	}
	if !serviceSHAPattern.MatchString(checksum) {
		return nil, errors.New("invalid runner checksum")
	}
	if !serviceURLPattern.MatchString(spec.URL) || strings.Contains(spec.URL, "releases/download") {
		return nil, errors.New("invalid runner url")
	}
	if !serviceTokenPattern.MatchString(spec.Token) {
		return nil, errors.New("invalid runner token")
	}
	if !serviceNamePattern.MatchString(spec.Instance.Name) {
		return nil, errors.New("invalid runner name")
	}
	if len(spec.Pool.Labels) == 0 {
		return nil, errors.New("invalid runner labels")
	}
	for _, label := range spec.Pool.Labels {
		if strings.HasPrefix(label, "-") || !serviceLabelPattern.MatchString(label) {
			return nil, errors.New("invalid runner labels")
		}
	}
	if !serviceGroupPattern.MatchString(spec.Pool.Group) {
		return nil, errors.New("invalid runner group")
	}
	if spec.Instance.CPU <= 0 || spec.Instance.MemoryMB < 256 {
		return nil, errors.New("invalid service limits")
	}
	var body strings.Builder
	fields := []struct {
		key   string
		value string
	}{
		{key: "action", value: "install"},
		{key: "id", value: spec.Instance.ID},
		{key: "url", value: spec.URL},
		{key: "token", value: spec.Token},
		{key: "name", value: spec.Instance.Name},
		{key: "labels", value: strings.Join(spec.Pool.Labels, ",")},
		{key: "group", value: spec.Pool.Group},
		{key: "version", value: spec.Pool.RunnerVersion},
		{key: "sha256", value: checksum},
		{key: "cpu", value: strconv.FormatFloat(spec.Instance.CPU, 'f', 2, 64)},
		{key: "memory_mb", value: strconv.FormatInt(spec.Instance.MemoryMB, 10)},
	}
	for _, field := range fields {
		if strings.ContainsAny(field.value, "\n\r\x00") {
			return nil, errors.New("invalid service request")
		}
		body.WriteString(field.key)
		body.WriteByte('=')
		body.WriteString(field.value)
		body.WriteByte('\n')
	}
	encoded := body.String()
	if strings.Contains(encoded, "releases/download") {
		return nil, errors.New("invalid service request")
	}
	return []byte(encoded), nil
}

func writeServiceRequest(id string, body []byte) error {
	if !serviceIDPattern.MatchString(id) {
		return errors.New("invalid instance id")
	}
	if err := os.MkdirAll(serviceRequestDirectory, 0770); err != nil {
		return err
	}
	tmp := filepath.Join(serviceRequestDirectory, fmt.Sprintf(".%s.%d.tmp", id, os.Getpid()))
	final := filepath.Join(serviceRequestDirectory, id+".request")
	if err := os.WriteFile(tmp, body, 0600); err != nil {
		return err
	}
	if err := os.Rename(tmp, final); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

func writeRemoveRequest(id string) error {
	if !serviceIDPattern.MatchString(id) {
		return errors.New("invalid instance id")
	}
	body := []byte("action=remove\nid=" + id + "\n")
	return writeServiceRequest(id, body)
}

func readServiceStatus(id string) (map[string]string, error) {
	if !serviceIDPattern.MatchString(id) {
		return nil, errors.New("invalid instance id")
	}
	raw, err := os.ReadFile(filepath.Join(serviceStatusDirectory, id+".status"))
	if err != nil {
		return nil, err
	}
	values := map[string]string{}
	for _, line := range strings.Split(string(raw), "\n") {
		if line == "" {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		values[key] = value
	}
	return values, nil
}

func (a *Agent) startService(ctx context.Context, spec capacity.Spec) error {
	body, err := serviceRequest(spec, runtime.GOARCH)
	if err != nil {
		a.cleaned(spec.Instance.ID, "invalid service request")
		return errors.New("invalid service request")
	}
	if err = writeServiceRequest(spec.Instance.ID, body); err != nil {
		a.cleaned(spec.Instance.ID, "service request failed")
		return errors.New("service request failed")
	}
	deadline := time.Now().Add(serviceStartTimeout)
	for {
		if err = ctx.Err(); err != nil {
			return err
		}
		status, readErr := readServiceStatus(spec.Instance.ID)
		if readErr == nil {
			switch status["state"] {
			case "ready":
				a.mu.Lock()
				if item := a.Instances[spec.Instance.ID]; item != nil {
					if status["busy"] == "yes" {
						item.Instance.State = "busy"
					} else {
						item.Instance.State = "idle"
					}
					a.saveLocked()
				}
				a.mu.Unlock()
				return nil
			case "error":
				a.cleaned(spec.Instance.ID, "runner configuration failed")
				return errors.New("runner configuration failed")
			}
		}
		if !time.Now().Before(deadline) {
			_ = writeRemoveRequest(spec.Instance.ID)
			a.cleaned(spec.Instance.ID, "service runner deadline exceeded")
			return errors.New("service runner deadline exceeded")
		}
		timer := time.NewTimer(servicePollInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func (a *Agent) observeService(v Local) {
	status, err := readServiceStatus(v.Instance.ID)
	if err != nil {
		if v.Instance.State != "provisioning" && time.Now().Unix() > v.Deadline {
			a.cleaned(v.Instance.ID, "service runner status missing")
		}
		return
	}
	switch status["state"] {
	case "removed":
		a.cleaned(v.Instance.ID, "")
	case "error":
		a.cleaned(v.Instance.ID, "runner configuration failed")
	case "ready":
		state := "idle"
		if status["busy"] == "yes" {
			state = "busy"
		}
		if v.Draining && status["busy"] != "yes" {
			a.requestServiceRemoval(v.Instance.ID)
		}
		a.mu.Lock()
		if item := a.Instances[v.Instance.ID]; item != nil && item.Instance.State != "cleaned" {
			item.Instance.State = state
			a.saveLocked()
		}
		a.mu.Unlock()
	}
}

func (a *Agent) requestServiceRemoval(id string) {
	if !serviceIDPattern.MatchString(id) {
		return
	}
	marker := filepath.Join(a.Cfg.StateDir, "service-remove", id)
	if _, err := os.Stat(marker); err == nil {
		return
	}
	if err := writeRemoveRequest(id); err != nil {
		return
	}
	if err := os.MkdirAll(filepath.Dir(marker), 0700); err != nil {
		return
	}
	_ = os.WriteFile(marker, []byte("remove\n"), 0600)
}
