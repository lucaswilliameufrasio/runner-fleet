package agent

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/gorilla/websocket"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runnerfleet/internal/capacity"
	"runnerfleet/internal/store"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

type Config struct {
	ID       string `json:"id"`
	URL      string `json:"url"`
	StateDir string `json:"-"`
}
type Local struct {
	Instance      capacity.Instance `json:"instance"`
	Image         string            `json:"image"`
	Container     string            `json:"container"`
	Command       string            `json:"command"`
	Draining      bool              `json:"draining"`
	DockerSidecar bool              `json:"docker_sidecar"`
	Deadline      int64             `json:"deadline"`
}
type Agent struct {
	Cfg        Config
	mu         sync.Mutex
	Instances  map[string]*Local
	Completed  map[string]bool
	Policy     capacity.Machine
	running    map[string]bool
	DoctorData map[string]any
}

func New(dir string) (*Agent, error) {
	b, e := os.ReadFile(filepath.Join(dir, "config.json"))
	if e != nil {
		return nil, e
	}
	var c Config
	if e = json.Unmarshal(b, &c); e != nil {
		return nil, e
	}
	c.StateDir = dir
	a := &Agent{Cfg: c, Instances: map[string]*Local{}, Completed: map[string]bool{}, running: map[string]bool{}}
	b, _ = os.ReadFile(filepath.Join(dir, "state.json"))
	var v struct {
		Instances map[string]*Local
		Completed map[string]bool
		Policy    capacity.Machine
	}
	if json.Unmarshal(b, &v) == nil {
		if v.Instances != nil {
			a.Instances = v.Instances
		}
		if v.Completed != nil {
			a.Completed = v.Completed
		}
		a.Policy = v.Policy
	}
	a.DoctorData = Doctor()
	return a, nil
}
func csr(dir string) (string, error) {
	path := filepath.Join(dir, "client-key.pem")
	var key *ecdsa.PrivateKey
	b, e := os.ReadFile(path)
	if e == nil {
		p, _ := pem.Decode(b)
		if p == nil {
			return "", errors.New("invalid client key")
		}
		key, e = x509.ParseECPrivateKey(p.Bytes)
		if e != nil {
			return "", e
		}
	} else {
		if !os.IsNotExist(e) {
			return "", e
		}
		key, e = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if e != nil {
			return "", e
		}
		der, _ := x509.MarshalECPrivateKey(key)
		if e = os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0600); e != nil {
			return "", e
		}
	}
	b, e = x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "enrolling"}}, key)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: b})), e
}
func Enroll(ctx context.Context, dir, server, name, code string) error {
	if !strings.HasPrefix(server, "https://") {
		return errors.New("HTTPS required")
	}
	if e := os.MkdirAll(dir, 0700); e != nil {
		return e
	}
	if _, e := os.Stat(filepath.Join(dir, "config.json")); e == nil {
		return errors.New("already enrolled; use existing identity")
	}
	request, e := csr(dir)
	if e != nil {
		return e
	}
	b, _ := json.Marshal(map[string]any{"code": strings.TrimSpace(code), "csr": request, "name": name, "arch": runtime.GOARCH})
	req, _ := http.NewRequestWithContext(ctx, "POST", strings.TrimRight(server, "/")+"/api/enroll", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	cl := &http.Client{Timeout: 30 * time.Second}
	res, e := cl.Do(req)
	if e != nil {
		return e
	}
	defer res.Body.Close()
	if res.StatusCode != 201 {
		return fmt.Errorf("enrollment HTTP %d", res.StatusCode)
	}
	var v struct {
		ID   string `json:"id"`
		Cert string `json:"cert"`
		CA   string `json:"ca"`
		URL  string `json:"agent_url"`
	}
	if e = json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&v); e != nil {
		return e
	}
	if !strings.HasPrefix(v.URL, "wss://") {
		return errors.New("secure agent URL required")
	}
	files := []struct{ name, data string }{{"client.pem", v.Cert}, {"ca.pem", v.CA}, {"config.json", store.JSON(Config{ID: v.ID, URL: v.URL})}}
	for _, file := range files {
		if e = os.WriteFile(filepath.Join(dir, file.name+".tmp"), []byte(file.data), 0600); e != nil {
			return e
		}
	}
	for _, file := range files {
		if e = os.Rename(filepath.Join(dir, file.name+".tmp"), filepath.Join(dir, file.name)); e != nil {
			return e
		}
	}

	return nil
}
func (a *Agent) saveLocked() error {
	b, _ := json.Marshal(map[string]any{"Instances": a.Instances, "Completed": a.Completed, "Policy": a.Policy})
	p := filepath.Join(a.Cfg.StateDir, "state.json")
	if e := os.WriteFile(p+".tmp", b, 0600); e != nil {
		return e
	}
	return os.Rename(p+".tmp", p)
}
func cmd(ctx context.Context, args ...string) (string, error) {
	b, e := exec.CommandContext(ctx, args[0], args[1:]...).CombinedOutput()
	return strings.TrimSpace(string(b)), e
}
func Doctor() map[string]any {
	v := map[string]any{"arch": runtime.GOARCH, "os": runtime.GOOS, "cpu": runtime.NumCPU(), "ready": false, "enforcement": false}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	b, e := cmd(ctx, "docker", "info", "--format", "{{json .}}")
	if e != nil {
		v["error"] = "Docker unavailable to agent user"
		return v
	}
	var info map[string]any
	if json.Unmarshal([]byte(b), &info) != nil {
		v["error"] = "invalid Docker info"
		return v
	}
	rootless := false
	if options, ok := info["SecurityOptions"].([]any); ok {
		for _, x := range options {
			if strings.Contains(fmt.Sprint(x), "rootless") {
				rootless = true
			}
		}
	}
	v["rootless"] = rootless
	v["cgroup_version"] = info["CgroupVersion"]
	v["ready"] = rootless && text(info["CgroupVersion"]) == "2" && text(info["CgroupDriver"]) == "systemd" && info["MemoryLimit"] == true
	v["enforcement"] = v["ready"]
	v["docker_version"] = info["ServerVersion"]
	if v["ready"] != true {
		v["error"] = "rootless Docker + cgroup v2 required"
	}
	return v
}
func text(v any) string { x, _ := v.(string); return x }
func (a *Agent) telemetry() map[string]any {
	v := map[string]any{"cpu_count": runtime.NumCPU()}
	b, _ := os.ReadFile("/proc/meminfo")
	var available, total int64
	for _, line := range strings.Split(string(b), "\n") {
		var key string
		var kb int64
		fmt.Sscan(line, &key, &kb)
		if key == "MemAvailable:" {
			available = kb / 1024
		}
		if key == "MemTotal:" {
			total = kb / 1024
		}
	}
	var fs syscall.Statfs_t
	syscall.Statfs(a.Cfg.StateDir, &fs)
	free := int64(fs.Bavail) * int64(fs.Bsize) / (1024 * 1024)
	v["memory_total_mb"] = total
	v["memory_available_mb"] = available
	v["disk_available_mb"] = free
	v["pressure"] = available < 512 || free < 2048
	return v
}
func (a *Agent) Run(ctx context.Context) error {
	go a.monitor(ctx)
	for {
		if ctx.Err() != nil {
			return nil
		}
		e := a.connect(ctx)
		if e != nil {
			fmt.Fprintln(os.Stderr, "agent connection unavailable; retrying")
		}
		a.mu.Lock()
		a.Policy.State = "offline"
		for _, v := range a.Instances {
			if v.Instance.State == "idle" {
				v.Draining = false
			}
		}
		a.saveLocked()
		a.mu.Unlock()
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(5 * time.Second):
		}
	}
}
func (a *Agent) connect(ctx context.Context) error {
	connCtx, cancelConnection := context.WithCancel(ctx)
	defer cancelConnection()
	cert, e := tls.LoadX509KeyPair(filepath.Join(a.Cfg.StateDir, "client.pem"), filepath.Join(a.Cfg.StateDir, "client-key.pem"))
	if e != nil {
		return e
	}
	dial := websocket.Dialer{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}}, HandshakeTimeout: 20 * time.Second}
	conn, _, e := dial.DialContext(ctx, a.Cfg.URL, nil)
	if e != nil {
		return e
	}
	defer conn.Close()
	incoming := make(chan struct {
		Type string          `json:"type"`
		Data json.RawMessage `json:"data"`
	}, 16)
	done := make(chan struct{})
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		defer close(done)
		for {
			var m struct {
				Type string          `json:"type"`
				Data json.RawMessage `json:"data"`
			}
			if conn.ReadJSON(&m) != nil {
				return
			}
			select {
			case incoming <- m:
			case <-stop:
				return
			}
		}
	}()
	acks := make(chan map[string]any, 16)
	tick := time.NewTicker(10 * time.Second)
	defer tick.Stop()
	sendHeartbeat := func() error {
		a.mu.Lock()
		instances := []capacity.Instance{}
		for _, v := range a.Instances {
			instances = append(instances, v.Instance)
		}
		doctor := a.DoctorData
		logs := map[string]string{}
		logCount := 0
		for id := range a.Instances {
			if logCount >= 8 {
				break
			}
			if b, e := os.ReadFile(filepath.Join(a.Cfg.StateDir, "logs", id+".log")); e == nil {
				if len(b) > 16384 {
					b = b[len(b)-16384:]
				}
				logs[id] = string(b)
				logCount++
			}
		}
		a.mu.Unlock()
		conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		return conn.WriteJSON(map[string]any{"type": "heartbeat", "data": map[string]any{"doctor": doctor, "telemetry": a.telemetry(), "instances": instances, "logs": logs}})
	}
	if e = sendHeartbeat(); e != nil {
		return e
	}
	if leaf, e := x509.ParseCertificate(cert.Certificate[0]); e == nil && time.Until(leaf.NotAfter) < 10*24*time.Hour {
		csr, e := csr(a.Cfg.StateDir)
		if e == nil {
			conn.WriteJSON(map[string]any{"type": "rotate", "data": map[string]any{"csr": csr}})
		}
	}
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-done:
			return errors.New("connection lost")
		case <-tick.C:
			if e = sendHeartbeat(); e != nil {
				return e
			}
		case ack := <-acks:
			if e = conn.WriteJSON(map[string]any{"type": "ack", "data": ack}); e != nil {
				return e
			}
		case m := <-incoming:
			switch m.Type {
			case "retired":
				var ids []string
				if json.Unmarshal(m.Data, &ids) == nil {
					a.mu.Lock()
					for _, id := range ids {
						if v := a.Instances[id]; v != nil && v.Instance.State == "cleaned" {
							delete(a.Completed, v.Command)
							delete(a.Instances, id)
							os.Remove(filepath.Join(a.Cfg.StateDir, "logs", id+".log"))
						}
					}
					a.saveLocked()
					a.mu.Unlock()
				}
			case "policy":
				a.mu.Lock()
				json.Unmarshal(m.Data, &a.Policy)
				a.saveLocked()
				a.mu.Unlock()
			case "certificate":
				var v struct {
					Cert string `json:"cert"`
				}
				if json.Unmarshal(m.Data, &v) == nil && v.Cert != "" {
					os.WriteFile(filepath.Join(a.Cfg.StateDir, "client.pem"), []byte(v.Cert), 0600)
				}
			case "command":
				var c struct {
					ID      string          `json:"id"`
					Kind    string          `json:"kind"`
					Payload json.RawMessage `json:"payload"`
					Expires int64           `json:"expires"`
				}
				if json.Unmarshal(m.Data, &c) != nil {
					return errors.New("invalid command")
				}
				a.mu.Lock()
				completed := a.Completed[c.ID]
				running := a.running[c.ID]
				if !completed && !running {
					a.running[c.ID] = true
				}
				a.mu.Unlock()
				if running {
					continue
				}
				if completed {
					conn.WriteJSON(map[string]any{"type": "ack", "data": map[string]any{"id": c.ID, "ok": true}})
					continue
				}
				go func() {
					var e error
					if c.Expires < time.Now().Unix() {
						e = errors.New("expired command")
					} else {
						e = a.execute(connCtx, c.ID, c.Kind, c.Payload)
					}
					a.mu.Lock()
					delete(a.running, c.ID)
					if e == nil {
						a.Completed[c.ID] = true
					}
					a.saveLocked()
					a.mu.Unlock()
					msg := ""
					if e != nil {
						msg = e.Error()
					}
					select {
					case acks <- map[string]any{"id": c.ID, "ok": e == nil, "error": msg}:
					case <-stop:
					}
				}()
			}
		}
	}
}
func (a *Agent) execute(ctx context.Context, command, kind string, b json.RawMessage) error {
	switch kind {
	case "update":
		return a.update(ctx, b)
	case "doctor":
		a.mu.Lock()
		a.DoctorData = Doctor()
		a.mu.Unlock()
		return nil
	case "detach":
		var v struct {
			Instance string `json:"instance"`
		}
		if e := json.Unmarshal(b, &v); e != nil {
			return e
		}
		a.mu.Lock()
		defer a.mu.Unlock()
		if instance := a.Instances[v.Instance]; instance != nil {
			instance.Draining = true
			return a.saveLocked()
		}
		return nil
	case "start":
		var spec capacity.Spec
		if e := json.Unmarshal(b, &spec); e != nil {
			return e
		}
		return a.start(ctx, command, spec)
	default:
		return errors.New("unsupported command")
	}
}
func (a *Agent) start(ctx context.Context, command string, spec capacity.Spec) error {
	a.mu.Lock()
	if old := a.Instances[spec.Instance.ID]; old != nil {
		a.mu.Unlock()
		return nil
	}
	if a.Policy.State != "online" {
		a.mu.Unlock()
		return errors.New("machine not active")
	}
	count := 0
	cpu := 0.0
	var mem, disk int64
	for _, v := range a.Instances {
		if v.Instance.State != "cleaned" {
			count++
			cpu += v.Instance.CPU
			mem += v.Instance.MemoryMB
			disk += v.Instance.DiskMB
		}
	}
	if count >= a.Policy.MaxSlots || cpu+spec.Instance.CPU > a.Policy.CPU || mem+spec.Instance.MemoryMB > a.Policy.MemoryMB || disk+spec.Instance.DiskMB > a.Policy.DiskMB {
		a.mu.Unlock()
		return errors.New("local capacity exceeded")
	}
	if spec.Pool.DockerSidecar && a.Policy.Shared {
		a.mu.Unlock()
		return errors.New("Docker sidecar requires dedicated machine")
	}
	if a.DoctorData["ready"] != true {
		a.mu.Unlock()
		return errors.New("doctor not ready")
	}
	if spec.Instance.Machine != a.Cfg.ID || capacity.Validate(spec.Pool) != nil {
		a.mu.Unlock()
		return errors.New("invalid runner spec")
	}
	local := &Local{Instance: spec.Instance, Image: spec.Pool.Image, Container: "rf-" + spec.Instance.ID, Command: command, Deadline: time.Now().Add(10 * time.Minute).Unix(), DockerSidecar: spec.Pool.DockerSidecar}
	local.DockerSidecar = spec.Pool.DockerSidecar
	local.Instance.State = "provisioning"
	a.Instances[spec.Instance.ID] = local
	e := a.saveLocked()
	a.mu.Unlock()
	if e != nil {
		return e
	}
	work := filepath.Join(a.Cfg.StateDir, "bootstrap", spec.Instance.ID)
	if e = os.MkdirAll(work, 0700); e != nil {
		return e
	}
	defer os.RemoveAll(work)
	specJSON := store.JSON(map[string]any{"url": spec.URL, "token": spec.Token, "name": spec.Instance.Name, "labels": strings.Join(spec.Pool.Labels, ","), "group": spec.Pool.Group})
	if e = os.WriteFile(filepath.Join(work, "config.json"), []byte(specJSON), 0600); e != nil {
		return e
	}
	if _, e = cmd(ctx, "docker", "pull", spec.Pool.Image); e != nil {
		a.cleaned(spec.Instance.ID, "image pull failed")
		return errors.New("image pull failed")
	}
	if spec.Pool.DockerSidecar {
		if e = a.startDockerSidecar(ctx, local, spec); e != nil {
			if cleanupErr := a.cleanupContainers(ctx, *local); cleanupErr != nil {
				return errors.New("sidecar failed; cleanup pending")
			}
			a.cleaned(spec.Instance.ID, "isolated Docker sidecar failed")
			return e
		}
	}
	args := []string{"docker", "create", "--name", local.Container, "--label", "runner-fleet.machine=" + a.Cfg.ID, "--label", "runner-fleet.instance=" + spec.Instance.ID, "--cpus", strconv.FormatFloat(spec.Instance.CPU, 'f', 2, 64), "--memory", fmt.Sprint(spec.Instance.MemoryMB) + "m", "--memory-swap", fmt.Sprint(spec.Instance.MemoryMB) + "m", "--pids-limit", "512", "--security-opt", "no-new-privileges", "--cap-drop", "ALL", "--log-driver", "local", "--log-opt", "max-size=5m", "--log-opt", "max-file=2", spec.Pool.Image}
	if spec.Pool.DockerSidecar {
		args = args[:len(args)-1]
		for i := range args {
			if args[i] == "--cpus" {
				args[i+1] = strconv.FormatFloat(spec.Instance.CPU*0.6, 'f', 2, 64)
			}
			if args[i] == "--memory" || args[i] == "--memory-swap" {
				args[i+1] = fmt.Sprint(spec.Instance.MemoryMB*6/10) + "m"
			}
		}
		args = append(args, "--group-add", "0", "--network", "container:"+local.Container+"-docker", "--mount", "type=volume,src="+local.Container+"-work,dst=/runner/_work", "--mount", "type=volume,src="+local.Container+"-socket,dst=/var/run", "--env", "DOCKER_HOST=unix:///var/run/docker.sock", spec.Pool.Image)
	}
	if _, e = cmd(ctx, args...); e != nil {
		if cleanupErr := a.cleanupContainers(ctx, *local); cleanupErr != nil {
			return errors.New("container create failed; cleanup pending")
		}
		a.cleaned(spec.Instance.ID, "container create failed")
		return errors.New("container create failed")
	}
	if _, e = cmd(ctx, "docker", "cp", filepath.Join(work, "config.json"), local.Container+":/runner/bootstrap.json"); e != nil {
		if cleanupErr := a.cleanupContainers(ctx, *local); cleanupErr != nil {
			return errors.New("bootstrap failed; cleanup pending")
		}
		a.cleaned(spec.Instance.ID, "bootstrap copy failed")
		return errors.New("bootstrap failed")
	}
	if _, e = cmd(ctx, "docker", "start", local.Container); e != nil {
		return errors.New("container start outcome unknown; reconciliation pending")
	}
	a.mu.Lock()
	local.Instance.State = "idle"
	a.saveLocked()
	a.mu.Unlock()
	return nil
}
func (a *Agent) cleaned(id, msg string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if v := a.Instances[id]; v != nil {
		v.Instance.State = "cleaned"
		v.Instance.Error = msg
		a.saveLocked()
	}
}
func (a *Agent) monitor(ctx context.Context) {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		a.mu.Lock()
		items := []Local{}
		for _, v := range a.Instances {
			items = append(items, *v)
		}
		a.mu.Unlock()
		for _, v := range items {
			a.mu.Lock()
			provisioning := a.running[v.Command]
			a.mu.Unlock()
			if provisioning {
				continue
			}
			if v.Instance.State == "cleaned" {
				continue
			}
			inspectCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			out, e := cmd(inspectCtx, "docker", "inspect", "--format", "{{.State.Running}}", v.Container)
			if e != nil {
				if v.Instance.State != "provisioning" || time.Now().Unix() > v.Deadline {
					if a.cleanupContainers(inspectCtx, v) == nil {
						a.cleaned(v.Instance.ID, "container absent after reconciliation")
					}
				}
				cancel()
				continue
			}
			if out != "true" {
				b, _ := cmd(inspectCtx, "docker", "logs", "--tail", "100", v.Container)
				os.MkdirAll(filepath.Join(a.Cfg.StateDir, "logs"), 0700)
				os.WriteFile(filepath.Join(a.Cfg.StateDir, "logs", v.Instance.ID+".log"), []byte(b), 0600)
				e = a.cleanupContainers(inspectCtx, v)
				if e == nil {
					a.cleaned(v.Instance.ID, "")
				}
				cancel()
				continue
			}
			_, busyErr := cmd(inspectCtx, "docker", "exec", v.Container, "test", "-f", "/runner/.busy")
			state := "idle"
			if busyErr == nil {
				state = "busy"
			}
			if v.Draining && state == "idle" {
				_, e = cmd(inspectCtx, "docker", "exec", v.Container, "touch", "/runner/.detached")
				if e != nil {
					fmt.Fprintln(os.Stderr, "drain pending: could not mark detached runner")
				}
			}
			a.mu.Lock()
			if item := a.Instances[v.Instance.ID]; item != nil {
				item.Instance.State = state
			}
			a.saveLocked()
			a.mu.Unlock()
			cancel()
		}
	}
}

func (a *Agent) startDockerSidecar(ctx context.Context, v *Local, spec capacity.Spec) error {
	for _, suffix := range []string{"-work", "-socket"} {
		if _, e := cmd(ctx, "docker", "volume", "create", v.Container+suffix); e != nil {
			return errors.New("isolated Docker volume failed")
		}
	}
	if _, e := cmd(ctx, "docker", "pull", spec.Pool.DockerImage); e != nil {
		return errors.New("Docker sidecar image unavailable")
	}
	args := []string{"docker", "run", "-d", "--name", v.Container + "-docker", "--privileged", "--cpus", strconv.FormatFloat(spec.Instance.CPU*0.4, 'f', 2, 64), "--memory", fmt.Sprint(spec.Instance.MemoryMB*4/10) + "m", "--memory-swap", fmt.Sprint(spec.Instance.MemoryMB*4/10) + "m", "--pids-limit", "512", "--env", "DOCKER_TLS_CERTDIR=", "--mount", "type=volume,src=" + v.Container + "-work,dst=/runner/_work", "--mount", "type=volume,src=" + v.Container + "-socket,dst=/var/run", spec.Pool.DockerImage, "--host=unix:///var/run/docker.sock", "--storage-driver=vfs"}
	if _, e := cmd(ctx, args...); e != nil {
		return errors.New("isolated Docker daemon failed")
	}
	for i := 0; i < 30; i++ {
		if _, e := cmd(ctx, "docker", "exec", v.Container+"-docker", "docker", "info"); e == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
	return errors.New("isolated Docker daemon readiness timeout")
}
func (a *Agent) cleanupContainers(ctx context.Context, v Local) error {
	if _, e := cmd(ctx, "docker", "info", "--format", "{{.ServerVersion}}"); e != nil {
		return errors.New("Docker state unknown; cleanup cannot be confirmed")
	}
	if _, e := cmd(ctx, "docker", "rm", "-f", "-v", v.Container); e != nil {
		if out, exists := cmd(ctx, "docker", "inspect", v.Container); exists == nil || !strings.Contains(out, "No such object") {
			return e
		}
	}
	if v.DockerSidecar {
		if _, e := cmd(ctx, "docker", "rm", "-f", "-v", v.Container+"-docker"); e != nil {
			if out, exists := cmd(ctx, "docker", "inspect", v.Container+"-docker"); exists == nil || !strings.Contains(out, "No such object") {
				return e
			}
		}
		for _, suffix := range []string{"-work", "-socket"} {
			if _, e := cmd(ctx, "docker", "volume", "rm", v.Container+suffix); e != nil {
				if out, exists := cmd(ctx, "docker", "volume", "inspect", v.Container+suffix); exists == nil || !strings.Contains(out, "no such volume") {
					return e
				}
			}
		}
	}
	return nil
}
