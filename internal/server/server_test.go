package server

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/gorilla/websocket"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runnerfleet/internal/capacity"
	"runnerfleet/internal/github"
	"runnerfleet/internal/security"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/smithy-go"
	"runnerfleet/internal/spot"
)

func testServer(t *testing.T) *Server {
	t.Helper()
	s, e := New(Config{DataDir: t.TempDir(), Origin: "http://localhost:8080", Dev: true})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.Store.DB.Close() })
	return s
}
func request(t *testing.T, s *Server, method, path string, v any, cookie *http.Cookie, csrf string) (int, map[string]any, *http.Cookie) {
	t.Helper()
	b, _ := json.Marshal(v)
	r := httptest.NewRequest(method, path, bytes.NewReader(b))
	r.RemoteAddr = "127.0.0.1:1000"
	r.Header.Set("Content-Type", "application/json")
	if cookie != nil {
		r.AddCookie(cookie)
	}
	r.Header.Set("X-CSRF-Token", csrf)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	out := map[string]any{}
	json.Unmarshal(w.Body.Bytes(), &out)
	var c *http.Cookie
	if a := w.Result().Cookies(); len(a) > 0 {
		c = a[0]
	}
	return w.Code, out, c
}
func TestSetupLoginCSRFAndRecovery(t *testing.T) {
	s := testServer(t)
	code, e := s.SetupCode()
	if e != nil {
		t.Fatal(e)
	}
	status, _, _ := request(t, s, "POST", "/api/auth/setup", map[string]any{"code": code, "email": "a@example.com", "password": "a secure password"}, nil, "")
	if status != 201 {
		t.Fatal(status)
	}
	status, _, _ = request(t, s, "POST", "/api/auth/setup", map[string]any{"code": code, "email": "a@example.com", "password": "a secure password"}, nil, "")
	if status < 400 {
		t.Fatal("setup replay accepted")
	}
	status, body, cookie := request(t, s, "POST", "/api/auth/login", map[string]any{"email": "a@example.com", "password": "a secure password"}, nil, "")
	if status != 200 || cookie == nil {
		t.Fatal(status, body)
	}
	csrf := text(body["csrf"])
	status, _, _ = request(t, s, "POST", "/api/enrollment", nil, cookie, "")
	if status != 403 {
		t.Fatal("CSRF accepted", status)
	}
	status, _, _ = request(t, s, "POST", "/api/enrollment", nil, cookie, csrf)
	if status != 403 {
		t.Fatal("elevation bypassed")
	}
	status, _, _ = request(t, s, "POST", "/api/auth/reauth", map[string]any{"password": "a secure password"}, cookie, csrf)
	if status != 200 {
		t.Fatal(status)
	}
	status, _, _ = request(t, s, "POST", "/api/enrollment", nil, cookie, csrf)
	if status != 201 {
		t.Fatal(status)
	}
	recovery, e := s.Recover()
	if e != nil {
		t.Fatal(e)
	}
	status, _, _ = request(t, s, "GET", "/api/state", nil, cookie, "")
	if status != 401 {
		t.Fatal("old session survives recovery")
	}
	status, _, _ = request(t, s, "POST", "/api/auth/recover", map[string]any{"code": recovery, "password": "new secure password"}, nil, "")
	if status != 200 {
		t.Fatal(status)
	}
	status, _, _ = request(t, s, "POST", "/api/auth/recover", map[string]any{"code": recovery, "password": "new secure password"}, nil, "")
	if status != 403 {
		t.Fatal("recovery replay")
	}
}
func enrollTest(t *testing.T, s *Server) (tls.Certificate, string) {
	t.Helper()
	code := security.Random(32)
	s.Store.DB.Exec(`INSERT INTO enrollment(hash,expires) VALUES(?,?)`, security.Hash(code), time.Now().Add(time.Minute).Unix())
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csr, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	v := map[string]any{"code": code, "name": "host", "arch": "amd64", "csr": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr}))}
	status, body, _ := request(t, s, "POST", "/api/enroll", v, nil, "")
	if status != 201 {
		t.Fatal(status, body)
	}
	status, _, _ = request(t, s, "POST", "/api/enroll", v, nil, "")
	if status != 403 {
		t.Fatal("enrollment replay accepted")
	}
	der, _ := x509.MarshalECPrivateKey(key)
	cert, e := tls.X509KeyPair([]byte(text(body["cert"])), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}))
	if e != nil {
		t.Fatal(e)
	}
	return cert, text(body["id"])
}

func TestSpotLaunchPersistsSecretAndEnrollmentBindsInstance(t *testing.T) {
	s := testServer(t)
	p := capacity.Pool{
		ID: "pool-spot-test", Name: "Spot", Installation: 1, Scope: "org", Target: "acme", Group: "Fleet",
		Labels: []string{"self-hosted", "linux", "x64"}, Arch: "amd64", Image: "registry.test/runner@sha256:" + strings.Repeat("a", 64),
		Min: 0, Max: 4, CPU: 1, MemoryMB: 1024, DiskMB: 2048, Enabled: true, Trusted: true,
		Spot: &capacity.SpotConfig{
			Region: "us-east-1", ImageID: "ami-0123456789abcdef0", ImageMode: "prebaked",
			SubnetIDs: []string{"subnet-0123456789abcdef0"}, SecurityGroupIDs: []string{"sg-0123456789abcdef0"},
			SpotInstanceTypes: []string{"m7i.large"}, SlotsPerMachine: 2, MaxMachines: 4,
			IdleMinutes: 10, RootVolumeGiB: 40,
		},
	}
	if err := s.Store.Put("pool", p.ID, p); err != nil {
		t.Fatal(err)
	}
	if err := s.createSpotLaunch(p); err != nil {
		t.Fatal(err)
	}
	var launchID, enrollmentHash, snapshot string
	if err := s.Store.DB.QueryRow(`SELECT id,enrollment_hash,pool_snapshot FROM spot_launches WHERE pool=?`, p.ID).Scan(&launchID, &enrollmentHash, &snapshot); err != nil {
		t.Fatal(err)
	}
	var persisted capacity.Pool
	if err := json.Unmarshal([]byte(snapshot), &persisted); err != nil || persisted.ID != p.ID || persisted.Spot == nil || persisted.Spot.Region != "us-east-1" {
		t.Fatalf("launch snapshot not persisted correctly: %+v err=%v", persisted, err)
	}
	code, err := s.enrollmentCode(enrollmentHash)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(s.Store.Get("spot-enrollment:"+enrollmentHash), code) {
		t.Fatal("enrollment code was stored in plaintext")
	}
	const instanceID = "i-0123456789abcdef0"
	if _, err = s.Store.DB.Exec(`UPDATE spot_launches SET state='running',instance_id=?,cpu=2,memory_mb=8192,architecture='amd64' WHERE id=?`, instanceID, launchID); err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatal(err)
	}
	csrPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}))
	requestPayload := func(cloudID string) map[string]any {
		return map[string]any{"code": code, "name": "rf-spot-test", "arch": "amd64", "cloud_instance_id": cloudID, "csr": csrPEM}
	}
	status, _, _ := request(t, s, http.MethodPost, "/api/enroll", requestPayload("i-00000000000000000"), nil, "")
	if status != http.StatusForbidden {
		t.Fatalf("mismatched EC2 identity got HTTP %d", status)
	}
	status, body, _ := request(t, s, http.MethodPost, "/api/enroll", requestPayload(instanceID), nil, "")
	if status != http.StatusCreated || text(body["cloud_instance_id"]) != instanceID {
		t.Fatalf("valid Spot enrollment failed: status=%d body=%v", status, body)
	}
	var machine capacity.Machine
	if err = s.Store.Read("machine", text(body["id"]), &machine); err != nil {
		t.Fatal(err)
	}
	if machine.CloudProvider != "aws" || machine.CloudInstanceID != instanceID || machine.ProviderPool != p.ID || machine.CloudRegion != p.Spot.Region || machine.MaxSlots != 2 || machine.CPU != 2 || machine.MemoryMB != 8192 || machine.Shared {
		t.Fatalf("enrolled machine did not inherit trusted launch capacity: %+v", machine)
	}
	var state string
	if err = s.Store.DB.QueryRow(`SELECT state FROM spot_launches WHERE id=?`, launchID).Scan(&state); err != nil || state != "enrolled" {
		t.Fatalf("launch enrollment state=%q err=%v", state, err)
	}
}

func TestSpotPoolChangesRequireStepUpAndPersistTypedConfiguration(t *testing.T) {
	s := testServer(t)
	setupCode, err := s.SetupCode()
	if err != nil {
		t.Fatal(err)
	}
	status, _, _ := request(t, s, http.MethodPost, "/api/auth/setup", map[string]any{"code": setupCode, "email": "spot@example.com", "password": "long secure password"}, nil, "")
	if status != http.StatusCreated {
		t.Fatalf("admin setup got HTTP %d", status)
	}
	status, body, cookie := request(t, s, http.MethodPost, "/api/auth/login", map[string]any{"email": "spot@example.com", "password": "long secure password"}, nil, "")
	if status != http.StatusOK || cookie == nil {
		t.Fatalf("admin login got HTTP %d", status)
	}
	csrf := text(body["csrf"])
	pool := capacity.Pool{
		Name: "Spot pool", Installation: 1, Scope: "repo", Target: "acme/build", Labels: []string{"self-hosted", "linux", "x64"},
		Arch: "amd64", Image: "registry.test/runner@sha256:" + strings.Repeat("b", 64), Min: 0, Max: 4, Weight: 1,
		CPU: 1, MemoryMB: 1024, DiskMB: 2048, Enabled: false, Trusted: true,
		Spot: &capacity.SpotConfig{
			Region: "us-east-1", ImageID: "ami-0123456789abcdef0", ImageMode: "prebaked",
			SubnetIDs: []string{"subnet-0123456789abcdef0"}, SecurityGroupIDs: []string{"sg-0123456789abcdef0"},
			SpotInstanceTypes: []string{"m7i.large"}, SlotsPerMachine: 1, MaxMachines: 4,
			IdleMinutes: 10, RootVolumeGiB: 40,
		},
	}
	status, _, _ = request(t, s, http.MethodPost, "/api/pools", pool, cookie, csrf)
	if status != http.StatusForbidden {
		t.Fatalf("Spot pool write without step-up got HTTP %d", status)
	}
	status, _, _ = request(t, s, http.MethodPost, "/api/auth/reauth", map[string]any{"password": "long secure password"}, cookie, csrf)
	if status != http.StatusOK {
		t.Fatalf("step-up got HTTP %d", status)
	}
	status, body, _ = request(t, s, http.MethodPost, "/api/pools", pool, cookie, csrf)
	if status != http.StatusOK {
		t.Fatalf("Spot pool save got HTTP %d: %v", status, body)
	}
	var saved capacity.Pool
	if err = s.Store.Read("pool", text(body["id"]), &saved); err != nil || saved.Spot == nil || saved.Spot.Region != "us-east-1" {
		t.Fatalf("Spot configuration did not persist: %+v err=%v", saved, err)
	}
}

type fakeServerEC2 struct {
	launches      int
	instance      *types.Instance
	input         *ec2.RunInstancesInput
	launchErr     error
	hideLaunchTag bool
}

func (f *fakeServerEC2) RunInstances(_ context.Context, input *ec2.RunInstancesInput, _ ...func(*ec2.Options)) (*ec2.RunInstancesOutput, error) {
	f.launches++
	f.input = input
	if f.launchErr != nil {
		return nil, f.launchErr
	}
	if f.instance == nil {
		f.instance = &types.Instance{
			InstanceId: aws.String("i-0123456789abcdef0"), InstanceType: types.InstanceType("m7i.large"),
			Architecture: types.ArchitectureValuesX8664, State: &types.InstanceState{Name: types.InstanceStateNamePending},
		}
	}
	return &ec2.RunInstancesOutput{Instances: []types.Instance{*f.instance}}, nil
}

func (f *fakeServerEC2) DescribeInstances(_ context.Context, input *ec2.DescribeInstancesInput, _ ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
	if f.hideLaunchTag && len(input.InstanceIds) == 0 {
		return &ec2.DescribeInstancesOutput{}, nil
	}
	if f.instance == nil {
		return &ec2.DescribeInstancesOutput{}, nil
	}
	return &ec2.DescribeInstancesOutput{Reservations: []types.Reservation{{Instances: []types.Instance{*f.instance}}}}, nil
}

func (f *fakeServerEC2) DescribeImages(_ context.Context, _ *ec2.DescribeImagesInput, _ ...func(*ec2.Options)) (*ec2.DescribeImagesOutput, error) {
	return &ec2.DescribeImagesOutput{Images: []types.Image{{
		RootDeviceName: aws.String("/dev/xvda"), RootDeviceType: types.DeviceTypeEbs, Architecture: types.ArchitectureValuesX8664,
	}}}, nil
}

func (f *fakeServerEC2) DescribeInstanceTypes(_ context.Context, _ *ec2.DescribeInstanceTypesInput, _ ...func(*ec2.Options)) (*ec2.DescribeInstanceTypesOutput, error) {
	return &ec2.DescribeInstanceTypesOutput{InstanceTypes: []types.InstanceTypeInfo{{
		VCpuInfo: &types.VCpuInfo{DefaultVCpus: aws.Int32(2)}, MemoryInfo: &types.MemoryInfo{SizeInMiB: aws.Int64(8192)},
		ProcessorInfo: &types.ProcessorInfo{SupportedArchitectures: []types.ArchitectureType{types.ArchitectureTypeX8664}},
	}}}, nil
}

func (f *fakeServerEC2) TerminateInstances(_ context.Context, input *ec2.TerminateInstancesInput, _ ...func(*ec2.Options)) (*ec2.TerminateInstancesOutput, error) {
	if f.instance != nil {
		f.instance.State = &types.InstanceState{Name: types.InstanceStateNameShuttingDown}
	}
	return &ec2.TerminateInstancesOutput{}, nil
}

func TestSpotReconcileLaunchesPersistentlyAndDoesNotDuplicate(t *testing.T) {
	s := testServer(t)
	s.Cfg.Origin = "https://fleet.example.test"
	fake := &fakeServerEC2{}
	provider, err := spot.New(fake)
	if err != nil {
		t.Fatal(err)
	}
	s.spotProviders["us-east-1"] = provider
	p := capacity.Pool{
		ID: "pool-reconcile", Name: "Spot", Installation: 1, Scope: "repo", Target: "acme/build",
		Labels: []string{"self-hosted", "linux", "x64"}, Arch: "amd64", Image: "registry.test/runner@sha256:" + strings.Repeat("c", 64),
		Min: 1, Max: 4, Weight: 1, CPU: 1, MemoryMB: 1024, DiskMB: 2048, Enabled: true, Trusted: true,
		Spot: &capacity.SpotConfig{
			Region: "us-east-1", ImageID: "ami-0123456789abcdef0", ImageMode: "prebaked",
			SubnetIDs: []string{"subnet-0123456789abcdef0"}, SecurityGroupIDs: []string{"sg-0123456789abcdef0"},
			SpotInstanceTypes: []string{"m7i.large"}, SlotsPerMachine: 1, MaxMachines: 4, IdleMinutes: 10, RootVolumeGiB: 40,
		},
	}
	if err = s.Store.Put("pool", p.ID, p); err != nil {
		t.Fatal(err)
	}
	s.reconcileSpot(context.Background())
	if fake.launches != 1 || fake.input == nil {
		t.Fatalf("expected one EC2 launch, got %d", fake.launches)
	}
	var state, instanceID string
	if err = s.Store.DB.QueryRow(`SELECT state,instance_id FROM spot_launches WHERE pool=?`, p.ID).Scan(&state, &instanceID); err != nil || state != "running" || instanceID != "i-0123456789abcdef0" {
		t.Fatalf("launch wasn't persisted: state=%s instance=%s err=%v", state, instanceID, err)
	}
	s.reconcileSpot(context.Background())
	if fake.launches != 1 {
		t.Fatalf("reconciliation duplicated an EC2 launch: calls=%d", fake.launches)
	}
}

func TestDisablingSpotPoolStopsUnenrolledLaunchAndDrainsMachines(t *testing.T) {
	s := testServer(t)
	s.Cfg.Origin = "https://fleet.example.test"
	fake := &fakeServerEC2{}
	provider, err := spot.New(fake)
	if err != nil {
		t.Fatal(err)
	}
	s.spotProviders["us-east-1"] = provider
	p := capacity.Pool{
		ID: "pool-disable", Name: "Spot", Installation: 1, Scope: "repo", Target: "acme/build",
		Labels: []string{"self-hosted", "linux", "x64"}, Arch: "amd64", Image: "registry.test/runner@sha256:" + strings.Repeat("e", 64),
		Min: 1, Max: 4, Weight: 1, CPU: 1, MemoryMB: 1024, DiskMB: 2048, Enabled: true, Trusted: true,
		Spot: &capacity.SpotConfig{
			Region: "us-east-1", ImageID: "ami-0123456789abcdef0", ImageMode: "prebaked",
			SubnetIDs: []string{"subnet-0123456789abcdef0"}, SecurityGroupIDs: []string{"sg-0123456789abcdef0"},
			SpotInstanceTypes: []string{"m7i.large"}, SlotsPerMachine: 1, MaxMachines: 4, IdleMinutes: 10, RootVolumeGiB: 40,
		},
	}
	if err = s.Store.Put("pool", p.ID, p); err != nil {
		t.Fatal(err)
	}
	if err = s.createSpotLaunch(p); err != nil {
		t.Fatal(err)
	}
	s.reconcileSpot(context.Background())
	if fake.launches != 1 || fake.instance == nil {
		t.Fatalf("expected initial launch, calls=%d", fake.launches)
	}
	p.Enabled = false
	if err = s.Store.Put("pool", p.ID, p); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Store.DB.Exec(`UPDATE spot_launches SET next=? WHERE pool=?`, time.Now().Unix(), p.ID); err != nil {
		t.Fatal(err)
	}
	s.reconcileSpot(context.Background())
	if fake.launches != 1 {
		t.Fatalf("disabled pool launched new capacity, calls=%d", fake.launches)
	}
	var state string
	if err = s.Store.DB.QueryRow(`SELECT state FROM spot_launches WHERE pool=?`, p.ID).Scan(&state); err != nil || state != "terminating" {
		t.Fatalf("disabled pool didn't terminate the unenrolled worker: state=%q err=%v", state, err)
	}
}

func TestSpotReconciliationMarksEnrolledMachineTerminatedWhenTagLookupExpires(t *testing.T) {
	s := testServer(t)
	fake := &fakeServerEC2{hideLaunchTag: true, instance: &types.Instance{
		InstanceId: aws.String("i-0123456789abcdef0"),
		State:      &types.InstanceState{Name: types.InstanceStateNameTerminated},
	}}
	provider, err := spot.New(fake)
	if err != nil {
		t.Fatal(err)
	}
	s.spotProviders["us-east-1"] = provider
	p := capacity.Pool{
		ID: "pool-gone", Name: "Spot", Installation: 1, Scope: "repo", Target: "acme/build",
		Labels: []string{"self-hosted", "linux", "x64"}, Arch: "amd64", Image: "registry.test/runner@sha256:" + strings.Repeat("f", 64),
		Min: 0, Max: 4, Weight: 1, CPU: 1, MemoryMB: 1024, DiskMB: 2048, Enabled: true, Trusted: true,
		Spot: &capacity.SpotConfig{
			Region: "us-east-1", ImageID: "ami-0123456789abcdef0", ImageMode: "prebaked",
			SubnetIDs: []string{"subnet-0123456789abcdef0"}, SecurityGroupIDs: []string{"sg-0123456789abcdef0"},
			SpotInstanceTypes: []string{"m7i.large"}, SlotsPerMachine: 1, MaxMachines: 4, IdleMinutes: 10, RootVolumeGiB: 40,
		},
	}
	if err = s.Store.Put("pool", p.ID, p); err != nil {
		t.Fatal(err)
	}
	if err = s.createSpotLaunch(p); err != nil {
		t.Fatal(err)
	}
	var launchID string
	if err = s.Store.DB.QueryRow(`SELECT id FROM spot_launches WHERE pool=?`, p.ID).Scan(&launchID); err != nil {
		t.Fatal(err)
	}
	machine := capacity.Machine{
		ID: "machine-gone", Name: "worker", Arch: "amd64", State: "online", CloudProvider: "aws",
		CloudInstanceID: "i-0123456789abcdef0", CloudRegion: "us-east-1", ProviderPool: p.ID,
	}
	if err = s.Store.Put("machine", machine.ID, machine); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Store.DB.Exec(`UPDATE spot_launches SET state='enrolled',instance_id=?,machine_id=?,next=? WHERE id=?`, machine.CloudInstanceID, machine.ID, time.Now().Unix(), launchID); err != nil {
		t.Fatal(err)
	}
	if err = s.processSpotLaunches(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	if err = s.Store.Read("machine", machine.ID, &machine); err != nil {
		t.Fatal(err)
	}
	if machine.State != "terminated" {
		t.Fatalf("machine state after EC2 termination=%q", machine.State)
	}
	var state string
	if err = s.Store.DB.QueryRow(`SELECT state FROM spot_launches WHERE id=?`, launchID).Scan(&state); err != nil || state != "terminated" {
		t.Fatalf("launch state after EC2 termination=%q err=%v", state, err)
	}
}

func TestSpotFallbackOccursOnlyAfterCapacityErrorAndConfiguredDelay(t *testing.T) {
	s := testServer(t)
	s.Cfg.Origin = "https://fleet.example.test"
	fake := &fakeServerEC2{launchErr: &smithy.GenericAPIError{Code: "InsufficientSpotInstanceCapacity", Message: "synthetic capacity failure", Fault: smithy.FaultServer}}
	provider, err := spot.New(fake)
	if err != nil {
		t.Fatal(err)
	}
	s.spotProviders["us-east-1"] = provider
	p := capacity.Pool{
		ID: "pool-fallback", Name: "Spot", Installation: 1, Scope: "repo", Target: "acme/build",
		Labels: []string{"self-hosted", "linux", "x64"}, Arch: "amd64", Image: "registry.test/runner@sha256:" + strings.Repeat("d", 64),
		Min: 1, Max: 4, Weight: 1, CPU: 1, MemoryMB: 1024, DiskMB: 2048, Enabled: true, Trusted: true,
		Spot: &capacity.SpotConfig{
			Region: "us-east-1", ImageID: "ami-0123456789abcdef0", ImageMode: "prebaked",
			SubnetIDs: []string{"subnet-0123456789abcdef0"}, SecurityGroupIDs: []string{"sg-0123456789abcdef0"},
			SpotInstanceTypes: []string{"m7i.large"}, OnDemandInstanceTypes: []string{"m7i.large"},
			SlotsPerMachine: 1, MaxMachines: 4, IdleMinutes: 10, RootVolumeGiB: 40, FallbackAfterSeconds: 60,
		},
	}
	if err = s.createSpotLaunch(p); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Store.DB.Exec(`UPDATE spot_launches SET created=?,next=? WHERE pool=?`, time.Now().Add(-time.Minute).Unix(), time.Now().Unix(), p.ID); err != nil {
		t.Fatal(err)
	}
	if err = s.processSpotLaunches(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	var market, errorCode string
	if err = s.Store.DB.QueryRow(`SELECT market,error FROM spot_launches WHERE pool=?`, p.ID).Scan(&market, &errorCode); err != nil {
		t.Fatal(err)
	}
	if market != "spot" || errorCode != "InsufficientSpotInstanceCapacity" {
		t.Fatalf("unexpected failure state: market=%s error=%s", market, errorCode)
	}
	fake.launchErr = nil
	if _, err = s.Store.DB.Exec(`UPDATE spot_launches SET next=? WHERE pool=?`, time.Now().Unix(), p.ID); err != nil {
		t.Fatal(err)
	}
	if err = s.processSpotLaunches(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	if fake.launches != 2 || fake.input == nil || fake.input.InstanceMarketOptions != nil {
		t.Fatalf("expected explicit On-Demand fallback after capacity delay, calls=%d input=%+v", fake.launches, fake.input)
	}
	if err = s.Store.DB.QueryRow(`SELECT market FROM spot_launches WHERE pool=?`, p.ID).Scan(&market); err != nil || market != "on-demand" {
		t.Fatalf("fallback market=%q err=%v", market, err)
	}
}

func TestMTLSHeartbeatAndRevocation(t *testing.T) {
	s := testServer(t)
	s.Cfg.AgentURL = "wss://agents.example.com/agent"
	cert, id := enrollTest(t, s)
	ts := httptest.NewUnstartedServer(s.AgentHandler())
	ts.TLS = s.AgentTLS()
	ts.StartTLS()
	defer ts.Close()
	roots := x509.NewCertPool()
	roots.AddCert(ts.Certificate())
	dial := websocket.Dialer{TLSClientConfig: &tls.Config{RootCAs: roots}}
	if conn, _, e := dial.Dial("wss"+ts.URL[5:]+"/agent", nil); e == nil {
		conn.Close()
		t.Fatal("client without certificate accepted")
	}
	dial.TLSClientConfig.Certificates = []tls.Certificate{cert}
	conn, _, e := dial.Dial("wss"+ts.URL[5:]+"/agent", nil)
	if e != nil {
		t.Fatal(e)
	}
	defer conn.Close()
	e = conn.WriteJSON(map[string]any{"type": "heartbeat", "data": map[string]any{"doctor": map[string]any{"ready": true}, "telemetry": map[string]any{}, "instances": []any{}}})
	if e != nil {
		t.Fatal(e)
	}
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	var out map[string]any
	if e = conn.ReadJSON(&out); e != nil || text(out["type"]) != "policy" {
		t.Fatal(e, out)
	}
	var m capacity.Machine
	s.Store.Read("machine", id, &m)
	if m.State != "online" || m.LastSeen == 0 {
		t.Fatal(m)
	}
	m.State = "revoked"
	s.Store.Put("machine", id, m)
	if c, _, e := dial.Dial("wss"+ts.URL[5:]+"/agent", nil); e == nil {
		c.Close()
		t.Fatal("revoked identity accepted")
	}
}
func TestWebhookDurabilityDedupAndMonotonicJobs(t *testing.T) {
	s := testServer(t)
	s.secretPut("github_app", appConfig{WebhookSecret: "012345678901234567890123456789"})
	payload := []byte(`{"workflow_job":{"id":42,"status":"completed","conclusion":"success"},"repository":{"full_name":"org/api"},"installation":{"id":1}}`)
	mac := hmac.New(sha256.New, []byte("012345678901234567890123456789"))
	mac.Write(payload)
	for i := 0; i < 2; i++ {
		r := httptest.NewRequest("POST", "/api/github/webhook", bytes.NewReader(payload))
		r.Header.Set("X-Hub-Signature-256", "sha256="+hex.EncodeToString(mac.Sum(nil)))
		r.Header.Set("X-GitHub-Delivery", "delivery")
		r.Header.Set("X-GitHub-Event", "workflow_job")
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != 202 {
			t.Fatal(w.Code)
		}
	}
	var n int
	s.Store.DB.QueryRow(`SELECT COUNT(*) FROM tasks`).Scan(&n)
	if n != 1 {
		t.Fatal("duplicate task", n)
	}
	if e := s.processWebhook(t.Context(), "webhook:workflow_job", string(payload)); e != nil {
		t.Fatal(e)
	}
	s.putJob(map[string]any{"id": float64(42), "status": "queued"})
	var job map[string]any
	s.Store.Read("job", "42", &job)
	if job["status"] != "completed" {
		t.Fatal("job regressed")
	}
	r := httptest.NewRequest("POST", "/api/github/webhook", bytes.NewReader(payload))
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("unsigned webhook accepted")
	}
}

var _ = io.EOF

func TestDiscoveryThroughGitHubAPIFixture(t *testing.T) {
	s := testServer(t)
	private, _ := rsa.GenerateKey(rand.Reader, 2048)
	raw, _ := x509.MarshalPKCS8PrivateKey(private)
	client := github.New("7", string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: raw})))
	workflow := "jobs:\n  build:\n    runs-on: ubuntu-latest\n    steps: []\n"
	tokenCalls := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/app/installations/7/access_tokens":
			tokenCalls++
			fmt.Fprintf(w, `{"token":"scoped","expires_at":%q}`, time.Now().Add(time.Hour).UTC().Format(time.RFC3339))
		case "/installation/repositories":
			fmt.Fprint(w, `{"repositories":[{"id":1,"full_name":"acme/api","private":true,"default_branch":"main"}]}`)
		case "/repos/acme/api/contents/.github/workflows":
			fmt.Fprint(w, `[{"path":".github/workflows/build.yml"}]`)
		case "/repos/acme/api/contents/.github/workflows/build.yml":
			fmt.Fprintf(w, `{"sha":"source-sha","content":%q}`, base64.StdEncoding.EncodeToString([]byte(workflow)))
		case "/repos/acme/api/actions/runs":
			fmt.Fprint(w, `{"workflow_runs":[{"id":99,"run_attempt":1}]}`)
		case "/repos/acme/api/actions/runs/99/attempts/1/jobs":
			fmt.Fprint(w, `{"jobs":[{"id":42,"name":"build","status":"completed","conclusion":"success","labels":["ubuntu-latest"],"runner_name":"GitHub Actions 1","started_at":"2026-10-13T10:00:00Z","completed_at":"2026-10-13T10:02:00Z"}]}`)
		case "/repos/acme/api/actions/runners", "/orgs/acme/actions/runners":
			fmt.Fprint(w, `{"runners":[],"total_count":0}`)
		case "/orgs/acme/actions/runner-groups":
			fmt.Fprint(w, `{"runner_groups":[],"total_count":0}`)
		default:
			t.Errorf("unexpected GitHub endpoint %s", r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	defer ts.Close()
	client.Base = ts.URL
	s.ghClient = client
	s.Store.Put("installation", "7", map[string]any{"id": 7, "owner": "acme", "scope_type": "Organization", "active": true})
	if e := s.scanInstallation(t.Context(), 7); e != nil {
		t.Fatal(e)
	}
	workflows, _ := s.Store.List("workflow")
	jobs, _ := s.Store.List("job")
	if len(workflows) != 1 || len(jobs) != 1 || tokenCalls != 1 {
		t.Fatal(len(workflows), len(jobs), tokenCalls)
	}
	var scan map[string]any
	s.Store.Read("scan", "7", &scan)
	if scan["state"] != "completed" {
		t.Fatal(scan)
	}
	analytics := s.analytics()
	if analytics["hosted_minutes"] != float64(2) || analytics["peak_concurrency"] != 1 {
		t.Fatal(analytics)
	}
}

func TestStaticBootstrapGetsExactCSPHash(t *testing.T) {
	s := testServer(t)
	s.Cfg.WebDir = t.TempDir()
	script := "\nconsole.log('boot');\n"
	os.WriteFile(filepath.Join(s.Cfg.WebDir, "index.html"), []byte("<html><script>"+script+"</script></html>"), 0600)
	r := httptest.NewRequest("GET", "/setup", nil)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	sum := sha256.Sum256([]byte(script))
	if w.Code != 200 || !strings.Contains(w.Header().Get("Content-Security-Policy"), "'sha256-"+base64.StdEncoding.EncodeToString(sum[:])+"'") {
		t.Fatal("bootstrap blocked by CSP", w.Code, w.Header())
	}
}

func TestServicePoolScalesIdleRunnersDownToTarget(t *testing.T) {
	s := testServer(t)
	service := capacity.Pool{
		ID: "svc", Name: "Service", Installation: 1, Scope: "repo", Target: "acme/build",
		Labels: []string{"linux"}, Arch: "amd64", Execution: "service",
		RunnerVersion: "2.321.0", RunnerSHA256AMD64: strings.Repeat("a", 64), RunnerSHA256ARM64: strings.Repeat("b", 64),
		Machines: []string{"m"}, Min: 1, Max: 4, CPU: 1, MemoryMB: 512, DiskMB: 1024, Enabled: true, Trusted: true,
	}
	container := service
	container.ID = "box"
	container.Name = "Container"
	container.Execution = ""
	container.Image = "registry.test/runner@sha256:" + strings.Repeat("c", 64)
	container.Min = 0
	if err := s.Store.Put("pool", service.ID, service); err != nil {
		t.Fatal(err)
	}
	if err := s.Store.Put("pool", container.ID, container); err != nil {
		t.Fatal(err)
	}
	insert := func(id string, poolID string, updated int64) {
		t.Helper()
		instance := capacity.Instance{ID: id, Name: "rf-" + id, Pool: poolID, Machine: "m", State: "idle", CPU: 1, MemoryMB: 512, DiskMB: 1024, Created: updated}
		body, err := json.Marshal(instance)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = s.Store.DB.Exec(`INSERT INTO instances VALUES(?,?,?,?,?,?)`, id, poolID, "m", "idle", string(body), updated); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now().Unix()
	insert("keep", service.ID, now-20)
	insert("drop", service.ID, now)
	insert("box1", container.ID, now)
	s.schedule(context.Background())
	s.schedule(context.Background())
	rows, err := s.Store.DB.Query(`SELECT json_extract(data,'$.instance') FROM commands WHERE kind='drain' AND state='pending'`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	got := []string{}
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			t.Fatal(err)
		}
		got = append(got, id)
	}
	if err = rows.Err(); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != "drop" {
		t.Fatalf("service scale-in drains = %v", got)
	}
}

func TestServiceMachineSchedulableWithoutDocker(t *testing.T) {
	now := time.Now()
	machine := capacity.Machine{ID: "m", Arch: "amd64", State: "online", LastSeen: now.Unix(), Doctor: map[string]any{"service_ready": true, "ready": false}}
	pool := capacity.Pool{Arch: "amd64", Execution: "service"}
	if !machineSchedulable(machine, pool, now) {
		t.Fatal("dedicated service machine was rejected")
	}
	machine.Shared = true
	if machineSchedulable(machine, pool, now) {
		t.Fatal("shared service machine without enforcement was accepted")
	}
	machine.Doctor["service_enforcement"] = true
	if !machineSchedulable(machine, pool, now) {
		t.Fatal("shared service machine with enforcement was rejected")
	}
	pool.Execution = ""
	if machineSchedulable(machine, pool, now) {
		t.Fatal("container machine without rootless Docker was accepted")
	}
}
