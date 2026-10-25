package spot

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"runnerfleet/internal/capacity"
)

type fakeEC2 struct {
	launchInput     *ec2.RunInstancesInput
	describeInput   *ec2.DescribeInstancesInput
	terminateInput  *ec2.TerminateInstancesInput
	launchOutput    *ec2.RunInstancesOutput
	launchErr       error
	describeErr     error
	imageRootDevice string
}

func (f *fakeEC2) RunInstances(_ context.Context, input *ec2.RunInstancesInput, _ ...func(*ec2.Options)) (*ec2.RunInstancesOutput, error) {
	f.launchInput = input
	return f.launchOutput, f.launchErr
}

func (f *fakeEC2) DescribeInstances(_ context.Context, input *ec2.DescribeInstancesInput, _ ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
	f.describeInput = input
	if f.describeErr != nil {
		return nil, f.describeErr
	}
	return &ec2.DescribeInstancesOutput{Reservations: []types.Reservation{{Instances: []types.Instance{{
		InstanceId:     aws.String("i-0123456789abcdef0"),
		InstanceType:   types.InstanceType("m7i.large"),
		PrivateDnsName: aws.String("ip-10-0-0-1.internal"),
		Architecture:   types.ArchitectureValuesX8664,
		State:          &types.InstanceState{Name: types.InstanceStateNameRunning},
	}}}}}, nil
}

func (f *fakeEC2) DescribeImages(_ context.Context, _ *ec2.DescribeImagesInput, _ ...func(*ec2.Options)) (*ec2.DescribeImagesOutput, error) {
	return &ec2.DescribeImagesOutput{Images: []types.Image{{RootDeviceName: aws.String(f.imageRootDevice), RootDeviceType: types.DeviceTypeEbs, Architecture: types.ArchitectureValuesX8664}}}, nil
}

func (f *fakeEC2) DescribeInstanceTypes(_ context.Context, _ *ec2.DescribeInstanceTypesInput, _ ...func(*ec2.Options)) (*ec2.DescribeInstanceTypesOutput, error) {
	return &ec2.DescribeInstanceTypesOutput{InstanceTypes: []types.InstanceTypeInfo{{
		VCpuInfo:      &types.VCpuInfo{DefaultVCpus: aws.Int32(2)},
		MemoryInfo:    &types.MemoryInfo{SizeInMiB: aws.Int64(8192)},
		ProcessorInfo: &types.ProcessorInfo{SupportedArchitectures: []types.ArchitectureType{types.ArchitectureTypeX8664}},
	}}}, nil
}

func (f *fakeEC2) TerminateInstances(_ context.Context, input *ec2.TerminateInstancesInput, _ ...func(*ec2.Options)) (*ec2.TerminateInstancesOutput, error) {
	f.terminateInput = input
	return &ec2.TerminateInstancesOutput{}, nil
}

func validConfig(mode string) capacity.SpotConfig {
	return capacity.SpotConfig{
		Region:                "us-east-1",
		ImageID:               "ami-0123456789abcdef0",
		ImageMode:             mode,
		SubnetIDs:             []string{"subnet-0123456789abcdef0", "subnet-abcdef0123456789a"},
		SecurityGroupIDs:      []string{"sg-0123456789abcdef0"},
		SpotInstanceTypes:     []string{"m7i.large", "m7a.large"},
		OnDemandInstanceTypes: []string{"m7i.large"},
		SlotsPerMachine:       1,
		MaxMachines:           8,
		IdleMinutes:           5,
		RootVolumeGiB:         40,
		FallbackAfterSeconds:  60,
	}
}

func validRequest(mode, market string) LaunchRequest {
	return LaunchRequest{
		LaunchID:       "launch-0123456789abcdef",
		PoolID:         "pool-0123456789",
		ClientToken:    "client-token-0123456789",
		BootstrapToken: "single-use-bootstrap-token",
		MachineName:    "rf-pool-01234567",
		ServerURL:      "https://fleet.example.test",
		InstanceType:   "m7i.large",
		SubnetID:       "subnet-abcdef0123456789a",
		Market:         market,
		Architecture:   "amd64",
		PoolCPU:        1,
		PoolMemoryMB:   1024,
		PoolDiskMB:     2048,
		Config:         validConfig(mode),
	}
}

func TestSpotLaunchUsesSafeMetadataAndBoundedBootstrap(t *testing.T) {
	fake := &fakeEC2{
		imageRootDevice: "/dev/xvda",
		launchOutput: &ec2.RunInstancesOutput{Instances: []types.Instance{{
			InstanceId:   aws.String("i-0123456789abcdef0"),
			InstanceType: types.InstanceType("m7i.large"),
			Architecture: types.ArchitectureValuesX8664,
			State:        &types.InstanceState{Name: types.InstanceStateNamePending},
		}}},
	}
	provider, err := New(fake)
	if err != nil {
		t.Fatal(err)
	}
	instance, err := provider.Launch(context.Background(), validRequest("bootstrap", "spot"))
	if err != nil {
		t.Fatal(err)
	}
	if instance.ID != "i-0123456789abcdef0" || instance.Market != "spot" || instance.CPU != 2 || instance.MemoryMB != 8192 || instance.Architecture != "amd64" {
		t.Fatalf("unexpected launched instance metadata: %+v", instance)
	}
	input := fake.launchInput
	if input == nil || aws.ToString(input.ClientToken) != "client-token-0123456789" {
		t.Fatal("launch did not preserve its idempotency token")
	}
	if input.InstanceMarketOptions == nil || input.InstanceMarketOptions.MarketType != types.MarketTypeSpot || input.InstanceMarketOptions.SpotOptions.InstanceInterruptionBehavior != types.InstanceInterruptionBehaviorTerminate {
		t.Fatal("launch did not request a terminating Spot instance")
	}
	if input.MetadataOptions == nil || input.MetadataOptions.HttpTokens != types.HttpTokensStateRequired || aws.ToInt32(input.MetadataOptions.HttpPutResponseHopLimit) != 1 {
		t.Fatal("launch did not require IMDSv2 with hop limit 1")
	}
	if aws.ToString(input.SubnetId) != "subnet-abcdef0123456789a" || input.BlockDeviceMappings[0].DeviceName == nil || *input.BlockDeviceMappings[0].DeviceName != "/dev/xvda" {
		t.Fatal("launch did not honor the selected subnet or AMI root device")
	}
	var userData string
	decoded, err := base64.StdEncoding.DecodeString(aws.ToString(input.UserData))
	if err != nil {
		t.Fatal("user-data was not base64 encoded")
	}
	userData = string(decoded)
	if !strings.Contains(userData, "setup-rootless-docker.sh") || !strings.Contains(userData, "RF_CODE_FILE") {
		t.Fatal("bootstrap mode did not install rootless Docker and enroll the agent")
	}
	if !strings.Contains(userData, "umask 077") {
		t.Fatal("bootstrap token file is not protected by a restrictive umask")
	}
}

func TestPrebakedModeSkipsDockerBootstrapAndOnDemandSkipsSpotMarket(t *testing.T) {
	fake := &fakeEC2{
		imageRootDevice: "/dev/sda1",
		launchOutput: &ec2.RunInstancesOutput{Instances: []types.Instance{{
			InstanceId: aws.String("i-0123456789abcdef0"),
		}}},
	}
	provider, err := New(fake)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = provider.Launch(context.Background(), validRequest("prebaked", "on-demand")); err != nil {
		t.Fatal(err)
	}
	if fake.launchInput.InstanceMarketOptions != nil {
		t.Fatal("On-Demand fallback was launched with Spot market options")
	}
	userData, err := base64.StdEncoding.DecodeString(aws.ToString(fake.launchInput.UserData))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(userData), "setup-rootless-docker.sh") {
		t.Fatal("prebaked AMI mode unexpectedly installed Docker at boot")
	}
}

func TestLaunchRejectsUnconfiguredSubnetAndFallbackType(t *testing.T) {
	fake := &fakeEC2{imageRootDevice: "/dev/xvda"}
	provider, err := New(fake)
	if err != nil {
		t.Fatal(err)
	}
	request := validRequest("bootstrap", "spot")
	request.SubnetID = "subnet-ffffffffffabcdef0"
	if _, err = provider.Launch(context.Background(), request); err == nil {
		t.Fatal("unconfigured subnet accepted")
	}
	request = validRequest("bootstrap", "on-demand")
	request.InstanceType = "m7a.large"
	if _, err = provider.Launch(context.Background(), request); err == nil {
		t.Fatal("unconfigured fallback instance type accepted")
	}
	if fake.launchInput != nil {
		t.Fatal("invalid request reached the EC2 client")
	}
}

func TestLaunchRejectsWorkerThatCannotFitOneJob(t *testing.T) {
	fake := &fakeEC2{imageRootDevice: "/dev/xvda"}
	provider, err := New(fake)
	if err != nil {
		t.Fatal(err)
	}
	request := validRequest("prebaked", "spot")
	request.PoolCPU = 3
	if _, err = provider.Launch(context.Background(), request); err == nil {
		t.Fatal("undersized instance type accepted for the pool")
	}
	if fake.launchInput != nil {
		t.Fatal("undersized instance reached RunInstances")
	}
}

func TestFindAndTerminateInstanceByBoundIdentity(t *testing.T) {
	fake := &fakeEC2{}
	provider, err := New(fake)
	if err != nil {
		t.Fatal(err)
	}
	instances, err := provider.FindByLaunchID(context.Background(), "launch-0123456789abcdef")
	if err != nil || len(instances) != 1 || instances[0].LaunchID != "launch-0123456789abcdef" {
		t.Fatalf("launch reconciliation failed: instances=%+v err=%v", instances, err)
	}
	if fake.describeInput == nil || len(fake.describeInput.Filters) != 1 || aws.ToString(fake.describeInput.Filters[0].Name) != "tag:runner-fleet-launch" {
		t.Fatal("reconciliation was not scoped to the launch identity")
	}
	instances, err = provider.FindByInstanceID(context.Background(), "i-0123456789abcdef0")
	if err != nil || len(instances) != 1 || instances[0].ID != "i-0123456789abcdef0" {
		t.Fatalf("instance reconciliation failed: instances=%+v err=%v", instances, err)
	}
	if fake.describeInput == nil || len(fake.describeInput.InstanceIds) != 1 || fake.describeInput.InstanceIds[0] != "i-0123456789abcdef0" {
		t.Fatal("instance reconciliation was not scoped to the exact instance id")
	}
	if err = provider.Terminate(context.Background(), "i-0123456789abcdef0"); err != nil {
		t.Fatal(err)
	}
	if fake.terminateInput == nil || len(fake.terminateInput.InstanceIds) != 1 {
		t.Fatal("termination did not target exactly the requested instance")
	}
	if err = provider.Terminate(context.Background(), "i-invalid"); err == nil {
		t.Fatal("invalid instance id accepted")
	}
}

func TestFallbackClassificationOnlyIncludesCapacityFailures(t *testing.T) {
	for _, code := range []string{"InsufficientInstanceCapacity", "InsufficientSpotInstanceCapacity", "MaxSpotInstanceCountExceeded", "SpotInstanceCountLimitExceeded"} {
		if !IsCapacityUnavailableCode(code) {
			t.Errorf("capacity error %q not classified", code)
		}
	}
	for _, code := range []string{"UnauthorizedOperation", "InvalidAMIID.NotFound", "RequestLimitExceeded", "EC2_OPERATION_FAILED"} {
		if IsCapacityUnavailableCode(code) {
			t.Errorf("non-capacity error %q could trigger paid fallback", code)
		}
	}
}
