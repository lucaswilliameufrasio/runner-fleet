package spot

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/smithy-go"
	"runnerfleet/internal/capacity"
)

type EC2API interface {
	RunInstances(context.Context, *ec2.RunInstancesInput, ...func(*ec2.Options)) (*ec2.RunInstancesOutput, error)
	DescribeInstances(context.Context, *ec2.DescribeInstancesInput, ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error)
	DescribeImages(context.Context, *ec2.DescribeImagesInput, ...func(*ec2.Options)) (*ec2.DescribeImagesOutput, error)
	DescribeInstanceTypes(context.Context, *ec2.DescribeInstanceTypesInput, ...func(*ec2.Options)) (*ec2.DescribeInstanceTypesOutput, error)
	TerminateInstances(context.Context, *ec2.TerminateInstancesInput, ...func(*ec2.Options)) (*ec2.TerminateInstancesOutput, error)
}

type LaunchRequest struct {
	LaunchID       string
	PoolID         string
	ClientToken    string
	BootstrapToken string
	MachineName    string
	ServerURL      string
	InstanceType   string
	SubnetID       string
	Market         string
	Architecture   string
	PoolCPU        float64
	PoolMemoryMB   int64
	PoolDiskMB     int64
	Config         capacity.SpotConfig
}

type Instance struct {
	ID           string
	Type         string
	Market       string
	State        string
	LaunchID     string
	PrivateDNS   string
	Architecture string
	CPU          float64
	MemoryMB     int64
}

type Provider struct {
	client EC2API
}

func IsCapacityUnavailableCode(code string) bool {
	switch code {
	case "InsufficientInstanceCapacity", "InsufficientSpotInstanceCapacity", "MaxSpotInstanceCountExceeded", "SpotInstanceCountLimitExceeded":
		return true
	default:
		return false
	}
}

func SafeErrorCode(err error) string {
	var apiError smithy.APIError
	if errors.As(err, &apiError) {
		return apiError.ErrorCode()
	}
	return "EC2_OPERATION_FAILED"
}

func New(client EC2API) (*Provider, error) {
	if client == nil {
		return nil, errors.New("EC2 client required")
	}
	return &Provider{client: client}, nil
}

func NewDefault(ctx context.Context, region string) (*Provider, error) {
	if region == "" {
		return nil, errors.New("AWS region required")
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("AWS credential provider unavailable: %w", err)
	}
	return New(ec2.NewFromConfig(cfg))
}

func (p *Provider) Launch(ctx context.Context, request LaunchRequest) (Instance, error) {
	if err := validateLaunchRequest(request); err != nil {
		return Instance{}, err
	}
	userData, err := bootstrapScript(request)
	if err != nil {
		return Instance{}, err
	}
	imageOutput, err := p.client.DescribeImages(ctx, &ec2.DescribeImagesInput{
		ImageIds: []string{request.Config.ImageID},
	})
	if err != nil {
		return Instance{}, fmt.Errorf("AMI lookup failed: %w", err)
	}
	if imageOutput == nil || len(imageOutput.Images) != 1 || aws.ToString(imageOutput.Images[0].RootDeviceName) == "" || imageOutput.Images[0].RootDeviceType != types.DeviceTypeEbs {
		return Instance{}, errors.New("configured AMI has no root device")
	}
	if fleetArchitecture(string(imageOutput.Images[0].Architecture)) != request.Architecture {
		return Instance{}, errors.New("configured AMI does not match pool architecture")
	}
	typeOutput, err := p.client.DescribeInstanceTypes(ctx, &ec2.DescribeInstanceTypesInput{
		InstanceTypes: []types.InstanceType{types.InstanceType(request.InstanceType)},
	})
	if err != nil {
		return Instance{}, fmt.Errorf("instance type lookup failed: %w", err)
	}
	if typeOutput == nil || len(typeOutput.InstanceTypes) != 1 || typeOutput.InstanceTypes[0].VCpuInfo == nil || typeOutput.InstanceTypes[0].MemoryInfo == nil || typeOutput.InstanceTypes[0].MemoryInfo.SizeInMiB == nil {
		return Instance{}, errors.New("EC2 instance type has incomplete capacity metadata")
	}
	if !supportsArchitecture(typeOutput.InstanceTypes[0], request.Architecture) {
		return Instance{}, errors.New("EC2 instance type does not support pool architecture")
	}
	instanceCPU := float64(aws.ToInt32(typeOutput.InstanceTypes[0].VCpuInfo.DefaultVCpus))
	instanceMemory := aws.ToInt64(typeOutput.InstanceTypes[0].MemoryInfo.SizeInMiB)
	if request.PoolCPU <= 0 || request.PoolMemoryMB <= 0 || request.PoolDiskMB <= 0 || instanceCPU < request.PoolCPU || instanceMemory < request.PoolMemoryMB || int64(request.Config.RootVolumeGiB)*1024 < request.PoolDiskMB {
		return Instance{}, errors.New("EC2 worker capacity is below one pool job")
	}
	market := types.MarketTypeSpot
	var marketOptions *types.InstanceMarketOptionsRequest
	if request.Market == "spot" {
		marketOptions = &types.InstanceMarketOptionsRequest{
			MarketType: market,
			SpotOptions: &types.SpotMarketOptions{
				InstanceInterruptionBehavior: types.InstanceInterruptionBehaviorTerminate,
				SpotInstanceType:             types.SpotInstanceTypeOneTime,
			},
		}
	} else if request.Market != "on-demand" {
		return Instance{}, errors.New("invalid EC2 purchase option")
	}
	tags := []types.Tag{
		{Key: aws.String("runner-fleet"), Value: aws.String("worker")},
		{Key: aws.String("runner-fleet-pool"), Value: aws.String(request.PoolID)},
		{Key: aws.String("runner-fleet-launch"), Value: aws.String(request.LaunchID)},
		{Key: aws.String("runner-fleet-market"), Value: aws.String(request.Market)},
	}
	input := &ec2.RunInstancesInput{
		ImageId:               aws.String(request.Config.ImageID),
		InstanceType:          types.InstanceType(request.InstanceType),
		MinCount:              aws.Int32(1),
		MaxCount:              aws.Int32(1),
		ClientToken:           aws.String(request.ClientToken),
		UserData:              aws.String(base64.StdEncoding.EncodeToString([]byte(userData))),
		SubnetId:              aws.String(request.SubnetID),
		SecurityGroupIds:      append([]string(nil), request.Config.SecurityGroupIDs...),
		InstanceMarketOptions: marketOptions,
		MetadataOptions: &types.InstanceMetadataOptionsRequest{
			HttpEndpoint:            types.InstanceMetadataEndpointStateEnabled,
			HttpTokens:              types.HttpTokensStateRequired,
			HttpPutResponseHopLimit: aws.Int32(1),
		},
		BlockDeviceMappings: []types.BlockDeviceMapping{{
			DeviceName: imageOutput.Images[0].RootDeviceName,
			Ebs: &types.EbsBlockDevice{
				DeleteOnTermination: aws.Bool(true),
				VolumeSize:          aws.Int32(int32(request.Config.RootVolumeGiB)),
				VolumeType:          types.VolumeTypeGp3,
				Encrypted:           aws.Bool(true),
			},
		}},
		TagSpecifications: []types.TagSpecification{{
			ResourceType: types.ResourceTypeInstance,
			Tags:         tags,
		}},
	}
	if request.Config.InstanceProfile != "" {
		profile := &types.IamInstanceProfileSpecification{}
		if strings.HasPrefix(request.Config.InstanceProfile, "arn:") {
			profile.Arn = aws.String(request.Config.InstanceProfile)
		} else {
			profile.Name = aws.String(request.Config.InstanceProfile)
		}
		input.IamInstanceProfile = profile
	}
	output, err := p.client.RunInstances(ctx, input)
	if err != nil {
		return Instance{}, fmt.Errorf("EC2 launch failed: %w", err)
	}
	if output == nil || len(output.Instances) != 1 || output.Instances[0].InstanceId == nil {
		return Instance{}, errors.New("EC2 launch returned no instance identity")
	}
	launched := output.Instances[0]
	state := ""
	if launched.State != nil {
		state = string(launched.State.Name)
	}
	return Instance{
		ID:           aws.ToString(launched.InstanceId),
		Type:         string(launched.InstanceType),
		Market:       request.Market,
		State:        state,
		LaunchID:     request.LaunchID,
		PrivateDNS:   aws.ToString(launched.PrivateDnsName),
		Architecture: fleetArchitecture(string(launched.Architecture)),
		CPU:          instanceCPU,
		MemoryMB:     instanceMemory,
	}, nil
}

func supportsArchitecture(info types.InstanceTypeInfo, architecture string) bool {
	if info.ProcessorInfo == nil {
		return false
	}
	want := "x86_64"
	if architecture == "arm64" {
		want = "arm64"
	} else if architecture != "amd64" {
		return false
	}
	for _, supported := range info.ProcessorInfo.SupportedArchitectures {
		if string(supported) == want {
			return true
		}
	}
	return false
}

func (p *Provider) FindByLaunchID(ctx context.Context, launchID string) ([]Instance, error) {
	if launchID == "" || len(launchID) > 64 {
		return nil, errors.New("invalid launch id")
	}
	output, err := p.client.DescribeInstances(ctx, &ec2.DescribeInstancesInput{
		Filters: []types.Filter{{
			Name:   aws.String("tag:runner-fleet-launch"),
			Values: []string{launchID},
		}},
	})
	if err != nil {
		return nil, fmt.Errorf("EC2 launch reconciliation failed: %w", err)
	}
	instances := []Instance{}
	if output == nil {
		return nil, errors.New("EC2 reconciliation returned no response")
	}
	for _, reservation := range output.Reservations {
		for _, value := range reservation.Instances {
			id := aws.ToString(value.InstanceId)
			if id == "" {
				continue
			}
			state := ""
			if value.State != nil {
				state = string(value.State.Name)
			}
			instances = append(instances, Instance{
				ID:           id,
				Type:         string(value.InstanceType),
				State:        state,
				LaunchID:     launchID,
				PrivateDNS:   aws.ToString(value.PrivateDnsName),
				Architecture: fleetArchitecture(string(value.Architecture)),
			})
		}
	}
	return instances, nil
}

func (p *Provider) FindByInstanceID(ctx context.Context, instanceID string) ([]Instance, error) {
	if !validInstanceID(instanceID) {
		return nil, errors.New("invalid EC2 instance id")
	}
	output, err := p.client.DescribeInstances(ctx, &ec2.DescribeInstancesInput{
		InstanceIds: []string{instanceID},
	})
	if err != nil {
		return nil, fmt.Errorf("EC2 instance reconciliation failed: %w", err)
	}
	if output == nil {
		return nil, errors.New("EC2 reconciliation returned no response")
	}
	instances := []Instance{}
	for _, reservation := range output.Reservations {
		for _, value := range reservation.Instances {
			id := aws.ToString(value.InstanceId)
			if id == "" {
				continue
			}
			state := ""
			if value.State != nil {
				state = string(value.State.Name)
			}
			instances = append(instances, Instance{
				ID:           id,
				Type:         string(value.InstanceType),
				State:        state,
				PrivateDNS:   aws.ToString(value.PrivateDnsName),
				Architecture: fleetArchitecture(string(value.Architecture)),
			})
		}
	}
	return instances, nil
}

func fleetArchitecture(value string) string {
	switch value {
	case "x86_64":
		return "amd64"
	case "arm64":
		return "arm64"
	default:
		return ""
	}
}

func (p *Provider) Terminate(ctx context.Context, instanceID string) error {
	if !validInstanceID(instanceID) {
		return errors.New("invalid EC2 instance id")
	}
	_, err := p.client.TerminateInstances(ctx, &ec2.TerminateInstancesInput{
		InstanceIds: []string{instanceID},
	})
	if err != nil {
		return fmt.Errorf("EC2 termination failed: %w", err)
	}
	return nil
}

func validateLaunchRequest(request LaunchRequest) error {
	if request.LaunchID == "" || len(request.LaunchID) > 64 || request.PoolID == "" || len(request.PoolID) > 64 {
		return errors.New("invalid Spot launch identity")
	}
	if request.ClientToken == "" || len(request.ClientToken) > 64 || request.BootstrapToken == "" || len(request.BootstrapToken) > 256 {
		return errors.New("invalid Spot launch token")
	}
	if request.MachineName == "" || len(request.MachineName) > 100 {
		return errors.New("invalid Spot launch name or instance type")
	}
	allowedTypes := request.Config.SpotInstanceTypes
	if request.Market == "on-demand" {
		allowedTypes = request.Config.OnDemandInstanceTypes
	}
	allowedType := false
	for _, instanceType := range allowedTypes {
		if instanceType == request.InstanceType {
			allowedType = true
			break
		}
	}
	if !allowedType {
		return errors.New("instance type is not allowed for selected purchase option")
	}
	validSubnet := false
	for _, subnet := range request.Config.SubnetIDs {
		if subnet == request.SubnetID {
			validSubnet = true
			break
		}
	}
	if !validSubnet {
		return errors.New("launch subnet is not allowed by pool configuration")
	}
	if err := capacity.ValidateSpot(request.Config); err != nil {
		return err
	}
	parsed, err := url.Parse(request.ServerURL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return errors.New("HTTPS server origin required for EC2 bootstrap")
	}
	return nil
}

func bootstrapScript(request LaunchRequest) (string, error) {
	server := shellQuote(strings.TrimRight(request.ServerURL, "/"))
	code := shellQuote(request.BootstrapToken)
	name := shellQuote(request.MachineName)
	lines := []string{
		"#!/bin/sh",
		"set -eu",
		"umask 077",
		"if ! command -v curl >/dev/null 2>&1; then command -v apt-get >/dev/null 2>&1 || { echo 'Ubuntu/Debian apt-get and curl are required' >&2; exit 1; }; apt-get update; DEBIAN_FRONTEND=noninteractive apt-get install -y curl ca-certificates; fi",
		"work=$(mktemp -d)",
		"trap 'rm -rf \"$work\"' EXIT",
		"metadata_token=$(curl -fsS --max-time 2 -X PUT -H 'X-aws-ec2-metadata-token-ttl-seconds: 60' http://169.254.169.254/latest/api/token)",
		"cloud_instance_id=$(curl -fsS --max-time 2 -H \"X-aws-ec2-metadata-token: $metadata_token\" http://169.254.169.254/latest/meta-data/instance-id)",
		"printf '%s' " + code + " > \"$work/code\"",
		"curl -fsS --proto '=https' " + shellQuote(strings.TrimRight(request.ServerURL, "/")+"/downloads/install.sh") + " -o \"$work/install.sh\"",
		"RF_SERVER=" + server + " RF_CODE_FILE=\"$work/code\" RF_NAME=" + name + " RF_CLOUD_INSTANCE_ID=\"$cloud_instance_id\" sh \"$work/install.sh\"",
	}
	if request.Config.ImageMode == "bootstrap" {
		lines = append(lines,
			"curl -fsS --proto '=https' "+shellQuote(strings.TrimRight(request.ServerURL, "/")+"/downloads/setup-rootless-docker.sh")+" -o \"$work/rootless.sh\"",
			"sh \"$work/rootless.sh\"",
		)
	}
	script := strings.Join(lines, "\n") + "\n"
	if len(script) > 16*1024 {
		return "", errors.New("EC2 user-data exceeds the 16 KiB limit")
	}
	return script, nil
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

func validInstanceID(value string) bool {
	if !strings.HasPrefix(value, "i-") || len(value) < 10 || len(value) > 19 {
		return false
	}
	for _, char := range value[2:] {
		if char < '0' || char > '9' {
			if char < 'a' || char > 'f' {
				return false
			}
		}
	}
	return true
}
