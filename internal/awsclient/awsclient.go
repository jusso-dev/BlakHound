// Package awsclient builds read-only AWS SDK v2 configuration from the standard
// credential provider chain. It never persists credentials.
package awsclient

import (
	"context"
	"fmt"
	"sort"

	"github.com/aws/aws-sdk-go-v2/aws"
	awscfg "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	bhconfig "github.com/jusso-dev/BlakHound/internal/config"
)

// Load builds an aws.Config honouring profile, region, and optional AssumeRole.
// It uses the standard provider chain: env, shared credentials, config profiles,
// SSO, and workload credentials.
func Load(ctx context.Context, cfg *bhconfig.Config) (aws.Config, error) {
	opts := []func(*awscfg.LoadOptions) error{}
	if cfg.Profile != "" {
		opts = append(opts, awscfg.WithSharedConfigProfile(cfg.Profile))
	}
	region := cfg.Region
	if region == "" && len(cfg.Regions) > 0 {
		region = cfg.Regions[0]
	}
	if region != "" {
		opts = append(opts, awscfg.WithRegion(region))
	}
	awsCfg, err := awscfg.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return aws.Config{}, fmt.Errorf("load aws config: %w", err)
	}
	if cfg.RoleARN != "" {
		base := sts.NewFromConfig(awsCfg)
		provider := stscreds.NewAssumeRoleProvider(base, cfg.RoleARN, func(o *stscreds.AssumeRoleOptions) {
			o.RoleSessionName = "blakhound"
			if cfg.ExternalID != "" {
				o.ExternalID = aws.String(cfg.ExternalID)
			}
		})
		awsCfg.Credentials = aws.NewCredentialsCache(provider)
	}
	return awsCfg, nil
}

// EnabledRegions lists regions available to the account, including regions
// enabled by default and regions the account explicitly opted into.
func EnabledRegions(ctx context.Context, awsCfg aws.Config) ([]string, error) {
	if awsCfg.Region == "" {
		awsCfg.Region = "us-east-1"
	}
	client := ec2.NewFromConfig(awsCfg)
	out, err := client.DescribeRegions(ctx, &ec2.DescribeRegionsInput{AllRegions: aws.Bool(true)})
	if err != nil {
		return nil, fmt.Errorf("ec2 describe-regions: %w", err)
	}
	return enabledRegionNames(out.Regions), nil
}

func enabledRegionNames(input []ec2types.Region) []string {
	regions := make([]string, 0, len(input))
	for _, region := range input {
		status := aws.ToString(region.OptInStatus)
		if status != "opt-in-not-required" && status != "opted-in" {
			continue
		}
		if name := aws.ToString(region.RegionName); name != "" {
			regions = append(regions, name)
		}
	}
	sort.Strings(regions)
	return regions
}

// Identity is the resolved caller identity.
type Identity struct {
	Account string `json:"account"`
	ARN     string `json:"arn"`
	UserID  string `json:"user_id"`
}

// WhoAmI resolves the current caller via STS GetCallerIdentity.
func WhoAmI(ctx context.Context, awsCfg aws.Config) (Identity, error) {
	client := sts.NewFromConfig(awsCfg)
	out, err := client.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return Identity{}, fmt.Errorf("sts get-caller-identity: %w", err)
	}
	return Identity{
		Account: aws.ToString(out.Account),
		ARN:     aws.ToString(out.Arn),
		UserID:  aws.ToString(out.UserId),
	}, nil
}
