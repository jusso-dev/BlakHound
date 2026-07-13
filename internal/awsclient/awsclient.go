// Package awsclient builds read-only AWS SDK v2 configuration from the standard
// credential provider chain. It never persists credentials.
package awsclient

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	awscfg "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
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
