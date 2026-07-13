// Package storage collects AWS storage and data resources (Secrets Manager,
// KMS, SQS, SNS, S3) and their resource-based policies. Secret and SecureString
// VALUES are never retrieved.
package storage

import (
	"context"
	"errors"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/smithy-go"

	"github.com/jusso-dev/BlakHound/internal/collector"
	"github.com/jusso-dev/BlakHound/pkg/models"
)

func warn(service, api, region string, err error, impact string) collector.Warning {
	w := collector.Warning{Service: service, API: api, Region: region, Message: err.Error(), Impact: impact}
	var ae smithy.APIError
	if errors.As(err, &ae) {
		w.Code = ae.ErrorCode()
		w.Message = ae.ErrorMessage()
	}
	return w
}

func regions(t collector.Target) []string {
	if len(t.Regions) > 0 {
		return t.Regions
	}
	if t.AWSConfig.Region != "" {
		return []string{t.AWSConfig.Region}
	}
	return nil
}

// --- Secrets Manager ---

// SecretsCollector collects Secrets Manager secrets (metadata + resource policy).
type SecretsCollector struct{}

func NewSecrets() *SecretsCollector                        { return &SecretsCollector{} }
func (c *SecretsCollector) Name() string                   { return "secretsmanager" }
func (c *SecretsCollector) Regions() collector.RegionScope { return collector.ScopeRegional }
func (c *SecretsCollector) RequiredPermissions() []string {
	return []string{"secretsmanager:ListSecrets", "secretsmanager:GetResourcePolicy"}
}

func (c *SecretsCollector) Collect(ctx context.Context, t collector.Target) (*collector.CollectionResult, error) {
	now := time.Now().UTC()
	res := &collector.CollectionResult{}
	for _, region := range regions(t) {
		client := secretsmanager.NewFromConfig(t.AWSConfig, func(o *secretsmanager.Options) { o.Region = region })
		p := secretsmanager.NewListSecretsPaginator(client, &secretsmanager.ListSecretsInput{})
		for p.HasMorePages() {
			page, err := p.NextPage(ctx)
			if err != nil {
				res.Warnings = append(res.Warnings, warn("secretsmanager", "ListSecrets", region, err,
					"Secrets could not be listed; secret-access paths may be missing."))
				break
			}
			res.APIRequests++
			for _, s := range page.SecretList {
				arn := aws.ToString(s.ARN)
				node := models.Node{ID: arn, Type: models.NodeSecret, Provider: "aws", AccountID: t.AccountID,
					Region: region, ARN: arn, Name: aws.ToString(s.Name), FirstSeenAt: now, LastSeenAt: now,
					Properties: map[string]any{}}
				if s.KmsKeyId != nil {
					node.Properties["kms_key_id"] = aws.ToString(s.KmsKeyId)
				}
				res.Nodes = append(res.Nodes, node)
				// encrypted-by edge if a CMK ARN is known.
				if keyARN := kmsKeyARN(aws.ToString(s.KmsKeyId), region, t.AccountID); keyARN != "" {
					res.Edges = append(res.Edges, structEdge(arn, models.EdgeEncryptedBy, keyARN, now,
						"Secret "+aws.ToString(s.Name)+" is encrypted by KMS key"))
				}
				// Resource policy (best effort).
				rp, err := client.GetResourcePolicy(ctx, &secretsmanager.GetResourcePolicyInput{SecretId: s.ARN})
				if err != nil {
					continue
				}
				res.APIRequests++
				if doc := aws.ToString(rp.ResourcePolicy); doc != "" {
					n, e, ev := collector.ResourcePolicyEdges(arn, arn, t.AccountID, "secretsmanager", "GetResourcePolicy", "secret-policy", doc, now)
					res.Nodes = append(res.Nodes, n...)
					res.Edges = append(res.Edges, e...)
					res.Evidence = append(res.Evidence, ev...)
				}
			}
		}
	}
	return res, nil
}

// --- KMS ---

type KMSCollector struct{}

func NewKMS() *KMSCollector                            { return &KMSCollector{} }
func (c *KMSCollector) Name() string                   { return "kms" }
func (c *KMSCollector) Regions() collector.RegionScope { return collector.ScopeRegional }
func (c *KMSCollector) RequiredPermissions() []string {
	return []string{"kms:ListKeys", "kms:DescribeKey", "kms:GetKeyPolicy"}
}

func (c *KMSCollector) Collect(ctx context.Context, t collector.Target) (*collector.CollectionResult, error) {
	now := time.Now().UTC()
	res := &collector.CollectionResult{}
	for _, region := range regions(t) {
		client := kms.NewFromConfig(t.AWSConfig, func(o *kms.Options) { o.Region = region })
		p := kms.NewListKeysPaginator(client, &kms.ListKeysInput{})
		for p.HasMorePages() {
			page, err := p.NextPage(ctx)
			if err != nil {
				res.Warnings = append(res.Warnings, warn("kms", "ListKeys", region, err,
					"KMS keys could not be listed; decrypt paths may be missing."))
				break
			}
			res.APIRequests++
			for _, k := range page.Keys {
				keyID := aws.ToString(k.KeyId)
				arn := aws.ToString(k.KeyArn)
				desc, err := client.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: k.KeyId})
				if err != nil {
					continue
				}
				res.APIRequests++
				manager := string(desc.KeyMetadata.KeyManager)
				res.Nodes = append(res.Nodes, models.Node{ID: arn, Type: models.NodeKMSKey, Provider: "aws",
					AccountID: t.AccountID, Region: region, ARN: arn, Name: keyID, FirstSeenAt: now, LastSeenAt: now,
					Properties: map[string]any{"key_manager": manager}})
				// AWS-managed keys have fixed policies; still record but skip policy fetch noise.
				pol, err := client.GetKeyPolicy(ctx, &kms.GetKeyPolicyInput{KeyId: k.KeyId, PolicyName: aws.String("default")})
				if err != nil {
					continue
				}
				res.APIRequests++
				if doc := aws.ToString(pol.Policy); doc != "" {
					n, e, ev := collector.ResourcePolicyEdges(arn, arn, t.AccountID, "kms", "GetKeyPolicy", "kms-key-policy", doc, now)
					res.Nodes = append(res.Nodes, n...)
					res.Edges = append(res.Edges, e...)
					res.Evidence = append(res.Evidence, ev...)
				}
			}
		}
	}
	return res, nil
}

// --- SQS ---

type SQSCollector struct{}

func NewSQS() *SQSCollector                            { return &SQSCollector{} }
func (c *SQSCollector) Name() string                   { return "sqs" }
func (c *SQSCollector) Regions() collector.RegionScope { return collector.ScopeRegional }
func (c *SQSCollector) RequiredPermissions() []string {
	return []string{"sqs:ListQueues", "sqs:GetQueueAttributes"}
}

func (c *SQSCollector) Collect(ctx context.Context, t collector.Target) (*collector.CollectionResult, error) {
	now := time.Now().UTC()
	res := &collector.CollectionResult{}
	for _, region := range regions(t) {
		client := sqs.NewFromConfig(t.AWSConfig, func(o *sqs.Options) { o.Region = region })
		p := sqs.NewListQueuesPaginator(client, &sqs.ListQueuesInput{})
		for p.HasMorePages() {
			page, err := p.NextPage(ctx)
			if err != nil {
				res.Warnings = append(res.Warnings, warn("sqs", "ListQueues", region, err, "SQS queues could not be listed."))
				break
			}
			res.APIRequests++
			for _, url := range page.QueueUrls {
				attr, err := client.GetQueueAttributes(ctx, &sqs.GetQueueAttributesInput{
					QueueUrl: aws.String(url), AttributeNames: sqsAttrNames()})
				if err != nil {
					continue
				}
				res.APIRequests++
				arn := attr.Attributes["QueueArn"]
				if arn == "" {
					continue
				}
				res.Nodes = append(res.Nodes, models.Node{ID: arn, Type: models.NodeSQSQueue, Provider: "aws",
					AccountID: t.AccountID, Region: region, ARN: arn, Name: queueName(url), FirstSeenAt: now, LastSeenAt: now})
				if doc := attr.Attributes["Policy"]; doc != "" {
					n, e, ev := collector.ResourcePolicyEdges(arn, arn, t.AccountID, "sqs", "GetQueueAttributes", "sqs-policy", doc, now)
					res.Nodes = append(res.Nodes, n...)
					res.Edges = append(res.Edges, e...)
					res.Evidence = append(res.Evidence, ev...)
				}
			}
		}
	}
	return res, nil
}

// --- SNS ---

type SNSCollector struct{}

func NewSNS() *SNSCollector                            { return &SNSCollector{} }
func (c *SNSCollector) Name() string                   { return "sns" }
func (c *SNSCollector) Regions() collector.RegionScope { return collector.ScopeRegional }
func (c *SNSCollector) RequiredPermissions() []string {
	return []string{"sns:ListTopics", "sns:GetTopicAttributes"}
}

func (c *SNSCollector) Collect(ctx context.Context, t collector.Target) (*collector.CollectionResult, error) {
	now := time.Now().UTC()
	res := &collector.CollectionResult{}
	for _, region := range regions(t) {
		client := sns.NewFromConfig(t.AWSConfig, func(o *sns.Options) { o.Region = region })
		p := sns.NewListTopicsPaginator(client, &sns.ListTopicsInput{})
		for p.HasMorePages() {
			page, err := p.NextPage(ctx)
			if err != nil {
				res.Warnings = append(res.Warnings, warn("sns", "ListTopics", region, err, "SNS topics could not be listed."))
				break
			}
			res.APIRequests++
			for _, tp := range page.Topics {
				arn := aws.ToString(tp.TopicArn)
				attr, err := client.GetTopicAttributes(ctx, &sns.GetTopicAttributesInput{TopicArn: tp.TopicArn})
				if err != nil {
					continue
				}
				res.APIRequests++
				res.Nodes = append(res.Nodes, models.Node{ID: arn, Type: models.NodeSNSTopic, Provider: "aws",
					AccountID: t.AccountID, Region: region, ARN: arn, Name: topicName(arn), FirstSeenAt: now, LastSeenAt: now})
				if doc := attr.Attributes["Policy"]; doc != "" {
					n, e, ev := collector.ResourcePolicyEdges(arn, arn, t.AccountID, "sns", "GetTopicAttributes", "sns-policy", doc, now)
					res.Nodes = append(res.Nodes, n...)
					res.Edges = append(res.Edges, e...)
					res.Evidence = append(res.Evidence, ev...)
				}
			}
		}
	}
	return res, nil
}
