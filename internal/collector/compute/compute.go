// Package compute collects AWS compute workloads (EC2, Lambda, ECS) and links
// them to the IAM roles they run as, so workload-identity paths can be found.
package compute

import (
	"context"
	"errors"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/smithy-go"

	"github.com/blakhound/blakhound/internal/collector"
	"github.com/blakhound/blakhound/pkg/models"
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

func structEdge(from, typ, to string, now time.Time, explanation string) models.Edge {
	return models.Edge{
		ID: collector.EdgeID(from, typ, to), FromNodeID: from, ToNodeID: to, Type: typ,
		Effect: "Allow", Confidence: models.ConfidenceDefinite,
		Properties: map[string]any{"explanation": explanation}, FirstSeenAt: now, LastSeenAt: now,
	}
}

// --- EC2 ---

type EC2Collector struct{}

func NewEC2() *EC2Collector                            { return &EC2Collector{} }
func (c *EC2Collector) Name() string                   { return "ec2" }
func (c *EC2Collector) Regions() collector.RegionScope { return collector.ScopeRegional }
func (c *EC2Collector) RequiredPermissions() []string  { return []string{"ec2:DescribeInstances"} }

func (c *EC2Collector) Collect(ctx context.Context, t collector.Target) (*collector.CollectionResult, error) {
	now := time.Now().UTC()
	res := &collector.CollectionResult{}
	for _, region := range regions(t) {
		client := ec2.NewFromConfig(t.AWSConfig, func(o *ec2.Options) { o.Region = region })
		p := ec2.NewDescribeInstancesPaginator(client, &ec2.DescribeInstancesInput{})
		for p.HasMorePages() {
			page, err := p.NextPage(ctx)
			if err != nil {
				res.Warnings = append(res.Warnings, warn("ec2", "DescribeInstances", region, err,
					"EC2 instances could not be described; workload-identity paths may be missing."))
				break
			}
			res.APIRequests++
			for _, r := range page.Reservations {
				for _, inst := range r.Instances {
					id := aws.ToString(inst.InstanceId)
					arn := "arn:aws:ec2:" + region + ":" + t.AccountID + ":instance/" + id
					props := map[string]any{"state": string(inst.State.Name)}
					if inst.PublicIpAddress != nil {
						props["public_ip"] = aws.ToString(inst.PublicIpAddress)
					}
					res.Nodes = append(res.Nodes, models.Node{ID: arn, Type: models.NodeEC2Instance, Provider: "aws",
						AccountID: t.AccountID, Region: region, ARN: arn, Name: id, FirstSeenAt: now, LastSeenAt: now, Properties: props})
					if inst.IamInstanceProfile != nil {
						ipArn := aws.ToString(inst.IamInstanceProfile.Arn)
						res.Edges = append(res.Edges, structEdge(arn, models.EdgeHasInstanceProfile, ipArn, now,
							"EC2 instance "+id+" has instance profile"))
					}
				}
			}
		}
	}
	return res, nil
}

// --- Lambda ---

type LambdaCollector struct{}

func NewLambda() *LambdaCollector                         { return &LambdaCollector{} }
func (c *LambdaCollector) Name() string                   { return "lambda" }
func (c *LambdaCollector) Regions() collector.RegionScope { return collector.ScopeRegional }
func (c *LambdaCollector) RequiredPermissions() []string {
	return []string{"lambda:ListFunctions", "lambda:GetPolicy"}
}

func (c *LambdaCollector) Collect(ctx context.Context, t collector.Target) (*collector.CollectionResult, error) {
	now := time.Now().UTC()
	res := &collector.CollectionResult{}
	for _, region := range regions(t) {
		client := lambda.NewFromConfig(t.AWSConfig, func(o *lambda.Options) { o.Region = region })
		p := lambda.NewListFunctionsPaginator(client, &lambda.ListFunctionsInput{})
		for p.HasMorePages() {
			page, err := p.NextPage(ctx)
			if err != nil {
				res.Warnings = append(res.Warnings, warn("lambda", "ListFunctions", region, err,
					"Lambda functions could not be listed; workload-identity paths may be missing."))
				break
			}
			res.APIRequests++
			for _, fn := range page.Functions {
				arn := aws.ToString(fn.FunctionArn)
				name := aws.ToString(fn.FunctionName)
				res.Nodes = append(res.Nodes, models.Node{ID: arn, Type: models.NodeLambdaFunction, Provider: "aws",
					AccountID: t.AccountID, Region: region, ARN: arn, Name: name, FirstSeenAt: now, LastSeenAt: now})
				if role := aws.ToString(fn.Role); role != "" {
					res.Edges = append(res.Edges, structEdge(arn, models.EdgeRunsAs, role, now,
						"Lambda function "+name+" executes as its execution role"))
				}
				// Resource policy (may be absent).
				pol, err := client.GetPolicy(ctx, &lambda.GetPolicyInput{FunctionName: fn.FunctionArn})
				if err == nil && pol.Policy != nil {
					res.APIRequests++
					n, e, ev := collector.ResourcePolicyEdges(arn, arn, t.AccountID, "lambda", "GetPolicy", "lambda-policy", aws.ToString(pol.Policy), now)
					res.Nodes = append(res.Nodes, n...)
					res.Edges = append(res.Edges, e...)
					res.Evidence = append(res.Evidence, ev...)
				}
			}
		}
	}
	return res, nil
}

// --- ECS ---

type ECSCollector struct{}

func NewECS() *ECSCollector                            { return &ECSCollector{} }
func (c *ECSCollector) Name() string                   { return "ecs" }
func (c *ECSCollector) Regions() collector.RegionScope { return collector.ScopeRegional }
func (c *ECSCollector) RequiredPermissions() []string {
	return []string{"ecs:ListTaskDefinitions", "ecs:DescribeTaskDefinition"}
}

func (c *ECSCollector) Collect(ctx context.Context, t collector.Target) (*collector.CollectionResult, error) {
	now := time.Now().UTC()
	res := &collector.CollectionResult{}
	for _, region := range regions(t) {
		client := ecs.NewFromConfig(t.AWSConfig, func(o *ecs.Options) { o.Region = region })
		p := ecs.NewListTaskDefinitionsPaginator(client, &ecs.ListTaskDefinitionsInput{})
		for p.HasMorePages() {
			page, err := p.NextPage(ctx)
			if err != nil {
				res.Warnings = append(res.Warnings, warn("ecs", "ListTaskDefinitions", region, err,
					"ECS task definitions could not be listed; workload-identity paths may be missing."))
				break
			}
			res.APIRequests++
			for _, arn := range page.TaskDefinitionArns {
				out, err := client.DescribeTaskDefinition(ctx, &ecs.DescribeTaskDefinitionInput{TaskDefinition: aws.String(arn)})
				if err != nil || out.TaskDefinition == nil {
					continue
				}
				res.APIRequests++
				td := out.TaskDefinition
				family := aws.ToString(td.Family)
				res.Nodes = append(res.Nodes, models.Node{ID: arn, Type: models.NodeECSTaskDefinition, Provider: "aws",
					AccountID: t.AccountID, Region: region, ARN: arn, Name: family, FirstSeenAt: now, LastSeenAt: now})
				if role := aws.ToString(td.TaskRoleArn); role != "" {
					res.Edges = append(res.Edges, structEdge(arn, models.EdgeRunsAs, role, now,
						"ECS task definition "+family+" runs as its task role"))
				}
				if role := aws.ToString(td.ExecutionRoleArn); role != "" {
					res.Edges = append(res.Edges, structEdge(arn, models.EdgeRunsAs, role, now,
						"ECS task definition "+family+" uses its execution role"))
				}
			}
		}
	}
	return res, nil
}
