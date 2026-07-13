// Package network collects AWS network resources (VPCs, subnets, route tables,
// security groups, gateways, load balancers, RDS instances) and the structural
// edges between them. It records the signals — public IPs, internet-facing
// schemes, publicly-accessible flags and 0.0.0.0/0 security-group rules — that
// the analysis layer turns into internet-exposure paths. It never mutates AWS.
package network

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	elb "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	elbtypes "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"
	"github.com/aws/aws-sdk-go-v2/service/rds"
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

func structEdge(from, typ, to string, now time.Time, explanation string) models.Edge {
	return models.Edge{
		ID: collector.EdgeID(from, typ, to), FromNodeID: from, ToNodeID: to, Type: typ,
		Effect: "Allow", Confidence: models.ConfidenceDefinite,
		Properties: map[string]any{"explanation": explanation}, FirstSeenAt: now, LastSeenAt: now,
	}
}

// ec2ARN builds an EC2 resource ARN (subnet/vpc/security-group/... share this shape).
func ec2ARN(region, account, resource, id string) string {
	return "arn:aws:ec2:" + region + ":" + account + ":" + resource + "/" + id
}

// internetNode returns the shared synthetic internet node.
func internetNode(now time.Time) models.Node {
	return models.Node{ID: models.NodeInternet, Type: models.NodeInternet, Provider: "aws",
		Name: "Internet (0.0.0.0/0)", FirstSeenAt: now, LastSeenAt: now}
}

// --- VPC / EC2 network topology ---

// VPCCollector collects VPCs, subnets, route tables, gateways, security groups
// and the ENIs that attach instances to security groups.
type VPCCollector struct{}

func NewVPC() *VPCCollector                            { return &VPCCollector{} }
func (c *VPCCollector) Name() string                   { return "vpc" }
func (c *VPCCollector) Regions() collector.RegionScope { return collector.ScopeRegional }
func (c *VPCCollector) RequiredPermissions() []string {
	return []string{
		"ec2:DescribeVpcs", "ec2:DescribeSubnets", "ec2:DescribeRouteTables",
		"ec2:DescribeInternetGateways", "ec2:DescribeNatGateways",
		"ec2:DescribeSecurityGroups", "ec2:DescribeNetworkInterfaces",
	}
}

func (c *VPCCollector) Collect(ctx context.Context, t collector.Target) (*collector.CollectionResult, error) {
	now := time.Now().UTC()
	res := &collector.CollectionResult{}
	for _, region := range regions(t) {
		client := ec2.NewFromConfig(t.AWSConfig, func(o *ec2.Options) { o.Region = region })
		c.collectVPCs(ctx, client, region, t, res, now)
		c.collectGateways(ctx, client, region, t, res, now)
		publicSubnets := c.collectRouteTables(ctx, client, region, t, res, now)
		c.collectSubnets(ctx, client, region, t, res, now, publicSubnets)
		c.collectSecurityGroups(ctx, client, region, t, res, now)
		c.collectENIs(ctx, client, region, t, res, now)
	}
	return res, nil
}

func (c *VPCCollector) collectVPCs(ctx context.Context, client *ec2.Client, region string, t collector.Target, res *collector.CollectionResult, now time.Time) {
	p := ec2.NewDescribeVpcsPaginator(client, &ec2.DescribeVpcsInput{})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			res.Warnings = append(res.Warnings, warn("ec2", "DescribeVpcs", region, err,
				"VPCs could not be described; network topology may be incomplete."))
			return
		}
		res.APIRequests++
		for _, v := range page.Vpcs {
			id := aws.ToString(v.VpcId)
			arn := ec2ARN(region, t.AccountID, "vpc", id)
			props := map[string]any{"cidr": aws.ToString(v.CidrBlock), "default": aws.ToBool(v.IsDefault)}
			res.Nodes = append(res.Nodes, models.Node{ID: arn, Type: models.NodeVPC, Provider: "aws",
				AccountID: t.AccountID, Region: region, ARN: arn, Name: id, FirstSeenAt: now, LastSeenAt: now, Properties: props})
		}
	}
}

func (c *VPCCollector) collectGateways(ctx context.Context, client *ec2.Client, region string, t collector.Target, res *collector.CollectionResult, now time.Time) {
	igw, err := client.DescribeInternetGateways(ctx, &ec2.DescribeInternetGatewaysInput{})
	if err != nil {
		res.Warnings = append(res.Warnings, warn("ec2", "DescribeInternetGateways", region, err,
			"Internet gateways could not be described; public-subnet detection may be incomplete."))
	} else {
		res.APIRequests++
		for _, g := range igw.InternetGateways {
			id := aws.ToString(g.InternetGatewayId)
			arn := ec2ARN(region, t.AccountID, "internet-gateway", id)
			res.Nodes = append(res.Nodes, models.Node{ID: arn, Type: models.NodeInternetGateway, Provider: "aws",
				AccountID: t.AccountID, Region: region, ARN: arn, Name: id, FirstSeenAt: now, LastSeenAt: now})
			for _, a := range g.Attachments {
				if vpc := aws.ToString(a.VpcId); vpc != "" {
					res.Edges = append(res.Edges, structEdge(arn, models.EdgeAttachedTo, ec2ARN(region, t.AccountID, "vpc", vpc), now,
						"Internet gateway "+id+" is attached to VPC "+vpc))
				}
			}
		}
	}
	nat, err := client.DescribeNatGateways(ctx, &ec2.DescribeNatGatewaysInput{})
	if err != nil {
		res.Warnings = append(res.Warnings, warn("ec2", "DescribeNatGateways", region, err,
			"NAT gateways could not be described; egress topology may be incomplete."))
		return
	}
	res.APIRequests++
	for _, g := range nat.NatGateways {
		id := aws.ToString(g.NatGatewayId)
		arn := ec2ARN(region, t.AccountID, "natgateway", id)
		res.Nodes = append(res.Nodes, models.Node{ID: arn, Type: models.NodeNATGateway, Provider: "aws",
			AccountID: t.AccountID, Region: region, ARN: arn, Name: id, FirstSeenAt: now, LastSeenAt: now})
	}
}

// collectRouteTables records route tables and returns the set of subnet ids that
// are public (their associated route table has a default route to an IGW).
func (c *VPCCollector) collectRouteTables(ctx context.Context, client *ec2.Client, region string, t collector.Target, res *collector.CollectionResult, now time.Time) map[string]bool {
	public := map[string]bool{}
	p := ec2.NewDescribeRouteTablesPaginator(client, &ec2.DescribeRouteTablesInput{})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			res.Warnings = append(res.Warnings, warn("ec2", "DescribeRouteTables", region, err,
				"Route tables could not be described; public-subnet detection may be incomplete."))
			return public
		}
		res.APIRequests++
		for _, rt := range page.RouteTables {
			id := aws.ToString(rt.RouteTableId)
			arn := ec2ARN(region, t.AccountID, "route-table", id)
			toInternet := routesToInternet(rt.Routes)
			res.Nodes = append(res.Nodes, models.Node{ID: arn, Type: models.NodeRouteTable, Provider: "aws",
				AccountID: t.AccountID, Region: region, ARN: arn, Name: id, FirstSeenAt: now, LastSeenAt: now,
				Properties: map[string]any{"internet_route": toInternet}})
			if toInternet != "" {
				res.Edges = append(res.Edges, structEdge(arn, models.EdgeRoutesTo, ec2ARN(region, t.AccountID, "internet-gateway", toInternet), now,
					"Route table "+id+" sends 0.0.0.0/0 to internet gateway "+toInternet))
			}
			for _, assoc := range rt.Associations {
				if sub := aws.ToString(assoc.SubnetId); sub != "" && toInternet != "" {
					public[sub] = true
				}
			}
		}
	}
	return public
}

// routesToInternet returns the IGW id if the routes include a default route to
// an internet gateway, otherwise "".
func routesToInternet(routes []ec2types.Route) string {
	for _, r := range routes {
		dst := aws.ToString(r.DestinationCidrBlock)
		if dst != "0.0.0.0/0" && aws.ToString(r.DestinationIpv6CidrBlock) != "::/0" {
			continue
		}
		if gw := aws.ToString(r.GatewayId); len(gw) > 4 && gw[:4] == "igw-" {
			return gw
		}
	}
	return ""
}

func (c *VPCCollector) collectSubnets(ctx context.Context, client *ec2.Client, region string, t collector.Target, res *collector.CollectionResult, now time.Time, public map[string]bool) {
	p := ec2.NewDescribeSubnetsPaginator(client, &ec2.DescribeSubnetsInput{})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			res.Warnings = append(res.Warnings, warn("ec2", "DescribeSubnets", region, err,
				"Subnets could not be described; network topology may be incomplete."))
			return
		}
		res.APIRequests++
		for _, sn := range page.Subnets {
			id := aws.ToString(sn.SubnetId)
			arn := aws.ToString(sn.SubnetArn)
			if arn == "" {
				arn = ec2ARN(region, t.AccountID, "subnet", id)
			}
			isPublic := public[id] || aws.ToBool(sn.MapPublicIpOnLaunch)
			res.Nodes = append(res.Nodes, models.Node{ID: arn, Type: models.NodeSubnet, Provider: "aws",
				AccountID: t.AccountID, Region: region, ARN: arn, Name: id, FirstSeenAt: now, LastSeenAt: now,
				Properties: map[string]any{"cidr": aws.ToString(sn.CidrBlock), "public": isPublic}})
			if vpc := aws.ToString(sn.VpcId); vpc != "" {
				res.Edges = append(res.Edges, structEdge(arn, models.EdgeDeployedIn, ec2ARN(region, t.AccountID, "vpc", vpc), now,
					"Subnet "+id+" is in VPC "+vpc))
			}
		}
	}
}

func (c *VPCCollector) collectSecurityGroups(ctx context.Context, client *ec2.Client, region string, t collector.Target, res *collector.CollectionResult, now time.Time) {
	internetAdded := false
	p := ec2.NewDescribeSecurityGroupsPaginator(client, &ec2.DescribeSecurityGroupsInput{})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			res.Warnings = append(res.Warnings, warn("ec2", "DescribeSecurityGroups", region, err,
				"Security groups could not be described; internet-exposure paths may be missing."))
			return
		}
		res.APIRequests++
		for _, sg := range page.SecurityGroups {
			id := aws.ToString(sg.GroupId)
			arn := ec2ARN(region, t.AccountID, "security-group", id)
			ports := openIngressPorts(sg.IpPermissions)
			res.Nodes = append(res.Nodes, models.Node{ID: arn, Type: models.NodeSecurityGroup, Provider: "aws",
				AccountID: t.AccountID, Region: region, ARN: arn, Name: aws.ToString(sg.GroupName), FirstSeenAt: now, LastSeenAt: now,
				Properties: map[string]any{"group_id": id, "vpc": aws.ToString(sg.VpcId), "open_ingress_ports": ports}})
			if vpc := aws.ToString(sg.VpcId); vpc != "" {
				res.Edges = append(res.Edges, structEdge(arn, models.EdgeDeployedIn, ec2ARN(region, t.AccountID, "vpc", vpc), now,
					"Security group "+id+" is in VPC "+vpc))
			}
			if ports != "" {
				if !internetAdded {
					res.Nodes = append(res.Nodes, internetNode(now))
					internetAdded = true
				}
				e := structEdge(models.NodeInternet, models.EdgeAllowsIngress, arn, now,
					"Security group "+id+" allows inbound "+ports+" from 0.0.0.0/0")
				e.Properties["ports"] = ports
				res.Edges = append(res.Edges, e)
			}
		}
	}
}

// openIngressPorts returns a human port summary if any ingress permission is open
// to 0.0.0.0/0 or ::/0, otherwise "".
func openIngressPorts(perms []ec2types.IpPermission) string {
	var out string
	for _, perm := range perms {
		open := false
		for _, r := range perm.IpRanges {
			if aws.ToString(r.CidrIp) == "0.0.0.0/0" {
				open = true
			}
		}
		for _, r := range perm.Ipv6Ranges {
			if aws.ToString(r.CidrIpv6) == "::/0" {
				open = true
			}
		}
		if !open {
			continue
		}
		if out != "" {
			out += ", "
		}
		out += portRange(perm)
	}
	return out
}

func portRange(perm ec2types.IpPermission) string {
	proto := aws.ToString(perm.IpProtocol)
	if proto == "-1" {
		return "all traffic"
	}
	from, to := aws.ToInt32(perm.FromPort), aws.ToInt32(perm.ToPort)
	if perm.FromPort == nil && perm.ToPort == nil {
		return proto + "/all"
	}
	if from == to {
		return fmt.Sprintf("%s/%d", proto, from)
	}
	return fmt.Sprintf("%s/%d-%d", proto, from, to)
}

// collectENIs links instances (and other attachments) to their security groups
// and records whether the interface has a public IP.
func (c *VPCCollector) collectENIs(ctx context.Context, client *ec2.Client, region string, t collector.Target, res *collector.CollectionResult, now time.Time) {
	p := ec2.NewDescribeNetworkInterfacesPaginator(client, &ec2.DescribeNetworkInterfacesInput{})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			res.Warnings = append(res.Warnings, warn("ec2", "DescribeNetworkInterfaces", region, err,
				"Network interfaces could not be described; instance-to-security-group links may be missing."))
			return
		}
		res.APIRequests++
		for _, eni := range page.NetworkInterfaces {
			if eni.Attachment == nil {
				continue
			}
			instID := aws.ToString(eni.Attachment.InstanceId)
			if instID == "" {
				continue
			}
			instARN := ec2ARN(region, t.AccountID, "instance", instID)
			publicIP := eni.Association != nil && aws.ToString(eni.Association.PublicIp) != ""
			if publicIP {
				// Record public exposure on the instance node so derivation can read it.
				res.Nodes = append(res.Nodes, models.Node{ID: instARN, Type: models.NodeEC2Instance, Provider: "aws",
					AccountID: t.AccountID, Region: region, ARN: instARN, Name: instID, FirstSeenAt: now, LastSeenAt: now,
					Properties: map[string]any{"public_ip": aws.ToString(eni.Association.PublicIp)}})
			}
			for _, g := range eni.Groups {
				sgARN := ec2ARN(region, t.AccountID, "security-group", aws.ToString(g.GroupId))
				res.Edges = append(res.Edges, structEdge(instARN, models.EdgeAttachedTo, sgARN, now,
					"Instance "+instID+" is attached to security group "+aws.ToString(g.GroupId)))
			}
		}
	}
}

// --- Elastic Load Balancing v2 ---

// ELBCollector collects application/network/gateway load balancers and target
// groups, and links load balancers to their security groups.
type ELBCollector struct{}

func NewELB() *ELBCollector                            { return &ELBCollector{} }
func (c *ELBCollector) Name() string                   { return "elbv2" }
func (c *ELBCollector) Regions() collector.RegionScope { return collector.ScopeRegional }
func (c *ELBCollector) RequiredPermissions() []string {
	return []string{"elasticloadbalancing:DescribeLoadBalancers", "elasticloadbalancing:DescribeTargetGroups"}
}

func (c *ELBCollector) Collect(ctx context.Context, t collector.Target) (*collector.CollectionResult, error) {
	now := time.Now().UTC()
	res := &collector.CollectionResult{}
	for _, region := range regions(t) {
		client := elb.NewFromConfig(t.AWSConfig, func(o *elb.Options) { o.Region = region })
		p := elb.NewDescribeLoadBalancersPaginator(client, &elb.DescribeLoadBalancersInput{})
		for p.HasMorePages() {
			page, err := p.NextPage(ctx)
			if err != nil {
				res.Warnings = append(res.Warnings, warn("elbv2", "DescribeLoadBalancers", region, err,
					"Load balancers could not be described; internet-exposure paths may be missing."))
				break
			}
			res.APIRequests++
			for _, lb := range page.LoadBalancers {
				c.addLoadBalancer(lb, region, t, res, now)
			}
		}
		c.collectTargetGroups(ctx, client, region, res, now)
	}
	return res, nil
}

func (c *ELBCollector) addLoadBalancer(lb elbtypes.LoadBalancer, region string, t collector.Target, res *collector.CollectionResult, now time.Time) {
	arn := aws.ToString(lb.LoadBalancerArn)
	name := aws.ToString(lb.LoadBalancerName)
	internetFacing := lb.Scheme == elbtypes.LoadBalancerSchemeEnumInternetFacing
	res.Nodes = append(res.Nodes, models.Node{ID: arn, Type: models.NodeLoadBalancer, Provider: "aws",
		AccountID: t.AccountID, Region: region, ARN: arn, Name: name, FirstSeenAt: now, LastSeenAt: now,
		Properties: map[string]any{"scheme": string(lb.Scheme), "internet_facing": internetFacing, "type": string(lb.Type)}})
	if vpc := aws.ToString(lb.VpcId); vpc != "" {
		res.Edges = append(res.Edges, structEdge(arn, models.EdgeDeployedIn, ec2ARN(region, t.AccountID, "vpc", vpc), now,
			"Load balancer "+name+" is in VPC "+vpc))
	}
	for _, sg := range lb.SecurityGroups {
		res.Edges = append(res.Edges, structEdge(arn, models.EdgeAttachedTo, ec2ARN(region, t.AccountID, "security-group", sg), now,
			"Load balancer "+name+" is attached to security group "+sg))
	}
}

func (c *ELBCollector) collectTargetGroups(ctx context.Context, client *elb.Client, region string, res *collector.CollectionResult, now time.Time) {
	p := elb.NewDescribeTargetGroupsPaginator(client, &elb.DescribeTargetGroupsInput{})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			res.Warnings = append(res.Warnings, warn("elbv2", "DescribeTargetGroups", region, err,
				"Target groups could not be described; load-balancer targets may be missing."))
			return
		}
		res.APIRequests++
		for _, tg := range page.TargetGroups {
			arn := aws.ToString(tg.TargetGroupArn)
			res.Nodes = append(res.Nodes, models.Node{ID: arn, Type: models.NodeTargetGroup, Provider: "aws",
				Region: region, ARN: arn, Name: aws.ToString(tg.TargetGroupName), FirstSeenAt: now, LastSeenAt: now,
				Properties: map[string]any{"port": aws.ToInt32(tg.Port), "target_type": string(tg.TargetType)}})
			for _, lbARN := range tg.LoadBalancerArns {
				res.Edges = append(res.Edges, structEdge(lbARN, models.EdgeFronts, arn, now,
					"Load balancer fronts target group "+aws.ToString(tg.TargetGroupName)))
			}
		}
	}
}

// --- RDS ---

// RDSCollector collects RDS instances, their security groups and public
// accessibility.
type RDSCollector struct{}

func NewRDS() *RDSCollector                            { return &RDSCollector{} }
func (c *RDSCollector) Name() string                   { return "rds" }
func (c *RDSCollector) Regions() collector.RegionScope { return collector.ScopeRegional }
func (c *RDSCollector) RequiredPermissions() []string {
	return []string{"rds:DescribeDBInstances"}
}

func (c *RDSCollector) Collect(ctx context.Context, t collector.Target) (*collector.CollectionResult, error) {
	now := time.Now().UTC()
	res := &collector.CollectionResult{}
	for _, region := range regions(t) {
		client := rds.NewFromConfig(t.AWSConfig, func(o *rds.Options) { o.Region = region })
		p := rds.NewDescribeDBInstancesPaginator(client, &rds.DescribeDBInstancesInput{})
		for p.HasMorePages() {
			page, err := p.NextPage(ctx)
			if err != nil {
				res.Warnings = append(res.Warnings, warn("rds", "DescribeDBInstances", region, err,
					"RDS instances could not be described; database-exposure paths may be missing."))
				break
			}
			res.APIRequests++
			for _, db := range page.DBInstances {
				arn := aws.ToString(db.DBInstanceArn)
				name := aws.ToString(db.DBInstanceIdentifier)
				public := aws.ToBool(db.PubliclyAccessible)
				props := map[string]any{"publicly_accessible": public, "engine": aws.ToString(db.Engine)}
				if db.Endpoint != nil {
					props["endpoint"] = aws.ToString(db.Endpoint.Address)
				}
				res.Nodes = append(res.Nodes, models.Node{ID: arn, Type: models.NodeRDSInstance, Provider: "aws",
					AccountID: t.AccountID, Region: region, ARN: arn, Name: name, FirstSeenAt: now, LastSeenAt: now, Properties: props})
				if db.DBSubnetGroup != nil {
					if vpc := aws.ToString(db.DBSubnetGroup.VpcId); vpc != "" {
						res.Edges = append(res.Edges, structEdge(arn, models.EdgeDeployedIn, ec2ARN(region, t.AccountID, "vpc", vpc), now,
							"RDS instance "+name+" is in VPC "+vpc))
					}
				}
				for _, sg := range db.VpcSecurityGroups {
					res.Edges = append(res.Edges, structEdge(arn, models.EdgeAttachedTo, ec2ARN(region, t.AccountID, "security-group", aws.ToString(sg.VpcSecurityGroupId)), now,
						"RDS instance "+name+" is attached to security group "+aws.ToString(sg.VpcSecurityGroupId)))
				}
			}
		}
	}
	return res, nil
}
