package network

import (
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	elbtypes "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"
	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"

	"github.com/jusso-dev/BlakHound/internal/collector"
	"github.com/jusso-dev/BlakHound/pkg/models"
)

func TestOpenIngressPortsIPv4AndIPv6(t *testing.T) {
	permissions := []ec2types.IpPermission{
		{IpProtocol: aws.String("tcp"), FromPort: aws.Int32(443), ToPort: aws.Int32(443),
			IpRanges: []ec2types.IpRange{{CidrIp: aws.String("0.0.0.0/0")}}},
		{IpProtocol: aws.String("udp"), FromPort: aws.Int32(53), ToPort: aws.Int32(53),
			Ipv6Ranges: []ec2types.Ipv6Range{{CidrIpv6: aws.String("::/0")}}},
	}
	if got := openIngressPorts(permissions); got != "tcp/443, udp/53" {
		t.Fatalf("unexpected ingress ports %q", got)
	}
}

func TestOpenACLIngressPortsHonoursEarlierWorldDeny(t *testing.T) {
	allowThenDefaultDeny := []ec2types.NetworkAclEntry{
		{RuleNumber: aws.Int32(100), Protocol: aws.String("6"), RuleAction: ec2types.RuleActionAllow,
			CidrBlock: aws.String("0.0.0.0/0"), PortRange: &ec2types.PortRange{From: aws.Int32(443), To: aws.Int32(443)}},
		{RuleNumber: aws.Int32(32767), Protocol: aws.String("-1"), RuleAction: ec2types.RuleActionDeny,
			CidrBlock: aws.String("0.0.0.0/0")},
	}
	if got := openACLIngressPorts(allowThenDefaultDeny); got != "tcp/443" {
		t.Fatalf("expected tcp/443, got %q", got)
	}
	earlierDeny := append([]ec2types.NetworkAclEntry{{RuleNumber: aws.Int32(50), Protocol: aws.String("-1"),
		RuleAction: ec2types.RuleActionDeny, CidrBlock: aws.String("0.0.0.0/0")}}, allowThenDefaultDeny...)
	if got := openACLIngressPorts(earlierDeny); got != "" {
		t.Fatalf("expected earlier deny to block later allow, got %q", got)
	}
	partialDeny := []ec2types.NetworkAclEntry{
		{RuleNumber: aws.Int32(50), Protocol: aws.String("6"), RuleAction: ec2types.RuleActionDeny,
			CidrBlock: aws.String("0.0.0.0/0"), PortRange: &ec2types.PortRange{From: aws.Int32(22), To: aws.Int32(22)}},
		{RuleNumber: aws.Int32(100), Protocol: aws.String("6"), RuleAction: ec2types.RuleActionAllow,
			CidrBlock: aws.String("0.0.0.0/0"), PortRange: &ec2types.PortRange{From: aws.Int32(0), To: aws.Int32(65535)}},
	}
	if got := openACLIngressPorts(partialDeny); got != "tcp/0-21, tcp/23-65535" {
		t.Fatalf("expected partial deny to be subtracted, got %q", got)
	}
}

func TestOpenACLEgressPorts(t *testing.T) {
	entries := []ec2types.NetworkAclEntry{
		{Egress: aws.Bool(true), RuleNumber: aws.Int32(100), Protocol: aws.String("6"), RuleAction: ec2types.RuleActionAllow,
			CidrBlock: aws.String("0.0.0.0/0"), PortRange: &ec2types.PortRange{From: aws.Int32(1024), To: aws.Int32(65535)}},
		{Egress: aws.Bool(true), RuleNumber: aws.Int32(32767), Protocol: aws.String("-1"), RuleAction: ec2types.RuleActionDeny,
			CidrBlock: aws.String("0.0.0.0/0")},
	}
	if got := openACLEgressPorts(entries); got != "tcp/1024-65535" {
		t.Fatalf("unexpected egress ports %q", got)
	}
}

func TestRoutesToInternet(t *testing.T) {
	routes := []ec2types.Route{{DestinationCidrBlock: aws.String("0.0.0.0/0"), GatewayId: aws.String("igw-123")}}
	if got := routesToInternet(routes); got != "igw-123" {
		t.Fatalf("expected igw-123, got %q", got)
	}
	routes[0].GatewayId = aws.String("nat-123")
	if got := routesToInternet(routes); got != "" {
		t.Fatalf("NAT route must not be treated as public ingress, got %q", got)
	}
}

func TestAddLoadBalancerRecordsSecurityGroupsAndSubnets(t *testing.T) {
	res := &collector.CollectionResult{}
	target := collector.Target{AccountID: "111111111111"}
	lb := elbtypes.LoadBalancer{
		LoadBalancerArn:  aws.String("arn:aws:elasticloadbalancing:ap-southeast-2:111111111111:loadbalancer/app/web/abc"),
		LoadBalancerName: aws.String("web"), Scheme: elbtypes.LoadBalancerSchemeEnumInternetFacing,
		Type: elbtypes.LoadBalancerTypeEnumApplication, VpcId: aws.String("vpc-1"),
		SecurityGroups: []string{"sg-1"}, AvailabilityZones: []elbtypes.AvailabilityZone{{SubnetId: aws.String("subnet-1")}},
	}
	NewELB().addLoadBalancer(lb, "ap-southeast-2", target, res, time.Now().UTC())
	if len(res.Nodes) != 1 || !res.Nodes[0].Properties["internet_facing"].(bool) {
		t.Fatalf("unexpected load balancer node: %+v", res.Nodes)
	}
	if len(res.Edges) != 3 {
		t.Fatalf("expected VPC, SG and subnet edges, got %+v", res.Edges)
	}
	if got := listenerPortSpecs("TCP_UDP", 53); len(got) != 2 || got[0] != "tcp/53" || got[1] != "udp/53" {
		t.Fatalf("unexpected listener specs: %v", got)
	}
}

func TestAddDBInstanceRecordsEndpointPortAndSubnets(t *testing.T) {
	res := &collector.CollectionResult{}
	target := collector.Target{AccountID: "111111111111"}
	db := rdstypes.DBInstance{
		DBInstanceArn:        aws.String("arn:aws:rds:ap-southeast-2:111111111111:db:prod"),
		DBInstanceIdentifier: aws.String("prod"), PubliclyAccessible: aws.Bool(true), Engine: aws.String("postgres"),
		Endpoint: &rdstypes.Endpoint{Address: aws.String("prod.example"), Port: aws.Int32(5432)},
		DBSubnetGroup: &rdstypes.DBSubnetGroup{VpcId: aws.String("vpc-1"),
			Subnets: []rdstypes.Subnet{{SubnetIdentifier: aws.String("subnet-1")}, {SubnetIdentifier: aws.String("subnet-2")}}},
		VpcSecurityGroups: []rdstypes.VpcSecurityGroupMembership{{VpcSecurityGroupId: aws.String("sg-1")}},
	}
	NewRDS().addDBInstance(db, "ap-southeast-2", target, res, time.Now().UTC())
	if len(res.Nodes) != 1 || res.Nodes[0].Properties["port"] != int32(5432) {
		t.Fatalf("RDS endpoint port not recorded: %+v", res.Nodes)
	}
	if len(res.Edges) != 4 {
		t.Fatalf("expected VPC, two subnet and SG edges, got %+v", res.Edges)
	}
	for _, edge := range res.Edges {
		if edge.Type != models.EdgeDeployedIn && edge.Type != models.EdgeAttachedTo {
			t.Fatalf("unexpected edge type %s", edge.Type)
		}
	}
}
