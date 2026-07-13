package analysis

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jusso-dev/BlakHound/internal/graph"
	"github.com/jusso-dev/BlakHound/pkg/models"
)

var exposableTypes = []string{
	models.NodeEC2Instance, models.NodeLoadBalancer, models.NodeRDSInstance,
}

// DeriveNetworkExposure emits reachable-from edges only when the resource has
// a public addressing signal, a world-open resource port, and a public subnet.
// A known network ACL must also allow the port for definite confidence; missing
// ACL data is retained as possible so permission gaps remain visible.
func DeriveNetworkExposure(ctx context.Context, store *graph.Store, snapshotID, accountID string) (int, error) {
	now := time.Now().UTC()
	openSGs, err := internetOpenSecurityGroups(ctx, store)
	if err != nil {
		return 0, err
	}

	var nodes []models.Node
	var edges []models.Edge
	internetSeen := false
	for _, typ := range exposableTypes {
		resources, err := store.NodesByType(ctx, typ)
		if err != nil {
			return 0, err
		}
		for _, resource := range resources {
			reason, exposed := exposureReason(resource)
			if !exposed {
				continue
			}
			ports, err := resourceOpenPorts(ctx, store, resource, openSGs)
			if err != nil {
				return 0, err
			}
			if ports == "" {
				continue
			}
			reachablePorts, confidence, pathReason, err := routedPorts(ctx, store, resource.ID, ports)
			if err != nil {
				return 0, err
			}
			if reachablePorts == "" {
				continue
			}

			explanation := fmt.Sprintf("%s is reachable from the internet: %s; accepts %s; %s",
				resource.Name, reason, reachablePorts, pathReason)
			if !internetSeen {
				nodes = append(nodes, models.Node{ID: models.NodeInternet, Type: models.NodeInternet, Provider: "aws",
					Name: "Internet (0.0.0.0/0 and ::/0)", Properties: map[string]any{"derived": true},
					FirstSeenAt: now, LastSeenAt: now})
				internetSeen = true
			}
			edge := derivedEdge(models.NodeInternet, models.EdgeReachableFrom, resource.ID, confidence, explanation, now)
			edge.Properties["ports"] = reachablePorts
			edges = append(edges, edge)
		}
	}

	if len(edges) == 0 {
		return 0, nil
	}
	if err := store.Import(ctx, snapshotID, nodes, edges, nil); err != nil {
		return 0, err
	}
	return len(edges), nil
}

func exposureReason(resource models.Node) (string, bool) {
	switch resource.Type {
	case models.NodeEC2Instance:
		if ip, _ := resource.Properties["public_ip"].(string); ip != "" {
			return "instance has public IP " + ip, true
		}
	case models.NodeLoadBalancer:
		if internetFacing, _ := resource.Properties["internet_facing"].(bool); internetFacing {
			return "load balancer scheme is internet-facing", true
		}
	case models.NodeRDSInstance:
		if public, _ := resource.Properties["publicly_accessible"].(bool); public {
			return "instance is publicly accessible", true
		}
	}
	return "", false
}

func internetOpenSecurityGroups(ctx context.Context, store *graph.Store) (map[string]string, error) {
	out := map[string]string{}
	edges, err := store.OutEdges(ctx, models.NodeInternet, []string{models.EdgeAllowsIngress})
	if err != nil {
		return nil, err
	}
	for _, edge := range edges {
		ports, _ := edge.Properties["ports"].(string)
		out[edge.ToNodeID] = ports
	}
	return out, nil
}

func resourceOpenPorts(ctx context.Context, store *graph.Store, resource models.Node, openSGs map[string]string) (string, error) {
	attached, err := store.OutEdges(ctx, resource.ID, []string{models.EdgeAttachedTo})
	if err != nil {
		return "", err
	}
	var sgPorts []string
	securityGroupCount := 0
	for _, edge := range attached {
		if strings.Contains(edge.ToNodeID, ":security-group/") {
			securityGroupCount++
		}
		node, err := store.GetNode(ctx, edge.ToNodeID)
		if err != nil {
			return "", err
		}
		if node == nil || node.Type != models.NodeSecurityGroup {
			continue
		}
		if ports := openSGs[node.ID]; ports != "" {
			sgPorts = append(sgPorts, ports)
		}
	}
	worldOpen := unionPortSummaries(sgPorts...)

	switch resource.Type {
	case models.NodeEC2Instance:
		return worldOpen, nil
	case models.NodeRDSInstance:
		port := intProperty(resource.Properties, "port")
		if port <= 0 || worldOpen == "" {
			return "", nil
		}
		return intersectPortSummaries(fmt.Sprintf("tcp/%d", port), worldOpen), nil
	case models.NodeLoadBalancer:
		listeners, _ := resource.Properties["listener_ports"].(string)
		if listeners == "" {
			return "", nil
		}
		if securityGroupCount > 0 {
			return intersectPortSummaries(listeners, worldOpen), nil
		}
		lbType, _ := resource.Properties["type"].(string)
		if lbType == "network" {
			return normalizePortSummary(listeners), nil
		}
	}
	return "", nil
}

func routedPorts(ctx context.Context, store *graph.Store, resourceID, ports string) (string, string, string, error) {
	edges, err := store.OutEdges(ctx, resourceID, []string{models.EdgeDeployedIn})
	if err != nil {
		return "", "", "", err
	}
	var definite, possible []string
	for _, edge := range edges {
		subnet, err := store.GetNode(ctx, edge.ToNodeID)
		if err != nil {
			return "", "", "", err
		}
		if subnet == nil || subnet.Type != models.NodeSubnet || !boolProperty(subnet.Properties, "public") {
			continue
		}
		aclEdges, err := store.OutEdges(ctx, subnet.ID, []string{models.EdgeAttachedTo})
		if err != nil {
			return "", "", "", err
		}
		aclSeen := false
		for _, aclEdge := range aclEdges {
			acl, err := store.GetNode(ctx, aclEdge.ToNodeID)
			if err != nil {
				return "", "", "", err
			}
			if acl == nil || acl.Type != models.NodeNetworkACL {
				continue
			}
			aclSeen = true
			aclPorts, _ := acl.Properties["open_ingress_ports"].(string)
			reachable := intersectPortSummaries(ports, aclPorts)
			if reachable == "" {
				continue
			}
			egressPorts, egressKnown := acl.Properties["open_egress_ports"].(string)
			if !egressKnown {
				possible = append(possible, reachable)
				continue
			}
			if aclAllowsResponseTraffic(reachable, egressPorts) {
				definite = append(definite, reachable)
			}
		}
		if !aclSeen {
			possible = append(possible, ports)
		}
	}
	if result := unionPortSummaries(definite...); result != "" {
		return result, models.ConfidenceDefinite, "a public subnet route and network ACL allow the traffic", nil
	}
	if result := unionPortSummaries(possible...); result != "" {
		return result, models.ConfidencePossible, "a public subnet route exists but network ACL data is unavailable", nil
	}
	return "", "", "", nil
}

func aclAllowsResponseTraffic(inbound, egress string) bool {
	egressRanges := parsePortSummary(egress)
	if len(egressRanges) == 0 {
		return false
	}
	for _, incoming := range parsePortSummary(inbound) {
		requiredProtocol := incoming.protocol
		covered := false
		for _, outgoing := range egressRanges {
			if outgoing.protocol != "*" && requiredProtocol != "*" && outgoing.protocol != requiredProtocol {
				continue
			}
			if outgoing.from <= 1024 && outgoing.to >= 65535 {
				covered = true
				break
			}
		}
		if !covered {
			return false
		}
	}
	return true
}

func boolProperty(properties map[string]any, key string) bool {
	value, _ := properties[key].(bool)
	return value
}

func intProperty(properties map[string]any, key string) int {
	switch value := properties[key].(type) {
	case int:
		return value
	case int32:
		return int(value)
	case int64:
		return int(value)
	case float64:
		return int(value)
	}
	return 0
}

type networkPortRange struct {
	protocol string
	from     int
	to       int
}

func parsePortSummary(summary string) []networkPortRange {
	var out []networkPortRange
	for _, raw := range strings.Split(summary, ",") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		if raw == "all traffic" {
			out = append(out, networkPortRange{protocol: "*", from: 0, to: 65535})
			continue
		}
		parts := strings.SplitN(raw, "/", 2)
		if len(parts) != 2 {
			continue
		}
		protocol := strings.ToLower(parts[0])
		if parts[1] == "all" {
			out = append(out, networkPortRange{protocol: protocol, from: 0, to: 65535})
			continue
		}
		bounds := strings.SplitN(parts[1], "-", 2)
		from, err := strconv.Atoi(bounds[0])
		if err != nil {
			continue
		}
		to := from
		if len(bounds) == 2 {
			to, err = strconv.Atoi(bounds[1])
			if err != nil {
				continue
			}
		}
		out = append(out, networkPortRange{protocol: protocol, from: from, to: to})
	}
	return out
}

func intersectPortSummaries(left, right string) string {
	var out []networkPortRange
	for _, a := range parsePortSummary(left) {
		for _, b := range parsePortSummary(right) {
			if a.protocol != b.protocol && a.protocol != "*" && b.protocol != "*" {
				continue
			}
			from, to := max(a.from, b.from), min(a.to, b.to)
			if from > to {
				continue
			}
			protocol := a.protocol
			if protocol == "*" {
				protocol = b.protocol
			}
			out = append(out, networkPortRange{protocol: protocol, from: from, to: to})
		}
	}
	return formatPortRanges(out)
}

func unionPortSummaries(summaries ...string) string {
	var ranges []networkPortRange
	for _, summary := range summaries {
		ranges = append(ranges, parsePortSummary(summary)...)
	}
	return formatPortRanges(ranges)
}

func normalizePortSummary(summary string) string { return formatPortRanges(parsePortSummary(summary)) }

func formatPortRanges(ranges []networkPortRange) string {
	seen := map[string]bool{}
	var out []string
	for _, port := range ranges {
		value := "all traffic"
		if port.protocol != "*" {
			value = fmt.Sprintf("%s/%d", port.protocol, port.from)
			if port.from == 0 && port.to == 65535 {
				value = port.protocol + "/all"
			} else if port.from != port.to {
				value = fmt.Sprintf("%s/%d-%d", port.protocol, port.from, port.to)
			}
		}
		if !seen[value] {
			seen[value] = true
			out = append(out, value)
		}
	}
	sort.Strings(out)
	return strings.Join(out, ", ")
}
