package analysis

import (
	"context"
	"fmt"
	"time"

	"github.com/jusso-dev/BlakHound/internal/graph"
	"github.com/jusso-dev/BlakHound/pkg/models"
)

// exposableTypes are resource types whose internet reachability we derive.
var exposableTypes = []string{
	models.NodeEC2Instance, models.NodeLoadBalancer, models.NodeRDSInstance,
}

// DeriveNetworkExposure emits `reachable-from` edges from the internet node to
// resources that are genuinely reachable from the internet: an internet-facing
// load balancer, a publicly-accessible RDS instance, or an EC2 instance with a
// public IP, in every case attached to a security group whose ingress is open
// to 0.0.0.0/0. The edge explanation names the open ports so the exposure is
// auditable. Deterministic and idempotent for a snapshot.
func DeriveNetworkExposure(ctx context.Context, store *graph.Store, snapshotID, accountID string) (int, error) {
	now := time.Now().UTC()

	// Security groups open to the internet, mapped to their open port summary.
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
		for _, r := range resources {
			reason, exposed := exposureReason(r)
			if !exposed {
				continue
			}
			ports := attachedOpenPorts(ctx, store, r.ID, openSGs)
			// EC2 instances require an open security group; an internet-facing LB or
			// a publicly-accessible RDS is reachable regardless of a 0.0.0.0/0 rule
			// (an NLB may have no security group at all).
			if r.Type == models.NodeEC2Instance && ports == "" {
				continue
			}
			expl := fmt.Sprintf("%s is reachable from the internet: %s", r.Name, reason)
			if ports != "" {
				expl += fmt.Sprintf("; security group allows inbound %s from 0.0.0.0/0", ports)
			}
			if !internetSeen {
				nodes = append(nodes, models.Node{ID: models.NodeInternet, Type: models.NodeInternet, Provider: "aws",
					Name: "Internet (0.0.0.0/0)", FirstSeenAt: now, LastSeenAt: now})
				internetSeen = true
			}
			e := derivedEdge(models.NodeInternet, models.EdgeReachableFrom, r.ID, models.ConfidenceDefinite, expl, now)
			if ports != "" {
				e.Properties["ports"] = ports
			}
			edges = append(edges, e)
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

// exposureReason reports why a resource is internet-exposed by its own flags.
func exposureReason(r models.Node) (string, bool) {
	switch r.Type {
	case models.NodeEC2Instance:
		if ip, _ := r.Properties["public_ip"].(string); ip != "" {
			return "instance has public IP " + ip, true
		}
	case models.NodeLoadBalancer:
		if b, _ := r.Properties["internet_facing"].(bool); b {
			return "load balancer scheme is internet-facing", true
		}
	case models.NodeRDSInstance:
		if b, _ := r.Properties["publicly_accessible"].(bool); b {
			return "instance is publicly accessible", true
		}
	}
	return "", false
}

// internetOpenSecurityGroups returns SG node id -> open port summary for every
// security group the internet node has an allows-ingress edge into.
func internetOpenSecurityGroups(ctx context.Context, store *graph.Store) (map[string]string, error) {
	out := map[string]string{}
	edges, err := store.OutEdges(ctx, models.NodeInternet, []string{models.EdgeAllowsIngress})
	if err != nil {
		return nil, err
	}
	for _, e := range edges {
		ports, _ := e.Properties["ports"].(string)
		out[e.ToNodeID] = ports
	}
	return out, nil
}

// attachedOpenPorts returns the combined open-port summary of the internet-open
// security groups a resource is attached to, or "" if none are open.
func attachedOpenPorts(ctx context.Context, store *graph.Store, resourceID string, openSGs map[string]string) string {
	attached, err := store.OutEdges(ctx, resourceID, []string{models.EdgeAttachedTo})
	if err != nil {
		return ""
	}
	var ports string
	for _, e := range attached {
		p, ok := openSGs[e.ToNodeID]
		if !ok {
			continue
		}
		if p == "" {
			continue
		}
		if ports != "" {
			ports += ", "
		}
		ports += p
	}
	return ports
}
