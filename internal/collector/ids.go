package collector

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/jusso-dev/BlakHound/internal/evidence"
	"github.com/jusso-dev/BlakHound/pkg/models"
)

// AccountNodeID returns the deterministic node id for an AWS account.
func AccountNodeID(accountID string) string { return "aws-account:" + accountID }

// ExternalAccountNodeID returns the node id for an external account.
func ExternalAccountNodeID(accountID string) string { return "external-account:" + accountID }

// ServicePrincipalNodeID returns the node id for an AWS service principal.
func ServicePrincipalNodeID(service string) string { return "service:" + service }

// InlinePolicyNodeID returns the node id for an inline policy on an owner.
func InlinePolicyNodeID(ownerARN, name string) string {
	return "inline:" + ownerARN + "#" + name
}

// EvidenceID returns a stable id derived from its parts.
func EvidenceID(parts ...string) string {
	h := sha1.New()
	for _, p := range parts {
		h.Write([]byte(p))
		h.Write([]byte{0})
	}
	return "ev-" + hex.EncodeToString(h.Sum(nil))[:16]
}

// EdgeID returns a stable id for an edge given its endpoints and type.
func EdgeID(from, typ, to string) string {
	h := sha1.New()
	fmt.Fprintf(h, "%s|%s|%s", from, typ, to)
	return "edge-" + hex.EncodeToString(h.Sum(nil))[:16]
}

// NewEvidence builds a redacted evidence record.
func NewEvidence(service, api, resource, docType, document, explanation string, stmtIdx *int, now time.Time) models.Evidence {
	red := evidence.Redact(document)
	id := EvidenceID(service, api, resource, docType, explanation)
	return models.Evidence{
		ID:             id,
		SourceService:  service,
		SourceAPI:      api,
		SourceResource: resource,
		DocumentType:   docType,
		Document:       []byte(red),
		StatementIndex: stmtIdx,
		Explanation:    explanation,
		CollectedAt:    now.UTC(),
	}
}
