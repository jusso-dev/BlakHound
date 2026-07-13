package storage

import (
	"strings"
	"time"

	sqstypes "github.com/aws/aws-sdk-go-v2/service/sqs/types"

	"github.com/jusso-dev/BlakHound/internal/collector"
	"github.com/jusso-dev/BlakHound/pkg/models"
)

func structEdge(from, typ, to string, now time.Time, explanation string) models.Edge {
	return models.Edge{
		ID: collector.EdgeID(from, typ, to), FromNodeID: from, ToNodeID: to, Type: typ,
		Effect: "Allow", Confidence: models.ConfidenceDefinite,
		Properties: map[string]any{"explanation": explanation}, FirstSeenAt: now, LastSeenAt: now,
	}
}

func sqsAttrNames() []sqstypes.QueueAttributeName {
	return []sqstypes.QueueAttributeName{sqstypes.QueueAttributeNameQueueArn, sqstypes.QueueAttributeNamePolicy}
}

func queueName(url string) string {
	if i := strings.LastIndex(url, "/"); i >= 0 {
		return url[i+1:]
	}
	return url
}

func topicName(arn string) string {
	if i := strings.LastIndex(arn, ":"); i >= 0 {
		return arn[i+1:]
	}
	return arn
}

// kmsKeyARN normalises a KMS key reference to a full ARN when possible. It
// returns "" for alias-only references that cannot be resolved offline.
func kmsKeyARN(ref, region, account string) string {
	if ref == "" {
		return ""
	}
	if strings.HasPrefix(ref, "arn:") {
		return ref
	}
	if strings.HasPrefix(ref, "alias/") {
		return "" // aliases are not resolved during collection
	}
	if region == "" || account == "" {
		return ""
	}
	return "arn:aws:kms:" + region + ":" + account + ":key/" + ref
}
