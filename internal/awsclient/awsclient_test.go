package awsclient

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

func TestEnabledRegionNames(t *testing.T) {
	input := []ec2types.Region{
		{RegionName: aws.String("us-west-2"), OptInStatus: aws.String("opt-in-not-required")},
		{RegionName: aws.String("ap-southeast-2"), OptInStatus: aws.String("opted-in")},
		{RegionName: aws.String("af-south-1"), OptInStatus: aws.String("not-opted-in")},
	}
	got := enabledRegionNames(input)
	if len(got) != 2 || got[0] != "ap-southeast-2" || got[1] != "us-west-2" {
		t.Fatalf("unexpected enabled regions: %v", got)
	}
}
