package evidence

import (
	"strings"
	"testing"
)

func TestRedactSecretsAndKeys(t *testing.T) {
	in := `{"password":"hunter2","note":"ok","AccessKey":"AKIAIOSFODNN7EXAMPLE"}`
	out := Redact(in)
	if strings.Contains(out, "hunter2") {
		t.Fatalf("password not redacted: %s", out)
	}
	if strings.Contains(out, "AKIAIOSFODNN7EXAMPLE") {
		t.Fatalf("access key id not redacted: %s", out)
	}
	if !strings.Contains(out, "ok") {
		t.Fatalf("non-secret value should be preserved: %s", out)
	}
	if !strings.Contains(out, Redacted) {
		t.Fatalf("expected redaction marker: %s", out)
	}
}
