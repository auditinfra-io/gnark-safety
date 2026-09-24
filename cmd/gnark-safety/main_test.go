package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/auditinfra-io/gnark-safety/pkg/report"
)

func TestJSONAndExitPolicy(t *testing.T) {
	var out, stderr bytes.Buffer
	code := run([]string{"scan", "--format", "json", "."}, &out, &stderr, "../..")
	if code != 1 {
		t.Fatalf("exit %d, want 1: %s", code, stderr.String())
	}
	var doc map[string]any
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if doc["schema_version"] != "2.0" {
		t.Fatalf("unexpected report: %s", out.String())
	}
	out.Reset()
	stderr.Reset()
	if code := run([]string{"scan", "--fail-on", "none", "."}, &out, &stderr, "../.."); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
}

func TestHighThresholdIgnoresLowerFindings(t *testing.T) {
	if hasFindingAtOrAbove(report.Report{Findings: []report.Finding{{Severity: report.SeverityMedium}}}, report.SeverityHigh) {
		t.Fatal("medium-only report crossed high threshold")
	}
	for _, severity := range []report.Severity{report.SeverityHigh, report.SeverityCritical} {
		if !hasFindingAtOrAbove(report.Report{Findings: []report.Finding{{Severity: severity}}}, report.SeverityHigh) {
			t.Fatalf("%s finding did not cross high threshold", severity)
		}
	}
}

func TestSARIF(t *testing.T) {
	var out, stderr bytes.Buffer
	if code := run([]string{"scan", "--format", "sarif", "--fail-on", "none", "."}, &out, &stderr, "../.."); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	if !strings.Contains(out.String(), `"version": "2.1.0"`) || !strings.Contains(out.String(), "GNARK_HINT_RELATION_INCOMPLETE") {
		t.Fatalf("unexpected SARIF: %s", out.String())
	}
}

func TestExplain(t *testing.T) {
	var out, stderr bytes.Buffer
	if code := run([]string{"explain", "GNARK_HINT_RELATION_INCOMPLETE"}, &out, &stderr, "."); code != 0 || !strings.Contains(out.String(), "Incomplete hint relation") {
		t.Fatalf("exit %d: %s%s", code, out.String(), stderr.String())
	}
	out.Reset()
	if code := run([]string{"explain"}, &out, &stderr, "."); code != 0 || !strings.Contains(out.String(), "GNARK_HINT_OUTPUT_UNUSED") {
		t.Fatalf("rule listing exit %d: %s", code, out.String())
	}
	if code := run([]string{"explain", "NO_SUCH_RULE"}, &out, &stderr, "."); code != 2 {
		t.Fatalf("unknown rule exit %d, want 2", code)
	}
}

func TestVersion(t *testing.T) {
	for _, arg := range []string{"version", "--version"} {
		var out, stderr bytes.Buffer
		if code := run([]string{arg}, &out, &stderr, "."); code != 0 || !strings.HasPrefix(out.String(), "gnark-safety ") {
			t.Fatalf("%s: exit %d, output %q", arg, code, out.String())
		}
	}
}

func TestResourceLimitValidationAndOutputLimit(t *testing.T) {
	for _, args := range [][]string{
		{"scan", "--timeout=0", "."},
		{"scan", "--max-hints=0", "."},
		{"scan", "--max-output-bytes=0", "."},
		{"scan", "--field=no-such-field", "."},
	} {
		var out, stderr bytes.Buffer
		if code := run(args, &out, &stderr, "../.."); code != 2 {
			t.Fatalf("run(%v) exit=%d, want 2", args, code)
		}
	}

	var out, stderr bytes.Buffer
	code := run([]string{"scan", "--format=json", "--max-output-bytes=1", "."}, &out, &stderr, "../..")
	if code != 2 || !strings.Contains(stderr.String(), "output limit exceeded") || out.Len() != 0 {
		t.Fatalf("unexpected limited output: exit=%d stdout=%q stderr=%q", code, out.String(), stderr.String())
	}
}
