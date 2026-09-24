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

func TestFailOnLevels(t *testing.T) {
	const demo = "./internal/analyzer/testdata/examples/demo" // one high finding, downgraded to low as example code
	for _, tc := range []struct {
		args []string
		want int
	}{
		{[]string{"scan", demo}, 0},
		{[]string{"scan", "--fail-on", "medium", demo}, 0},
		{[]string{"scan", "--fail-on", "low", demo}, 1},
		{[]string{"scan", "--fail-on", "info", demo}, 1},
		{[]string{"scan", "--include-examples", demo}, 1},
		{[]string{"scan", "--include-examples", "--fail-on", "critical", demo}, 0},
		{[]string{"scan", "--include-examples", "--fail-on", "none", demo}, 0},
		{[]string{"scan", "--fail-on", "review", demo}, 2},
		{[]string{"scan", "--fail-on", "HIGH", demo}, 2},
	} {
		var out, stderr bytes.Buffer
		if code := run(tc.args, &out, &stderr, "../.."); code != tc.want {
			t.Errorf("run(%v) exit %d, want %d: %s", tc.args, code, tc.want, stderr.String())
		}
	}
}

func TestSummaryLine(t *testing.T) {
	var out, stderr bytes.Buffer
	if code := run([]string{"scan", "--format", "json", "."}, &out, &stderr, "../.."); code != 1 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	want := "gnark-safety: 1 finding(s) [1 high] in 1 file(s); scanned 1 package(s), 1 importing gnark; _test.go files excluded — fails (--fail-on high)\n"
	if stderr.String() != want {
		t.Fatalf("summary\n got %q\nwant %q", stderr.String(), want)
	}
	stderr.Reset()
	if code := run([]string{"scan", "./internal/analyzer/testdata/examples/demo"}, &out, &stderr, "../.."); code != 0 || !strings.Contains(stderr.String(), "1 downgraded as example code") || !strings.Contains(stderr.String(), "— passes (--fail-on high)") {
		t.Fatalf("exit %d, summary %q", code, stderr.String())
	}
}

func TestEmptyScanIsNotAPass(t *testing.T) {
	const noGnark = "./cmd/gnark-hint-scan/testdata/nohint"
	var out, stderr bytes.Buffer
	if code := run([]string{"scan", noGnark}, &out, &stderr, "../.."); code != 2 || out.Len() != 0 || !strings.Contains(stderr.String(), "--allow-empty") {
		t.Fatalf("exit %d, stdout %q, stderr %q", code, out.String(), stderr.String())
	}
	stderr.Reset()
	if code := run([]string{"scan", "--allow-empty", noGnark}, &out, &stderr, "../.."); code != 0 || !strings.Contains(stderr.String(), "0 importing gnark") {
		t.Fatalf("--allow-empty exit %d, stderr %q", code, stderr.String())
	}
}

func TestIncludeTestsFlag(t *testing.T) {
	const pattern = "./internal/analyzer/testdata/testonly"
	var out, stderr bytes.Buffer
	if code := run([]string{"scan", pattern}, &out, &stderr, "../.."); code != 0 {
		t.Fatalf("default exit %d: %s", code, stderr.String())
	}
	if code := run([]string{"scan", "--include-tests", pattern}, &out, &stderr, "../.."); code != 1 {
		t.Fatalf("--include-tests exit %d: %s", code, stderr.String())
	}
}

func TestSuppressedFindingsDoNotGate(t *testing.T) {
	var out, stderr bytes.Buffer
	// Five findings stay active in the fixture, so the gate still fails; the
	// three suppressed ones are counted and the malformed directives warned.
	if code := run([]string{"scan", "--format", "json", "./internal/analyzer/testdata/suppress"}, &out, &stderr, "../.."); code != 1 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	var doc report.Report
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Findings) != 5 || len(doc.Suppressed) != 3 {
		t.Fatalf("findings=%d suppressed=%d", len(doc.Findings), len(doc.Suppressed))
	}
	log := stderr.String()
	if !strings.Contains(log, "5 finding(s) [5 high]") || !strings.Contains(log, "; 3 suppressed;") || !strings.Contains(log, "gnark-safety: warning: internal/analyzer/testdata/suppress/suppress.go:") {
		t.Fatalf("unexpected stderr:\n%s", log)
	}
}
