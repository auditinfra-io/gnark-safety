package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/auditinfra-io/gnark-safety/pkg/report"
)

func TestJSONAndExitPolicy(t *testing.T) {
	var out, stderr bytes.Buffer
	code := run([]string{"scan", "--format", "json", "--include-examples", "./examples/divmod"}, &out, &stderr, "../..")
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
	if code := run([]string{"scan", "--fail-on", "none", "--include-examples", "./examples/divmod"}, &out, &stderr, "../.."); code != 0 {
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
	if code := run([]string{"scan", "--format", "sarif", "--fail-on", "none", "./examples/divmod"}, &out, &stderr, "../.."); code != 0 {
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
		{"scan", "--timeout=0", "./examples/divmod"},
		{"scan", "--max-hints=0", "./examples/divmod"},
		{"scan", "--max-output-bytes=0", "./examples/divmod"},
		{"scan", "--field=no-such-field", "./examples/divmod"},
	} {
		var out, stderr bytes.Buffer
		if code := run(args, &out, &stderr, "../.."); code != 2 {
			t.Fatalf("run(%v) exit=%d, want 2", args, code)
		}
	}

	var out, stderr bytes.Buffer
	code := run([]string{"scan", "--format=json", "--max-output-bytes=1", "./examples/divmod"}, &out, &stderr, "../..")
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
	if code := run([]string{"scan", "--format", "json", "--include-examples", "./examples/divmod"}, &out, &stderr, "../.."); code != 1 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	want := "gnark-safety: 1 finding(s) [1 high] in 1 file(s); scanned 1 package(s), 1 importing gnark; 1 hint call(s), 1 in the quotient/remainder shape; _test.go files excluded — fails (--fail-on high)\n"
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

// TestPartialScanIsNotAPass: packages that load are analyzed and reported,
// but a scan that skipped a package exits 2 unless --allow-partial is given,
// and findings at the gate still exit 1.
func TestPartialScanIsNotAPass(t *testing.T) {
	const good, broken = "./internal/analyzer/testdata/partial/good", "./internal/analyzer/testdata/partial/broken"
	var out, stderr bytes.Buffer
	code := run([]string{"scan", "--format", "json", "--fail-on", "none", good, broken}, &out, &stderr, "../..")
	if code != 2 || !strings.Contains(stderr.String(), "--allow-partial") || !strings.Contains(stderr.String(), "warning: package") || !strings.Contains(stderr.String(), "1 package(s) skipped") || !strings.Contains(stderr.String(), "— incomplete (") {
		t.Fatalf("exit %d, stderr %q", code, stderr.String())
	}
	var r report.Report
	if err := json.Unmarshal(out.Bytes(), &r); err != nil || len(r.Findings) != 1 || len(r.Coverage.Skipped) != 1 {
		t.Fatalf("the partial report was not written: %v %s", err, out.String())
	}
	if !strings.Contains(strings.Join(r.Limitations, "\n"), "Partial scan: 1 requested package(s)") {
		t.Fatalf("the JSON report must say it is partial: %q", r.Limitations)
	}
	// A text report saved with --output carries the partial-scan notice too,
	// not only the stderr summary.
	saved := filepath.Join(t.TempDir(), "report.txt")
	if code := run([]string{"scan", "--fail-on", "none", "--output", saved, good, broken}, &out, &stderr, "../.."); code != 2 {
		t.Fatalf("text exit %d", code)
	}
	if content, err := os.ReadFile(saved); err != nil || !strings.Contains(string(content), "Partial scan: 1 requested package(s) failed to load and were not analyzed: ") {
		t.Fatalf("saved text report does not say it is partial: %q %v", content, err)
	}
	out.Reset()
	stderr.Reset()
	if code := run([]string{"scan", "--fail-on", "none", "--allow-partial", good, broken}, &out, &stderr, "../.."); code != 0 {
		t.Fatalf("--allow-partial exit %d, stderr %q", code, stderr.String())
	}
	if code := run([]string{"scan", good, broken}, &out, &stderr, "../.."); code != 1 {
		t.Fatalf("a finding at the gate must exit 1 even when the scan is partial: exit %d", code)
	}
	if code := run([]string{"scan", "--allow-partial", broken}, &out, &stderr, "../.."); code != 2 {
		t.Fatalf("a scan in which nothing loads must exit 2: exit %d", code)
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

// TestSelfScanPassesDefaultGate is a Phase 1 exit criterion: scanning this
// repository reports the demo's deliberate bug only as downgraded example
// code, so the default gate passes.
func TestSelfScanPassesDefaultGate(t *testing.T) {
	var out, stderr bytes.Buffer
	if code := run([]string{"scan", "./..."}, &out, &stderr, "../.."); code != 0 {
		t.Fatalf("self-scan exit %d:\n%s%s", code, out.String(), stderr.String())
	}
	if !strings.Contains(out.String(), "examples/divmod/circuits.go:44:26: low [GNARK_HINT_RELATION_INCOMPLETE]") || !strings.Contains(stderr.String(), "1 downgraded as example code") {
		t.Fatalf("unexpected self-scan:\n%s%s", out.String(), stderr.String())
	}
}

func TestInventory(t *testing.T) {
	var out, stderr bytes.Buffer
	if code := run([]string{"inventory", "./examples/divmod"}, &out, &stderr, "../.."); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	want := "examples/divmod/circuits.go:20:35: github.com/auditinfra-io/gnark-safety/examples/divmod: constrainDivision (hint=github.com/auditinfra-io/gnark-safety/examples/divmod.QuotientRemainderHint, outputs=2, inputs=2)\nInventory only: constraint completeness and circuit soundness were not analyzed.\n"
	if out.String() != want {
		t.Fatalf("inventory text\n got %q\nwant %q", out.String(), want)
	}
	out.Reset()
	if code := run([]string{"inventory", "--format", "json", "./examples/divmod"}, &out, &stderr, "../.."); code != 0 {
		t.Fatalf("json exit %d: %s", code, stderr.String())
	}
	var doc map[string]any
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if _, hasFindings := doc["findings"]; hasFindings || doc["schema_version"] != "2.0" || len(doc["hints"].([]any)) != 1 {
		t.Fatalf("unexpected inventory JSON: %s", out.String())
	}
	for _, args := range [][]string{{"inventory"}, {"inventory", "--format", "sarif", "./examples/divmod"}, {"inventory", "./does-not-exist"}} {
		if code := run(args, &out, &stderr, "../.."); code != 2 {
			t.Errorf("run(%v) exit %d, want 2", args, code)
		}
	}
}

func TestSARIFOutputSidecar(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.sarif")
	var out, stderr bytes.Buffer
	if code := run([]string{"scan", "--include-examples", "--sarif-output", path, "./examples/divmod"}, &out, &stderr, "../.."); code != 1 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	if !strings.Contains(out.String(), "examples/divmod/circuits.go:44:26: high") {
		t.Fatalf("primary text output missing: %s", out.String())
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Runs []struct {
			Results []struct {
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct{ URI string } `json:"artifactLocation"`
					} `json:"physicalLocation"`
				} `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(content, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Runs[0].Results) != 1 || doc.Runs[0].Results[0].Locations[0].PhysicalLocation.ArtifactLocation.URI != "examples/divmod/circuits.go" {
		t.Fatalf("unexpected SARIF: %s", content)
	}
	// An operational failure writes no SARIF, so a stale file cannot be uploaded as a result.
	missing := filepath.Join(t.TempDir(), "never.sarif")
	if code := run([]string{"scan", "--sarif-output", missing, "./cmd/gnark-hint-scan/testdata/nohint"}, &out, &stderr, "../.."); code != 2 {
		t.Fatalf("empty scan exit %d", code)
	}
	if _, err := os.Stat(missing); !os.IsNotExist(err) {
		t.Fatalf("SARIF written for a failed scan: %v", err)
	}
}

func TestRelativeTo(t *testing.T) {
	var out, stderr bytes.Buffer
	if code := run([]string{"scan", "--relative-to", "examples", "--fail-on", "none", "./examples/divmod"}, &out, &stderr, "../.."); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	if !strings.HasPrefix(out.String(), "divmod/circuits.go:44:26: high") {
		t.Fatalf("paths not relative to --relative-to: %s", out.String())
	}
}
