package output

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/auditinfra-io/gnark-safety/internal/rules"
	"github.com/auditinfra-io/gnark-safety/pkg/report"
)

func renderSARIF(t *testing.T, input report.Report) sarif {
	t.Helper()
	var buffer bytes.Buffer
	if err := SARIF(&buffer, input); err != nil {
		t.Fatal(err)
	}
	var result sarif
	if err := json.Unmarshal(buffer.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func TestSARIFRuleMetadataComesFromRegistry(t *testing.T) {
	input := report.Report{Tool: report.Tool{Name: "gnark-safety", Version: "v0.1.0"}, Coverage: report.Coverage{Packages: 3, GnarkPackages: 2, Files: 7, ExamplesDowngraded: 1}, Findings: []report.Finding{
		{RuleID: rules.HintOutputUnused, Severity: report.SeverityMedium, Message: "Hint output 1 is never used after extraction.", File: "a.go", Line: 1, Column: 1},
		{RuleID: rules.HintRelationIncomplete, Severity: report.SeverityHigh, Message: "per-finding text", File: "b.go", Line: 2, Column: 1},
	}}
	run := renderSARIF(t, input).Runs[0]
	if run.Tool.Driver.Version != "v0.1.0" || run.Tool.Driver.InformationURI != InformationURI {
		t.Fatalf("driver identity: %#v", run.Tool.Driver)
	}
	registered := rules.All()
	if len(run.Tool.Driver.Rules) != len(registered) {
		t.Fatalf("got %d rules, want every registered rule (%d)", len(run.Tool.Driver.Rules), len(registered))
	}
	for i, spec := range registered {
		rule := run.Tool.Driver.Rules[i]
		if rule.ID != spec.ID || rule.ShortDescription.Text != spec.Title || rule.FullDescription.Text != spec.Summary || rule.HelpURI != spec.HelpURI() {
			t.Errorf("rule %s metadata does not match the registry: %#v", spec.ID, rule)
		}
		if _, score := sarifLevel(spec.DefaultSeverity()); rule.Properties.SecuritySeverity != score {
			t.Errorf("rule %s security-severity %q, want %q", spec.ID, rule.Properties.SecuritySeverity, score)
		}
	}
	for _, result := range run.Results {
		if run.Tool.Driver.Rules[result.RuleIndex].ID != result.RuleID {
			t.Errorf("result %s points at rule index %d", result.RuleID, result.RuleIndex)
		}
	}
	if run.Results[0].Level != "warning" || run.Results[1].Level != "error" {
		t.Fatalf("unexpected SARIF levels: %#v", run.Results)
	}
	if len(run.Invocations) != 1 || !run.Invocations[0].ExecutionSuccessful || run.Invocations[0].Properties != input.Coverage {
		t.Fatalf("missing invocation: %#v", run.Invocations)
	}
}

func TestSARIFLevelsCoverEverySeverity(t *testing.T) {
	want := map[report.Severity]string{
		report.SeverityCritical: "error", report.SeverityHigh: "error", report.SeverityMedium: "warning",
		report.SeverityLow: "note", report.SeverityInfo: "note",
	}
	for _, severity := range report.Severities {
		if level, _ := sarifLevel(severity); level != want[severity] {
			t.Errorf("%s: level %q, want %q", severity, level, want[severity])
		}
	}
}

func TestSARIFUnregisteredRuleGetsEntry(t *testing.T) {
	run := renderSARIF(t, report.Report{Findings: []report.Finding{{RuleID: "THIRD_PARTY", Severity: report.SeverityLow, Message: "x", File: "c.go", Line: 3, Column: 1}}}).Runs[0]
	result := run.Results[0]
	if run.Tool.Driver.Rules[result.RuleIndex].ID != "THIRD_PARTY" || result.Level != "note" {
		t.Fatalf("unregistered rule not represented: %#v", run)
	}
	if run.Tool.Driver.Version != "devel" {
		t.Fatalf("empty tool version should render as devel, got %q", run.Tool.Driver.Version)
	}
}

func TestTextOutput(t *testing.T) {
	var buffer bytes.Buffer
	if err := Text(&buffer, report.Report{}); err != nil || buffer.String() != "No findings.\n" {
		t.Fatalf("empty report rendered %q, %v", buffer.String(), err)
	}
	buffer.Reset()
	if err := Text(&buffer, report.Report{Findings: []report.Finding{{RuleID: rules.HintRelationIncomplete, Severity: report.SeverityHigh, File: "a.go", Line: 1, Column: 2, Message: "m"}}}); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(buffer.String(), "a.go:1:2: high [GNARK_HINT_RELATION_INCOMPLETE] m\n") {
		t.Fatalf("unexpected text: %q", buffer.String())
	}
}
