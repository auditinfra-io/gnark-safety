package output

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/auditinfra-io/gnark-safety/pkg/report"
)

func TestSARIFIncludesAllRulesAndSeverityLevels(t *testing.T) {
	input := report.Report{Findings: []report.Finding{
		{RuleID: "Z_REVIEW", Severity: report.SeverityReview, Message: "review", File: "a.go", Line: 1, Column: 1},
		{RuleID: "A_HIGH", Severity: report.SeverityHigh, Message: "high", File: "b.go", Line: 2, Column: 1},
	}}
	var buffer bytes.Buffer
	if err := SARIF(&buffer, input); err != nil {
		t.Fatal(err)
	}
	var result sarif
	if err := json.Unmarshal(buffer.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	run := result.Runs[0]
	if len(run.Tool.Driver.Rules) != 2 || run.Tool.Driver.Rules[0].ID != "A_HIGH" || run.Tool.Driver.Rules[1].ID != "Z_REVIEW" {
		t.Fatalf("rules are incomplete or unstable: %#v", run.Tool.Driver.Rules)
	}
	if run.Results[0].Level != "warning" || run.Results[1].Level != "error" {
		t.Fatalf("unexpected SARIF levels: %#v", run.Results)
	}
}
