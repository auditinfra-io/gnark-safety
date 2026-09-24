// Package output renders analyzer reports.
package output

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/auditinfra-io/gnark-safety/pkg/report"
)

func JSON(w io.Writer, r report.Report) error {
	e := json.NewEncoder(w)
	e.SetIndent("", "  ")
	return e.Encode(r)
}

func Text(w io.Writer, r report.Report) error {
	for _, f := range r.Findings {
		if _, err := fmt.Fprintf(w, "%s:%d:%d: %s [%s] %s\n", f.File, f.Line, f.Column, f.Severity, f.RuleID, f.Message); err != nil {
			return err
		}
	}
	if len(r.Findings) == 0 {
		_, err := fmt.Fprintln(w, "No findings.")
		return err
	}
	_, err := fmt.Fprintf(w, "\n%d finding(s).\n", len(r.Findings))
	return err
}

type sarif struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []sarifRun `json:"runs"`
}
type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}
type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}
type sarifDriver struct {
	Name    string      `json:"name"`
	Version string      `json:"version"`
	Rules   []sarifRule `json:"rules"`
}
type sarifRule struct {
	ID               string       `json:"id"`
	ShortDescription sarifMessage `json:"shortDescription"`
}
type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifMessage    `json:"message"`
	Locations []sarifLocation `json:"locations"`
}
type sarifMessage struct {
	Text string `json:"text"`
}
type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}
type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
	Region           sarifRegion   `json:"region"`
}
type sarifArtifact struct {
	URI string `json:"uri"`
}
type sarifRegion struct {
	StartLine   int `json:"startLine"`
	StartColumn int `json:"startColumn"`
}

func SARIF(w io.Writer, r report.Report) error {
	rules := map[string]sarifRule{}
	results := make([]sarifResult, 0, len(r.Findings))
	for _, f := range r.Findings {
		rules[f.RuleID] = sarifRule{ID: f.RuleID, ShortDescription: sarifMessage{Text: f.Message}}
		results = append(results, sarifResult{RuleID: f.RuleID, Level: "error", Message: sarifMessage{Text: f.Message}, Locations: []sarifLocation{{PhysicalLocation: sarifPhysical{ArtifactLocation: sarifArtifact{URI: f.File}, Region: sarifRegion{StartLine: f.Line, StartColumn: f.Column}}}}})
	}
	ruleList := make([]sarifRule, 0, len(rules))
	if x, ok := rules["GNARK_HINT_RELATION_INCOMPLETE"]; ok {
		ruleList = append(ruleList, x)
	}
	s := sarif{Version: "2.1.0", Schema: "https://json.schemastore.org/sarif-2.1.0.json", Runs: []sarifRun{{Tool: sarifTool{Driver: sarifDriver{Name: "gnark-safety", Version: report.SchemaVersion, Rules: ruleList}}, Results: results}}}
	e := json.NewEncoder(w)
	e.SetIndent("", "  ")
	return e.Encode(s)
}
