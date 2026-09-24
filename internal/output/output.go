// Package output renders analyzer reports.
package output

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"

	"github.com/auditinfra-io/gnark-safety/internal/rules"
	"github.com/auditinfra-io/gnark-safety/pkg/report"
)

// InformationURI is the project home recorded in SARIF output.
const InformationURI = "https://github.com/auditinfra-io/gnark-safety"

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

// sarifLevels maps severities to a SARIF level and GitHub's
// security-severity score. GitHub buckets scores as >= 9 critical, 7-8.9
// high, 4-6.9 medium, and < 4 low.
var sarifLevels = map[report.Severity]struct{ level, score string }{
	report.SeverityCritical: {"error", "9.5"},
	report.SeverityHigh:     {"error", "8.0"},
	report.SeverityMedium:   {"warning", "5.0"},
	report.SeverityLow:      {"note", "3.0"},
	report.SeverityInfo:     {"note", "1.0"},
}

func sarifLevel(severity report.Severity) (level, score string) {
	if mapped, ok := sarifLevels[severity]; ok {
		return mapped.level, mapped.score
	}
	return "warning", "5.0"
}

type sarif struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []sarifRun `json:"runs"`
}
type sarifRun struct {
	Tool        sarifTool         `json:"tool"`
	Results     []sarifResult     `json:"results"`
	Invocations []sarifInvocation `json:"invocations"`
}
type sarifInvocation struct {
	ExecutionSuccessful bool            `json:"executionSuccessful"`
	Properties          report.Coverage `json:"properties"`
}
type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}
type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}
type sarifRule struct {
	ID                   string              `json:"id"`
	Name                 string              `json:"name"`
	ShortDescription     sarifMessage        `json:"shortDescription"`
	FullDescription      sarifMessage        `json:"fullDescription"`
	Help                 *sarifMessage       `json:"help,omitempty"`
	HelpURI              string              `json:"helpUri,omitempty"`
	DefaultConfiguration sarifConfiguration  `json:"defaultConfiguration"`
	Properties           sarifRuleProperties `json:"properties"`
}
type sarifConfiguration struct {
	Level string `json:"level"`
}
type sarifRuleProperties struct {
	Tags             []string `json:"tags"`
	Precision        string   `json:"precision,omitempty"`
	SecuritySeverity string   `json:"security-severity"`
}
type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	RuleIndex int             `json:"ruleIndex"`
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

// SARIF renders a SARIF 2.1.0 log. Rule metadata comes from the registry, so
// it never depends on which finding happened to be reported first; every
// registered rule is listed, and a finding with an unregistered ID still
// gets a minimal rule entry rather than a dangling reference.
func SARIF(w io.Writer, r report.Report) error {
	var ruleList []sarifRule
	index := map[string]int{}
	for _, spec := range rules.All() {
		level, score := sarifLevel(spec.DefaultSeverity())
		index[spec.ID] = len(ruleList)
		ruleList = append(ruleList, sarifRule{
			ID:                   spec.ID,
			Name:                 spec.ID,
			ShortDescription:     sarifMessage{Text: spec.Title},
			FullDescription:      sarifMessage{Text: spec.Summary},
			Help:                 &sarifMessage{Text: spec.Description},
			HelpURI:              spec.HelpURI(),
			DefaultConfiguration: sarifConfiguration{Level: level},
			Properties:           sarifRuleProperties{Tags: []string{"security", "zk", "gnark", spec.Class}, Precision: spec.Confidence, SecuritySeverity: score},
		})
	}
	var unregistered []string
	for _, f := range r.Findings {
		if _, ok := index[f.RuleID]; !ok {
			index[f.RuleID] = -1
			unregistered = append(unregistered, f.RuleID)
		}
	}
	sort.Strings(unregistered)
	for _, id := range unregistered {
		level, score := sarifLevel("")
		index[id] = len(ruleList)
		ruleList = append(ruleList, sarifRule{ID: id, Name: id, ShortDescription: sarifMessage{Text: id}, FullDescription: sarifMessage{Text: id}, HelpURI: InformationURI, DefaultConfiguration: sarifConfiguration{Level: level}, Properties: sarifRuleProperties{Tags: []string{"security", "zk", "gnark"}, SecuritySeverity: score}})
	}

	results := make([]sarifResult, 0, len(r.Findings))
	for _, f := range r.Findings {
		level, _ := sarifLevel(f.Severity)
		results = append(results, sarifResult{RuleID: f.RuleID, RuleIndex: index[f.RuleID], Level: level, Message: sarifMessage{Text: f.Message}, Locations: []sarifLocation{{PhysicalLocation: sarifPhysical{ArtifactLocation: sarifArtifact{URI: f.File}, Region: sarifRegion{StartLine: f.Line, StartColumn: f.Column}}}}})
	}
	toolVersion := r.Tool.Version
	if toolVersion == "" {
		toolVersion = "devel"
	}
	s := sarif{Version: "2.1.0", Schema: "https://json.schemastore.org/sarif-2.1.0.json", Runs: []sarifRun{{
		Tool:        sarifTool{Driver: sarifDriver{Name: "gnark-safety", Version: toolVersion, InformationURI: InformationURI, Rules: ruleList}},
		Results:     results,
		Invocations: []sarifInvocation{{ExecutionSuccessful: true, Properties: r.Coverage}},
	}}}
	e := json.NewEncoder(w)
	e.SetIndent("", "  ")
	return e.Encode(s)
}
