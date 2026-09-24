// Package canary compares a scan of a third-party codebase with a committed,
// classified snapshot, so every finding the rules produce on real code has
// been read and explained, and any change is noticed.
package canary

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"

	"github.com/auditinfra-io/gnark-safety/pkg/report"
)

// Classifications a snapshot entry may carry.
const (
	// TruePositive: the finding is a real defect in the scanned code. Such
	// an entry is committed only after the maintainers of that code have
	// cleared publication.
	TruePositive = "true-positive"
	// FalsePositive: the rule is wrong here; the note names the missing guard.
	FalsePositive = "false-positive"
	// Intended: the rule describes the code correctly, and the code's own
	// documented design accounts for it.
	Intended = "intended"
)

// Snapshot is the classified record of one scan target at one version.
type Snapshot struct {
	Target       string  `json:"target"`
	GnarkVersion string  `json:"gnark_version"`
	Findings     []Entry `json:"findings"`
}

// Entry is one classified finding.
type Entry struct {
	RuleID         string          `json:"rule_id"`
	Severity       report.Severity `json:"severity"`
	File           string          `json:"file"`
	Line           int             `json:"line"`
	Function       string          `json:"function"`
	Classification string          `json:"classification"`
	Note           string          `json:"note"`
}

// Load reads and validates a snapshot.
func Load(path string) (Snapshot, error) {
	var s Snapshot
	content, err := os.ReadFile(path)
	if err != nil {
		return s, err
	}
	if err := json.Unmarshal(content, &s); err != nil {
		return s, fmt.Errorf("%s: %w", path, err)
	}
	return s, s.Validate()
}

// Validate requires every entry to be classified and explained.
func (s Snapshot) Validate() error {
	if s.Target == "" || s.GnarkVersion == "" {
		return fmt.Errorf("snapshot needs a target and a gnark_version")
	}
	for _, e := range s.Findings {
		switch e.Classification {
		case TruePositive, FalsePositive, Intended:
		default:
			return fmt.Errorf("%s %s:%d: classification %q is not one of %s, %s, %s", e.RuleID, e.File, e.Line, e.Classification, TruePositive, FalsePositive, Intended)
		}
		if e.Note == "" {
			return fmt.Errorf("%s %s:%d: every classification needs a note", e.RuleID, e.File, e.Line)
		}
		if e.Severity.Rank() < 0 {
			return fmt.Errorf("%s %s:%d: unknown severity %q", e.RuleID, e.File, e.Line, e.Severity)
		}
	}
	return nil
}

// Key identifies a finding. With ignoreLines it tolerates code moving, as
// when comparing a development snapshot of gnark against a release.
func Key(rule string, severity report.Severity, file string, line int, function string, ignoreLines bool) string {
	if ignoreLines {
		line = 0
	}
	return fmt.Sprintf("%s %s %s:%d %s", rule, severity, file, line, function)
}

// Diff lists findings in the report that the snapshot does not classify
// (unexpected) and snapshot entries the report no longer produces
// (missing). Both are sorted.
func Diff(s Snapshot, r report.Report, ignoreLines bool) (unexpected, missing []string) {
	classified := map[string]int{}
	for _, e := range s.Findings {
		classified[Key(e.RuleID, e.Severity, e.File, e.Line, e.Function, ignoreLines)]++
	}
	for _, f := range r.Findings {
		key := Key(f.RuleID, f.Severity, f.File, f.Line, f.Function, ignoreLines)
		if classified[key] > 0 {
			classified[key]--
			continue
		}
		unexpected = append(unexpected, key)
	}
	for key, count := range classified {
		for ; count > 0; count-- {
			missing = append(missing, key)
		}
	}
	sort.Strings(unexpected)
	sort.Strings(missing)
	return unexpected, missing
}
