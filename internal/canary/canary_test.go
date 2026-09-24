package canary

import (
	"path/filepath"
	"sort"
	"testing"

	"github.com/auditinfra-io/gnark-safety/pkg/report"
)

func loadAll(t *testing.T) map[string]Snapshot {
	t.Helper()
	paths, err := filepath.Glob("../../canary/*.json")
	if err != nil || len(paths) == 0 {
		t.Fatalf("no snapshots found: %v", err)
	}
	snapshots := map[string]Snapshot{}
	for _, path := range paths {
		s, err := Load(path)
		if err != nil {
			t.Fatal(err)
		}
		snapshots[s.GnarkVersion] = s
	}
	return snapshots
}

// TestSnapshotsAreClassified is the Phase 3 exit criterion: every finding on
// gnark std/ is classified and explained, and none is an unclassified high.
func TestSnapshotsAreClassified(t *testing.T) {
	for version, s := range loadAll(t) {
		for _, e := range s.Findings {
			if e.Severity.Rank() >= report.SeverityHigh.Rank() && e.Classification == FalsePositive {
				t.Errorf("%s: high false positive %s at %s:%d must be fixed in the rule, not recorded", version, e.RuleID, e.File, e.Line)
			}
		}
	}
}

// TestReleaseMatrix pins how findings differ between the gnark releases the
// canary scans. A change here means a rule or gnark moved; update the
// numbers and canary/README.md together.
func TestReleaseMatrix(t *testing.T) {
	snapshots := loadAll(t)
	older, newer := snapshots["v0.15.0"], snapshots["v0.16.3"]
	if older.GnarkVersion == "" || newer.GnarkVersion == "" {
		t.Fatal("release matrix needs the v0.15.0 and v0.16.3 snapshots")
	}
	keys := func(s Snapshot) map[string]bool {
		set := map[string]bool{}
		for _, e := range s.Findings {
			set[Key(e.RuleID, e.Severity, e.File, e.Line, e.Function, true)] = true
		}
		return set
	}
	oldKeys, newKeys := keys(older), keys(newer)
	var shared, onlyOld, onlyNew []string
	for key := range oldKeys {
		if newKeys[key] {
			shared = append(shared, key)
		} else {
			onlyOld = append(onlyOld, key)
		}
	}
	for key := range newKeys {
		if !oldKeys[key] {
			onlyNew = append(onlyNew, key)
		}
	}
	sort.Strings(onlyOld)
	sort.Strings(onlyNew)
	if len(shared) != 2 || len(onlyOld) != 0 || len(onlyNew) != 0 {
		t.Fatalf("release delta changed: shared=%d only v0.15.0=%v only v0.16.3=%v", len(shared), onlyOld, onlyNew)
	}
}

func TestDiff(t *testing.T) {
	s := Snapshot{Target: "t", GnarkVersion: "v", Findings: []Entry{
		{RuleID: "A", Severity: report.SeverityMedium, File: "a.go", Line: 1, Function: "f", Classification: Intended, Note: "n"},
		{RuleID: "B", Severity: report.SeverityHigh, File: "b.go", Line: 2, Function: "g", Classification: FalsePositive, Note: "n"},
	}}
	r := report.Report{Findings: []report.Finding{
		{RuleID: "A", Severity: report.SeverityMedium, File: "a.go", Line: 1, Function: "f"},
		{RuleID: "C", Severity: report.SeverityLow, File: "c.go", Line: 3, Function: "h"},
	}}
	unexpected, missing := Diff(s, r, false)
	if len(unexpected) != 1 || unexpected[0] != "C low c.go:3 h" || len(missing) != 1 || missing[0] != "B high b.go:2 g" {
		t.Fatalf("unexpected=%v missing=%v", unexpected, missing)
	}
	// A moved line is a difference unless lines are ignored.
	r.Findings[0].Line = 9
	if unexpected, _ := Diff(s, r, false); len(unexpected) != 2 {
		t.Fatalf("moved line not detected: %v", unexpected)
	}
	if unexpected, _ := Diff(s, r, true); len(unexpected) != 1 {
		t.Fatalf("ignore-lines still reports the moved line: %v", unexpected)
	}
	// Duplicates are matched one for one.
	r.Findings = append(r.Findings, r.Findings[0])
	if unexpected, _ := Diff(s, r, true); len(unexpected) != 2 {
		t.Fatalf("a duplicate finding must not reuse one classification: %v", unexpected)
	}
}

func TestValidate(t *testing.T) {
	for _, bad := range []Snapshot{
		{GnarkVersion: "v"},
		{Target: "t", GnarkVersion: "v", Findings: []Entry{{RuleID: "A", Severity: report.SeverityLow, Classification: "maybe", Note: "n"}}},
		{Target: "t", GnarkVersion: "v", Findings: []Entry{{RuleID: "A", Severity: report.SeverityLow, Classification: Intended}}},
		{Target: "t", GnarkVersion: "v", Findings: []Entry{{RuleID: "A", Severity: "review", Classification: Intended, Note: "n"}}},
	} {
		if bad.Validate() == nil {
			t.Errorf("invalid snapshot accepted: %#v", bad)
		}
	}
}
