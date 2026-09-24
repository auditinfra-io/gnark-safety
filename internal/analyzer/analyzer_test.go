package analyzer

import (
	"strings"
	"testing"

	"github.com/auditinfra-io/gnark-safety/pkg/report"
)

func TestCanonicalFixture(t *testing.T) {
	r, err := Scan("../..", []string{"."})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Hints) != 1 {
		t.Fatalf("got %d hints, want 1", len(r.Hints))
	}
	if len(r.Findings) != 1 {
		t.Fatalf("got %d findings, want 1: %#v", len(r.Findings), r.Findings)
	}
	f := r.Findings[0]
	if f.RuleID != relationRule || f.Function != "constrainDivision" {
		t.Fatalf("unexpected finding: %#v", f)
	}
	assertInvariant(t, r.Hints[0].Invariants, 0, "participation", report.InvariantSatisfied, "n = q*d + r")
	assertInvariant(t, r.Hints[0].Invariants, 0, "range", report.InvariantSatisfied, "width: 8")
	assertInvariant(t, r.Hints[0].Invariants, 1, "relation", report.InvariantSatisfied, "n = q*d + r")
	assertInvariant(t, r.Hints[0].Invariants, 1, "canonicality", report.InvariantMissing, "r < d")
	assertInvariant(t, r.Hints[0].Invariants, 0, "field_safety", report.InvariantUnknown, "65280")
}

func assertInvariant(t *testing.T, invariants []report.Invariant, output int, kind string, status report.InvariantStatus, evidence string) {
	t.Helper()
	for _, invariant := range invariants {
		if invariant.OutputIndex != output || invariant.Kind != kind {
			continue
		}
		if invariant.Status != status || !strings.Contains(strings.Join(invariant.Evidence, " "), evidence) {
			t.Fatalf("unexpected invariant: %#v; want status=%s evidence containing %q", invariant, status, evidence)
		}
		return
	}
	t.Fatalf("missing invariant output=%d kind=%s in %#v", output, kind, invariants)
}

func TestRelationShapeAndCoverage(t *testing.T) {
	r, err := Scan("../..", []string{"./internal/analyzer/testdata/relation"})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, f := range r.Findings {
		got[f.Function] = true
	}
	for _, name := range []string{"wrongBound", "invertedBound", "elseBound", "loopBound", "directIndex", "helperConditional", "successfulEarlyReturn"} {
		if !got[name] {
			t.Errorf("missing finding for %s", name)
		}
	}
	for _, name := range []string{"separateAssertions", "safe", "helperSafe"} {
		if got[name] {
			t.Errorf("unexpected finding for %s", name)
		}
	}
	if len(r.Findings) != 7 {
		t.Fatalf("got %d findings, want 7: %#v", len(r.Findings), r.Findings)
	}
	for _, hint := range r.Hints {
		status := report.InvariantMissing
		if hint.Function == "safe" || hint.Function == "helperSafe" {
			status = report.InvariantSatisfied
		}
		if hint.Function == "separateAssertions" {
			status = report.InvariantUnknown
		}
		assertInvariant(t, hint.Invariants, 1, "canonicality", status, map[report.InvariantStatus]string{
			report.InvariantMissing:   "missing unconditional constraint",
			report.InvariantSatisfied: "unconditional constraint",
			report.InvariantUnknown:   "reconstruction not found",
		}[status])
		if hint.Function == "helperSafe" {
			assertInvariant(t, hint.Invariants, 1, "canonicality", report.InvariantSatisfied, "helper assertCanonical")
			assertInvariant(t, hint.Invariants, 0, "range", report.InvariantSatisfied, "width: 8")
			assertInvariant(t, hint.Invariants, 0, "field_safety", report.InvariantUnknown, "65280")
		}
	}
}

func TestRuleHelp(t *testing.T) {
	if _, ok := RuleHelp(relationRule); !ok {
		t.Fatal("documented rule is missing")
	}
	if _, ok := RuleHelp("NO_SUCH_RULE"); ok {
		t.Fatal("unknown rule was accepted")
	}
}

func TestUnknownInvariantsRejectsNegativeOutputCount(t *testing.T) {
	if got := unknownInvariants(-1, "invalid"); got == nil || len(got) != 0 {
		t.Fatalf("negative output count produced invariants: %#v", got)
	}
}
