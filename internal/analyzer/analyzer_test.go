package analyzer

import (
	"context"
	"math/big"
	"strings"
	"testing"

	"github.com/auditinfra-io/gnark-safety/internal/rules"
	"github.com/auditinfra-io/gnark-safety/pkg/report"
	"github.com/consensys/gnark-crypto/ecc"
)

func TestScanResourceLimits(t *testing.T) {
	_, err := ScanContext(context.Background(), "../..", []string{"./internal/analyzer/testdata/relation"}, Options{MaxHints: 1})
	if err == nil || !strings.Contains(err.Error(), "hint limit exceeded") {
		t.Fatalf("expected hint limit error, got %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = ScanContext(ctx, "../..", []string{"."}, Options{})
	if err == nil || !strings.Contains(err.Error(), "canceled") {
		t.Fatalf("expected cancellation error, got %v", err)
	}
}

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

func TestConfiguredFieldAssessment(t *testing.T) {
	r, err := ScanContext(context.Background(), "../..", []string{"."}, Options{FieldModulus: ecc.BN254.ScalarField(), FieldName: "BN254 scalar field"})
	if err != nil {
		t.Fatal(err)
	}
	assertInvariant(t, r.Hints[0].Invariants, 0, "field_safety", report.InvariantSatisfied, "below BN254 scalar field modulus")

	r, err = ScanContext(context.Background(), "../..", []string{"."}, Options{FieldModulus: big.NewInt(101), FieldName: "test field"})
	if err != nil {
		t.Fatal(err)
	}
	assertInvariant(t, r.Hints[0].Invariants, 0, "field_safety", report.InvariantMissing, "not below test field modulus")
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
	rules := map[string]string{}
	for _, f := range r.Findings {
		got[f.Function] = true
		rules[f.Function] = f.RuleID
	}
	for _, name := range []string{"wrongBound", "invertedBound", "elseBound", "loopBound", "directIndex", "helperConditional", "successfulEarlyReturn"} {
		if !got[name] {
			t.Errorf("missing finding for %s", name)
		}
	}
	for _, name := range []string{"separateAssertions", "safe", "helperSafe", "lessOrEqualSafe", "helperLessOrEqualSafe"} {
		if got[name] {
			t.Errorf("unexpected finding for %s", name)
		}
	}
	if len(r.Findings) != 8 {
		t.Fatalf("got %d findings, want 8: %#v", len(r.Findings), r.Findings)
	}
	if rules["unusedRemainder"] != unusedOutputRule {
		t.Errorf("missing unused-output finding: %#v", r.Findings)
	}
	for _, hint := range r.Hints {
		status := report.InvariantMissing
		if hint.Function == "safe" || hint.Function == "helperSafe" || hint.Function == "lessOrEqualSafe" || hint.Function == "helperLessOrEqualSafe" {
			status = report.InvariantSatisfied
		}
		if hint.Function == "separateAssertions" || hint.Function == "unusedRemainder" {
			status = report.InvariantUnknown
		}
		assertInvariant(t, hint.Invariants, 1, "canonicality", status, map[report.InvariantStatus]string{
			report.InvariantMissing:   "missing unconditional constraint",
			report.InvariantSatisfied: "constraint",
			report.InvariantUnknown:   "reconstruction not found",
		}[status])
		if hint.Function == "helperSafe" {
			assertInvariant(t, hint.Invariants, 1, "canonicality", report.InvariantSatisfied, "helper assertCanonical")
			assertInvariant(t, hint.Invariants, 0, "range", report.InvariantSatisfied, "width: 8")
			assertInvariant(t, hint.Invariants, 0, "field_safety", report.InvariantUnknown, "65280")
		}
		if hint.Function == "lessOrEqualSafe" {
			assertInvariant(t, hint.Invariants, 1, "canonicality", report.InvariantSatisfied, "r <= d-1")
		}
		if hint.Function == "helperLessOrEqualSafe" {
			assertInvariant(t, hint.Invariants, 1, "canonicality", report.InvariantSatisfied, "helper assertCanonicalLessOrEqual")
		}
	}
}

func TestUnknownInvariantsRejectsNegativeOutputCount(t *testing.T) {
	if got := unknownInvariants(-1, "invalid"); got == nil || len(got) != 0 {
		t.Fatalf("negative output count produced invariants: %#v", got)
	}
}

// TestDeprecatedAPINewHint guards the gap where frontend.API.NewHint calls
// were not recognized and a vulnerable circuit scanned as clean.
func TestDeprecatedAPINewHint(t *testing.T) {
	r, err := Scan("../..", []string{"./internal/analyzer/testdata/deprecated"})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Hints) != 4 {
		t.Fatalf("got %d hints, want 4: %#v", len(r.Hints), r.Hints)
	}
	got := map[string]string{}
	for _, f := range r.Findings {
		got[f.Function] = f.RuleID
	}
	want := map[string]string{"(*Circuit).Define": relationRule, "methodExpression": relationRule, "promoted": relationRule}
	if len(got) != len(want) {
		t.Fatalf("got findings %v, want %v", got, want)
	}
	for function, rule := range want {
		if got[function] != rule {
			t.Errorf("%s: got rule %q, want %q", function, got[function], rule)
		}
	}
}

// TestRegistryCoverage checks the registry against what the analyzer really
// emits, in both directions: every emitted rule is registered with the
// severity it uses, and every registered rule is exercised by a fixture.
func TestRegistryCoverage(t *testing.T) {
	emitted := map[string]bool{}
	for _, pattern := range []string{".", "./internal/analyzer/testdata/relation", "./internal/analyzer/testdata/deprecated"} {
		r, err := Scan("../..", []string{pattern})
		if err != nil {
			t.Fatal(err)
		}
		if r.Tool.Name != "gnark-safety" || r.Tool.Version == "" {
			t.Fatalf("missing tool identity: %#v", r.Tool)
		}
		for _, f := range r.Findings {
			spec, ok := rules.Lookup(f.RuleID)
			if !ok {
				t.Errorf("%s: emitted rule is not registered", f.RuleID)
				continue
			}
			if !spec.Allows(f.Severity) {
				t.Errorf("%s: emitted severity %q is not registered (%s)", f.RuleID, f.Severity, spec.SeverityLabel())
			}
			emitted[f.RuleID] = true
		}
	}
	for _, spec := range rules.All() {
		if !emitted[spec.ID] {
			t.Errorf("%s: registered rule is not exercised by any fixture", spec.ID)
		}
	}
}
