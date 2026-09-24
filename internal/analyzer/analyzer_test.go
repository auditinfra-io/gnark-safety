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
	_, err = ScanContext(ctx, "../..", []string{"./examples/divmod"}, Options{})
	if err == nil || !strings.Contains(err.Error(), "canceled") {
		t.Fatalf("expected cancellation error, got %v", err)
	}
}

func TestCanonicalFixture(t *testing.T) {
	r, err := Scan("../..", []string{"./examples/divmod"})
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
	// The shared helper guards r < d with a bool; the finding belongs to the
	// caller that passes false, not to the helper or the corrected caller.
	if f.RuleID != relationRule || f.Function != "(*VulnerableCircuit).Define" || !strings.Contains(f.Message, "enforceCanonicalRemainder=false") {
		t.Fatalf("unexpected finding: %#v", f)
	}
	assertInvariant(t, r.Hints[0].Invariants, 0, "participation", report.InvariantSatisfied, "n = q*d + r")
	assertInvariant(t, r.Hints[0].Invariants, 0, "range", report.InvariantSatisfied, "width: 8")
	assertInvariant(t, r.Hints[0].Invariants, 1, "relation", report.InvariantSatisfied, "n = q*d + r")
	assertInvariant(t, r.Hints[0].Invariants, 1, "canonicality", report.InvariantMissing, "r < d")
	assertInvariant(t, r.Hints[0].Invariants, 0, "field_safety", report.InvariantUnknown, "65280")
}

func TestConfiguredFieldAssessment(t *testing.T) {
	r, err := ScanContext(context.Background(), "../..", []string{"./examples/divmod"}, Options{FieldModulus: ecc.BN254.ScalarField(), FieldName: "BN254 scalar field"})
	if err != nil {
		t.Fatal(err)
	}
	assertInvariant(t, r.Hints[0].Invariants, 0, "field_safety", report.InvariantSatisfied, "below BN254 scalar field modulus")

	r, err = ScanContext(context.Background(), "../..", []string{"./examples/divmod"}, Options{FieldModulus: big.NewInt(101), FieldName: "test field"})
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
	for _, pattern := range []string{"./examples/divmod", "./internal/analyzer/testdata/relation", "./internal/analyzer/testdata/deprecated"} {
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
			severity := f.Severity
			if f.OriginalSeverity != "" {
				severity = f.OriginalSeverity
			}
			if !spec.Allows(severity) {
				t.Errorf("%s: emitted severity %q is not registered (%s)", f.RuleID, severity, spec.SeverityLabel())
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

func TestIncludeTests(t *testing.T) {
	pattern := []string{"./internal/analyzer/testdata/testonly"}
	r, err := Scan("../..", pattern)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Findings) != 0 || len(r.Hints) != 1 || r.Coverage.TestsIncluded {
		t.Fatalf("default scan must skip _test.go: findings=%#v hints=%d coverage=%#v", r.Findings, len(r.Hints), r.Coverage)
	}
	r, err = ScanContext(context.Background(), "../..", pattern, Options{IncludeTests: true})
	if err != nil {
		t.Fatal(err)
	}
	// The production file is shared by the package and its test variant; it
	// must be analyzed once, not once per variant.
	if len(r.Hints) != 2 || len(r.Findings) != 1 || r.Findings[0].Function != "vulnerableInTest" || !r.Coverage.TestsIncluded {
		t.Fatalf("test scan: findings=%#v hints=%#v coverage=%#v", r.Findings, r.Hints, r.Coverage)
	}
	if r.Coverage.Files != 2 || r.Coverage.Packages != 1 || r.Coverage.GnarkPackages != 1 {
		t.Fatalf("unexpected coverage with tests: %#v", r.Coverage)
	}
}

func TestExampleDowngrade(t *testing.T) {
	pattern := []string{"./internal/analyzer/testdata/examples/demo"}
	r, err := Scan("../..", pattern)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Findings) != 1 {
		t.Fatalf("got %#v", r.Findings)
	}
	f := r.Findings[0]
	if f.Severity != report.SeverityLow || f.OriginalSeverity != report.SeverityHigh || r.Coverage.ExamplesDowngraded != 1 || !strings.Contains(strings.Join(f.Limitations, " "), "--include-examples") {
		t.Fatalf("example finding not downgraded: %#v coverage=%#v", f, r.Coverage)
	}
	r, err = ScanContext(context.Background(), "../..", pattern, Options{IncludeExamples: true})
	if err != nil {
		t.Fatal(err)
	}
	if f := r.Findings[0]; f.Severity != report.SeverityHigh || f.OriginalSeverity != "" || r.Coverage.ExamplesDowngraded != 0 {
		t.Fatalf("--include-examples did not keep severity: %#v", f)
	}
}

func TestIsExamplePath(t *testing.T) {
	for path, want := range map[string]bool{
		"examples/divmod/circuit.go": true,
		"a/example/b.go":             true,
		"_examples/x.go":             true,
		"examples.go":                false,
		"src/examples_test/x.go":     false,
		"circuits/example.go":        false,
	} {
		if got := IsExamplePath(path); got != want {
			t.Errorf("IsExamplePath(%q) = %v, want %v", path, got, want)
		}
	}
}

func TestSuppressions(t *testing.T) {
	r, err := Scan("../..", []string{"./internal/analyzer/testdata/suppress"})
	if err != nil {
		t.Fatal(err)
	}
	suppressed := map[string]string{}
	for _, f := range r.Suppressed {
		if f.Suppression == nil || f.Suppression.Kind != "inSource" {
			t.Fatalf("suppressed finding lacks a suppression record: %#v", f)
		}
		suppressed[f.Function] = f.Suppression.Justification
	}
	want := map[string]string{"aboveLine": "the caller constrains r < d", "trailing": "reviewed in audit 12", "multipleIDs": "both reviewed"}
	if len(suppressed) != len(want) {
		t.Fatalf("suppressed %v, want %v", suppressed, want)
	}
	for function, reason := range want {
		if suppressed[function] != reason {
			t.Errorf("%s: justification %q, want %q", function, suppressed[function], reason)
		}
	}
	active := map[string]bool{}
	for _, f := range r.Findings {
		if f.Suppression != nil {
			t.Errorf("active finding carries a suppression: %#v", f)
		}
		active[f.Function] = true
	}
	for _, function := range []string{"wrongRule", "noReason", "spaced", "unknownRule", "tooFar"} {
		if !active[function] {
			t.Errorf("%s: finding should stay active", function)
		}
	}
	diagnostics := strings.Join(r.Diagnostics, "\n")
	for _, fragment := range []string{
		"needs a rule ID and a reason",
		"no space after //",
		`unknown rule "GNARK_NO_SUCH_RULE"`,
		"suppression of GNARK_HINT_OUTPUT_UNUSED matched no finding",       // wrongRule and multipleIDs
		"suppression of GNARK_HINT_RELATION_INCOMPLETE matched no finding", // tooFar
	} {
		if !strings.Contains(diagnostics, fragment) {
			t.Errorf("missing diagnostic containing %q in:\n%s", fragment, diagnostics)
		}
	}
	if got := strings.Count(diagnostics, "matched no finding"); got != 3 {
		t.Errorf("got %d unused-directive diagnostics, want 3:\n%s", got, diagnostics)
	}
}

func TestCallSiteSpecialization(t *testing.T) {
	r, err := Scan("../..", []string{"./internal/analyzer/testdata/specialize"})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, f := range r.Findings {
		if f.RuleID != relationRule {
			t.Fatalf("unexpected rule: %#v", f)
		}
		got[f.Function] = f.Message
	}
	// Call sites that disable the bound carry the finding; the hint in the
	// shared helper does not.
	for function, argument := range map[string]string{
		"(*Vulnerable).Define": "enforce=false",
		"skipsBound":           "skip=true",
		"relaxedCaller":        "relaxed=true",
	} {
		if !strings.Contains(got[function], argument) {
			t.Errorf("%s: want a call-site finding mentioning %q, got %q", function, argument, got[function])
		}
	}
	// Unresolvable guards keep the finding at the hint.
	for _, function := range []string{"escaping", "dynamic", "reassigned", "Uncalled", "Exported", "(divider).constrain"} {
		if got[function] != relationMessage {
			t.Errorf("%s: want a hint-site finding, got %q", function, got[function])
		}
	}
	if len(got) != 9 || len(r.Findings) != 9 {
		t.Fatalf("got findings %v", got)
	}
	for _, f := range r.Findings {
		if f.Function == "dynamic" && !strings.Contains(strings.Join(f.Evidence, " "), "enforced only when parameter enforce is true") {
			t.Errorf("hint-site finding for a guarded bound should explain the guard: %#v", f.Evidence)
		}
		if f.Function == "(*Vulnerable).Define" && !strings.Contains(strings.Join(f.Evidence, " "), "in guarded") {
			t.Errorf("call-site finding should point back to the hint: %#v", f.Evidence)
		}
	}
}

func TestPathBase(t *testing.T) {
	r, err := ScanContext(context.Background(), "../..", []string{"./examples/divmod"}, Options{PathBase: "../../examples"})
	if err != nil {
		t.Fatal(err)
	}
	if r.Hints[0].File != "divmod/circuits.go" || r.Findings[0].File != "divmod/circuits.go" {
		t.Fatalf("paths not relative to base: hint %q finding %q", r.Hints[0].File, r.Findings[0].File)
	}
	// Example classification and suppressions both use the rebased path.
	if r.Findings[0].OriginalSeverity != "" {
		t.Fatalf("divmod/circuits.go is not under an examples directory once rebased: %#v", r.Findings[0])
	}
	r, err = ScanContext(context.Background(), "../..", []string{"./internal/analyzer/testdata/suppress"}, Options{PathBase: "../../internal"})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Suppressed) != 3 || !strings.HasPrefix(r.Suppressed[0].File, "analyzer/testdata/suppress/") {
		t.Fatalf("suppressions must match under a rebased path: %#v", r.Suppressed)
	}
}

func TestUnusedOutputClassification(t *testing.T) {
	r, err := Scan("../..", []string{"./internal/analyzer/testdata/unused"})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string][]string{}
	for _, f := range r.Findings {
		got[f.Function] = append(got[f.Function], f.Message)
	}
	want := map[string][]string{
		"discarded": {"Hint output 1 is never used after extraction."},
	}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for function, messages := range want {
		if strings.Join(got[function], "|") != strings.Join(messages, "|") {
			t.Errorf("%s: got %v, want %v", function, got[function], messages)
		}
	}
}
