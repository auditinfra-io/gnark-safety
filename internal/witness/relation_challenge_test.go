package witness

import (
	"context"
	"errors"
	"math/big"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/auditinfra-io/gnark-safety/examples/divmod"
	"github.com/auditinfra-io/gnark-safety/internal/analyzer"
	"github.com/auditinfra-io/gnark-safety/internal/rules"
	"github.com/auditinfra-io/gnark-safety/pkg/report"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/cmp"
)

// Challenge cases for GNARK_HINT_RELATION_INCOMPLETE; docs/relation-rule-review.md
// has the table. Each case states the property the circuit is meant to
// enforce, checks by solving whether a witness violating it is accepted or
// rejected by an unsatisfied constraint, and then checks what the rule
// reports. The expected outcome comes from the constraints, not from the
// scanner.
//
// Unless a case says otherwise the intended property is Euclidean division
// of 8-bit unsigned integers: n = q*d + r with d > 0 and 0 <= r < d.

// chDivHint is an honest Euclidean quotient/remainder hint.
func chDivHint(_ *big.Int, inputs, outputs []*big.Int) error {
	if inputs[1].Sign() == 0 {
		return errors.New("division by zero")
	}
	outputs[0].QuoRem(inputs[0], inputs[1], outputs[1])
	return nil
}

var fieldModulus = ecc.BN254.ScalarField()

// fieldValue encodes a signed integer as a BN254 field element.
func fieldValue(v int64) *big.Int {
	return new(big.Int).Mod(big.NewInt(v), fieldModulus)
}

// advice substitutes fixed (q, r) outputs for a hint and records that the
// substitute ran to completion, so a rejection can be told apart from a
// failing hint.
func advice(q, r *big.Int) (solver.Hint, *atomic.Bool) {
	var completed atomic.Bool
	return func(_ *big.Int, _, outputs []*big.Int) error {
		outputs[0].Set(q)
		outputs[1].Set(r)
		completed.Store(true)
		return nil
	}, &completed
}

// accepts reports whether circuit accepts assignment when the prover
// supplies (q, r) for hint. It fails the test on any error other than an
// unsatisfied constraint.
func accepts(t *testing.T, circuit, assignment frontend.Circuit, hint solver.Hint, q, r *big.Int) bool {
	t.Helper()
	substitute, completed := advice(q, r)
	err := solve(t, circuit, assignment, solver.OverrideHint(solver.GetHintID(hint), substitute))
	if !completed.Load() {
		t.Fatalf("the substituted hint did not run to completion: %v", err)
	}
	if err != nil && !strings.Contains(err.Error(), "is not satisfied") {
		t.Fatalf("rejected for a reason other than an unsatisfied constraint: %v", err)
	}
	return err == nil
}

func requireAccepts(t *testing.T, circuit, assignment frontend.Circuit, hint solver.Hint, q, r *big.Int) {
	t.Helper()
	if !accepts(t, circuit, assignment, hint, q, r) {
		t.Fatalf("the constraints rejected q=%s r=%s", q, r)
	}
}

func requireRejects(t *testing.T, circuit, assignment frontend.Circuit, hint solver.Hint, q, r *big.Int) {
	t.Helper()
	if accepts(t, circuit, assignment, hint, q, r) {
		t.Fatalf("the constraints accepted q=%s r=%s", q, r)
	}
}

func requireHonest(t *testing.T, circuit, assignment frontend.Circuit, hint solver.Hint) {
	t.Helper()
	if err := solve(t, circuit, assignment, solver.WithHints(hint)); err != nil {
		t.Fatalf("honest witness rejected: %v", err)
	}
}

// divide asks the hint for q and r and range-checks n, d, q, and r to 8
// bits, so q*d + r <= 65,280 cannot wrap the field. It adds no remainder
// bound and does not assert d != 0.
func divide(api frontend.API, n, d frontend.Variable) (q, r frontend.Variable) {
	out, err := api.Compiler().NewHint(chDivHint, 2, n, d)
	if err != nil {
		panic(err)
	}
	q, r = out[0], out[1]
	api.ToBinary(n, 8)
	api.ToBinary(d, 8)
	api.ToBinary(q, 8)
	api.ToBinary(r, 8)
	api.AssertIsEqual(n, api.Add(api.Mul(q, d), r))
	return q, r
}

func comparator(api frontend.API) *cmp.BoundedComparator {
	return cmp.NewBoundedComparator(api, big.NewInt(255), false)
}

// chComparatorBound is the valid correction: every value is range-checked
// and a bounded comparator asserts r < d. Written out in full rather than
// through divide, so the bound sits next to the hint.
type chComparatorBound struct{ N, D frontend.Variable }

func (c *chComparatorBound) Define(api frontend.API) error {
	out, err := api.Compiler().NewHint(chDivHint, 2, c.N, c.D)
	if err != nil {
		return err
	}
	q, r := out[0], out[1]
	api.ToBinary(c.N, 8)
	api.ToBinary(c.D, 8)
	api.ToBinary(q, 8)
	api.ToBinary(r, 8)
	api.AssertIsEqual(c.N, api.Add(api.Mul(q, c.D), r))
	comparator(api).AssertIsLess(r, c.D)
	return nil
}

// chComparatorLessEq is the same correction written differently:
// AssertIsLessEq(r, d-1). gnark implements AssertIsLess(a, b) as
// AssertIsLessEq(a, b-1), so the two emit the same constraint.
type chComparatorLessEq struct{ N, D frontend.Variable }

func (c *chComparatorLessEq) Define(api frontend.API) error {
	out, err := api.Compiler().NewHint(chDivHint, 2, c.N, c.D)
	if err != nil {
		return err
	}
	q, r := out[0], out[1]
	api.ToBinary(c.N, 8)
	api.ToBinary(c.D, 8)
	api.ToBinary(q, 8)
	api.ToBinary(r, 8)
	api.AssertIsEqual(c.N, api.Add(api.Mul(q, c.D), r))
	comparator(api).AssertIsLessEq(r, api.Sub(c.D, 1))
	return nil
}

// chLessOrEqualNonzero bounds r <= d-1 with the full-field comparison and
// asserts d != 0, which that bound needs.
type chLessOrEqualNonzero struct{ N, D frontend.Variable }

func (c *chLessOrEqualNonzero) Define(api frontend.API) error {
	out, err := api.Compiler().NewHint(chDivHint, 2, c.N, c.D)
	if err != nil {
		return err
	}
	q, r := out[0], out[1]
	api.ToBinary(c.N, 8)
	api.ToBinary(c.D, 8)
	api.ToBinary(q, 8)
	api.ToBinary(r, 8)
	api.AssertIsDifferent(c.D, 0)
	api.AssertIsEqual(c.N, api.Add(api.Mul(q, c.D), r))
	api.AssertIsLessOrEqual(r, api.Sub(c.D, 1))
	return nil
}

// chLessOrEqualZeroDivisor is chLessOrEqualNonzero without d != 0. When
// d = 0, d-1 is the largest field element and r <= d-1 holds for every r.
type chLessOrEqualZeroDivisor struct{ N, D frontend.Variable }

func (c *chLessOrEqualZeroDivisor) Define(api frontend.API) error {
	out, err := api.Compiler().NewHint(chDivHint, 2, c.N, c.D)
	if err != nil {
		return err
	}
	q, r := out[0], out[1]
	api.ToBinary(c.N, 8)
	api.ToBinary(c.D, 8)
	api.ToBinary(q, 8)
	api.ToBinary(r, 8)
	api.AssertIsEqual(c.N, api.Add(api.Mul(q, c.D), r))
	api.AssertIsLessOrEqual(r, api.Sub(c.D, 1))
	return nil
}

// chBoundInHelper bounds r in a package-local helper, one call away.
type chBoundInHelper struct{ N, D frontend.Variable }

func (c *chBoundInHelper) Define(api frontend.API) error {
	out, err := api.Compiler().NewHint(chDivHint, 2, c.N, c.D)
	if err != nil {
		return err
	}
	q, r := out[0], out[1]
	api.ToBinary(c.N, 8)
	api.ToBinary(c.D, 8)
	api.ToBinary(q, 8)
	api.ToBinary(r, 8)
	api.AssertIsEqual(c.N, api.Add(api.Mul(q, c.D), r))
	assertBelow(api, r, c.D)
	return nil
}

func assertBelow(api frontend.API, r, d frontend.Variable) {
	comparator(api).AssertIsLess(r, d)
}

// chBoundTwoHelpersAway bounds r two helper calls away.
type chBoundTwoHelpersAway struct{ N, D frontend.Variable }

func (c *chBoundTwoHelpersAway) Define(api frontend.API) error {
	out, err := api.Compiler().NewHint(chDivHint, 2, c.N, c.D)
	if err != nil {
		return err
	}
	q, r := out[0], out[1]
	api.ToBinary(c.N, 8)
	api.ToBinary(c.D, 8)
	api.ToBinary(q, 8)
	api.ToBinary(r, 8)
	api.AssertIsEqual(c.N, api.Add(api.Mul(q, c.D), r))
	checkRemainder(api, r, c.D)
	return nil
}

func checkRemainder(api frontend.API, r, d frontend.Variable) {
	assertBelow(api, r, d)
}

// chBoundInCaller calls divide, whose hint has no bound, and bounds the
// remainder it returns.
type chBoundInCaller struct{ N, D frontend.Variable }

func (c *chBoundInCaller) Define(api frontend.API) error {
	_, r := divide(api, c.N, c.D)
	comparator(api).AssertIsLess(r, c.D)
	return nil
}

// chConditionalBound bounds r only when the circuit is compiled with
// Strict set.
type chConditionalBound struct {
	N, D   frontend.Variable
	Strict bool `gnark:"-"`
}

func (c *chConditionalBound) Define(api frontend.API) error {
	out, err := api.Compiler().NewHint(chDivHint, 2, c.N, c.D)
	if err != nil {
		return err
	}
	q, r := out[0], out[1]
	api.ToBinary(c.N, 8)
	api.ToBinary(c.D, 8)
	api.ToBinary(q, 8)
	api.ToBinary(r, 8)
	api.AssertIsEqual(c.N, api.Add(api.Mul(q, c.D), r))
	if c.Strict {
		comparator(api).AssertIsLess(r, c.D)
	}
	return nil
}

// chRemainderUnranged asserts r < d with a bounded comparator but does not
// range-check r. The comparator compares signed values, so r = p-3, the
// field's encoding of -3, satisfies r < 5.
type chRemainderUnranged struct{ N, D frontend.Variable }

func (c *chRemainderUnranged) Define(api frontend.API) error {
	out, err := api.Compiler().NewHint(chDivHint, 2, c.N, c.D)
	if err != nil {
		return err
	}
	q, r := out[0], out[1]
	api.ToBinary(c.N, 8)
	api.ToBinary(c.D, 8)
	api.ToBinary(q, 8)
	api.AssertIsDifferent(c.D, 0)
	api.AssertIsEqual(c.N, api.Add(api.Mul(q, c.D), r))
	comparator(api).AssertIsLess(r, c.D)
	return nil
}

// chQuotientUnranged bounds 0 <= r < d correctly but does not range-check
// q, so n = q*d + r holds modulo the field for every r in [0, d): with
// q = (n - r)/d computed in the field.
type chQuotientUnranged struct{ N, D frontend.Variable }

func (c *chQuotientUnranged) Define(api frontend.API) error {
	out, err := api.Compiler().NewHint(chDivHint, 2, c.N, c.D)
	if err != nil {
		return err
	}
	q, r := out[0], out[1]
	api.ToBinary(c.N, 8)
	api.ToBinary(c.D, 8)
	api.ToBinary(r, 8)
	api.AssertIsDifferent(c.D, 0)
	api.AssertIsEqual(c.N, api.Add(api.Mul(q, c.D), r))
	comparator(api).AssertIsLess(r, c.D)
	return nil
}

// chSignedDigitHint splits n into q*16 + r with a signed digit r in
// [-8, 8), as signed-window scalar recoding does. It is not Euclidean
// division: r is negative for about half of all n.
func chSignedDigitHint(_ *big.Int, inputs, outputs []*big.Int) error {
	n := inputs[0].Int64()
	r := (n+8)%16 - 8
	outputs[0].SetInt64((n - r) / 16)
	outputs[1].Set(fieldValue(r))
	return nil
}

// chSignedDigit constrains its own convention: r + 8 is a 4-bit value, so
// r is in [-8, 8), and q is a 5-bit value.
type chSignedDigit struct{ N frontend.Variable }

func (c *chSignedDigit) Define(api frontend.API) error {
	out, err := api.Compiler().NewHint(chSignedDigitHint, 2, c.N)
	if err != nil {
		return err
	}
	q, r := out[0], out[1]
	api.ToBinary(c.N, 8)
	api.ToBinary(q, 5)
	api.ToBinary(api.Add(r, 8), 4)
	api.AssertIsEqual(c.N, api.Add(api.Mul(q, 16), r))
	return nil
}

// chSignedDigitEuclidean adds the bound the rule asks for, r <= 15.
type chSignedDigitEuclidean struct{ N frontend.Variable }

func (c *chSignedDigitEuclidean) Define(api frontend.API) error {
	out, err := api.Compiler().NewHint(chSignedDigitHint, 2, c.N)
	if err != nil {
		return err
	}
	q, r := out[0], out[1]
	api.ToBinary(c.N, 8)
	api.ToBinary(q, 5)
	api.ToBinary(api.Add(r, 8), 4)
	api.AssertIsEqual(c.N, api.Add(api.Mul(q, 16), r))
	api.AssertIsLessOrEqual(r, 15)
	return nil
}

func TestRelationChallengeConstraints(t *testing.T) {
	q2, r7 := big.NewInt(2), big.NewInt(7) // 17 = 2*5 + 7: reconstructs, but 7 >= 5

	t.Run("1 existing example: divmod accepts 2 remainder 7, its correction does not", func(t *testing.T) {
		requireAccepts(t, &divmod.VulnerableCircuit{}, &divmod.VulnerableCircuit{N: 17, D: 5}, divmod.QuotientRemainderHint, q2, r7)
		requireRejects(t, &divmod.CorrectedCircuit{}, &divmod.CorrectedCircuit{N: 17, D: 5}, divmod.QuotientRemainderHint, q2, r7)
	})
	t.Run("2 valid correction: comparator with range checks", func(t *testing.T) {
		circuit, assignment := &chComparatorBound{}, &chComparatorBound{N: 17, D: 5}
		requireHonest(t, circuit, assignment, chDivHint)
		requireHonest(t, circuit, &chComparatorBound{N: 255, D: 255}, chDivHint)
		requireRejects(t, circuit, assignment, chDivHint, q2, r7)
		requireRejects(t, circuit, assignment, chDivHint, big.NewInt(4), fieldValue(-3)) // 17 = 4*5 - 3
		requireRejects(t, circuit, &chComparatorBound{N: 17, D: 0}, chDivHint, big.NewInt(0), big.NewInt(17))
	})
	t.Run("3 equivalent corrections: comparator r <= d-1, and full-field r <= d-1 with d != 0", func(t *testing.T) {
		requireHonest(t, &chComparatorLessEq{}, &chComparatorLessEq{N: 17, D: 5}, chDivHint)
		requireRejects(t, &chComparatorLessEq{}, &chComparatorLessEq{N: 17, D: 5}, chDivHint, q2, r7)
		requireRejects(t, &chComparatorLessEq{}, &chComparatorLessEq{N: 17, D: 5}, chDivHint, big.NewInt(4), fieldValue(-3))
		requireRejects(t, &chComparatorLessEq{}, &chComparatorLessEq{N: 17, D: 0}, chDivHint, big.NewInt(9), big.NewInt(17))
		requireHonest(t, &chLessOrEqualNonzero{}, &chLessOrEqualNonzero{N: 17, D: 5}, chDivHint)
		requireRejects(t, &chLessOrEqualNonzero{}, &chLessOrEqualNonzero{N: 17, D: 5}, chDivHint, q2, r7)
		requireRejects(t, &chLessOrEqualNonzero{}, &chLessOrEqualNonzero{N: 17, D: 5}, chDivHint, big.NewInt(4), fieldValue(-3))
		requireRejects(t, &chLessOrEqualNonzero{}, &chLessOrEqualNonzero{N: 17, D: 0}, chDivHint, big.NewInt(9), big.NewInt(17))
	})
	t.Run("4 bound in a helper or in the caller", func(t *testing.T) {
		requireRejects(t, &chBoundInHelper{}, &chBoundInHelper{N: 17, D: 5}, chDivHint, q2, r7)
		requireRejects(t, &chBoundTwoHelpersAway{}, &chBoundTwoHelpersAway{N: 17, D: 5}, chDivHint, q2, r7)
		requireRejects(t, &chBoundInCaller{}, &chBoundInCaller{N: 17, D: 5}, chDivHint, q2, r7)
	})
	t.Run("5 conditional bound: absent when compiled without Strict", func(t *testing.T) {
		requireAccepts(t, &chConditionalBound{}, &chConditionalBound{N: 17, D: 5}, chDivHint, q2, r7)
		requireRejects(t, &chConditionalBound{Strict: true}, &chConditionalBound{N: 17, D: 5}, chDivHint, q2, r7)
	})
	t.Run("6 zero divisor: r <= d-1 without d != 0 accepts d = 0 with any q", func(t *testing.T) {
		for _, q := range []int64{0, 9, 255} {
			requireAccepts(t, &chLessOrEqualZeroDivisor{}, &chLessOrEqualZeroDivisor{N: 17, D: 0}, chDivHint, big.NewInt(q), big.NewInt(17))
		}
		// With d != 0 it rejects both d = 0 and the noncanonical pair.
		requireRejects(t, &chLessOrEqualZeroDivisor{}, &chLessOrEqualZeroDivisor{N: 17, D: 5}, chDivHint, q2, r7)
	})
	t.Run("7a insufficient bounds: comparator without a range check of r accepts r = -3", func(t *testing.T) {
		requireAccepts(t, &chRemainderUnranged{}, &chRemainderUnranged{N: 17, D: 5}, chDivHint, big.NewInt(4), fieldValue(-3))
	})
	t.Run("7b insufficient bounds: r < d without a range check of q accepts q = 17/5 in the field", func(t *testing.T) {
		q := new(big.Int).Mul(big.NewInt(17), new(big.Int).ModInverse(big.NewInt(5), fieldModulus))
		q.Mod(q, fieldModulus)
		requireAccepts(t, &chQuotientUnranged{}, &chQuotientUnranged{N: 17, D: 5}, chDivHint, q, big.NewInt(0))
	})
	t.Run("8 non-Euclidean hint: signed digits are enforced, and r < d would reject honest witnesses", func(t *testing.T) {
		for _, n := range []int64{0, 7, 8, 23, 25, 255} {
			requireHonest(t, &chSignedDigit{}, &chSignedDigit{N: n}, chSignedDigitHint)
		}
		// 25 = 2*16 - 7 is the honest pair; the Euclidean 25 = 1*16 + 9 is not
		// in [-8, 8), and the circuit rejects it.
		requireRejects(t, &chSignedDigit{}, &chSignedDigit{N: 25}, chSignedDigitHint, big.NewInt(1), big.NewInt(9))
		requireRejects(t, &chSignedDigitEuclidean{}, &chSignedDigitEuclidean{N: 25}, chSignedDigitHint, big.NewInt(2), fieldValue(-7))
	})
}

// wantFinding is the rule's expected verdict on one function.
type wantFinding struct {
	confidence string // "" means no finding
	message    string // a fragment of the message
}

func TestRelationChallengeScanner(t *testing.T) {
	scanOnce.Do(func() {
		scanResult, scanErr = analyzer.ScanContext(context.Background(), "../..", []string{"./internal/witness"}, analyzer.Options{IncludeTests: true})
	})
	if scanErr != nil {
		t.Fatal(scanErr)
	}
	demo, err := analyzer.ScanContext(context.Background(), "../..", []string{"./examples/divmod"}, analyzer.Options{IncludeExamples: true})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]report.Finding{}
	for _, f := range append(append([]report.Finding(nil), scanResult.Findings...), demo.Findings...) {
		if f.RuleID == rules.HintRelationIncomplete {
			got[f.Function] = f
		}
	}
	for function, want := range map[string]wantFinding{
		"(*VulnerableCircuit).Define":    {"high", "enforceCanonicalRemainder=false"},
		"(*CorrectedCircuit).Define":     {},
		"(*chComparatorBound).Define":    {},
		"(*chComparatorLessEq).Define":   {},
		"(*chLessOrEqualNonzero).Define": {},
		"(*chBoundInHelper).Define":      {},
		// The rule cannot see bounds two helpers away or in a caller. It
		// still reports, but says so and lowers its confidence.
		"(*chBoundTwoHelpersAway).Define":    {"medium", "is passed to checkRemainder"},
		"divide":                             {"medium", "is returned to the caller"},
		"(*chConditionalBound).Define":       {"medium", "may not run"},
		"(*chLessOrEqualZeroDivisor).Define": {"medium", "d = 0"},
		"(*chRemainderUnranged).Define":      {"high", "no range check of r"},
		// Known false negative: the rule checks the remainder bound only.
		// The quotient's range is reported through field_safety below.
		"(*chQuotientUnranged).Define": {},
		"(*chSignedDigit).Define":      {"medium", "whose result this rule does not follow"},
	} {
		f, reported := got[function]
		switch {
		case want.confidence == "" && reported:
			t.Errorf("%s: unexpected finding: %s", function, f.Message)
		case want.confidence != "" && !reported:
			t.Errorf("%s: no finding, want a %s-confidence one mentioning %q", function, want.confidence, want.message)
		case reported && (f.Severity != report.SeverityHigh || f.Confidence != want.confidence || !strings.Contains(f.Message, want.message)):
			t.Errorf("%s: got %s/%s %q, want high/%s mentioning %q", function, f.Severity, f.Confidence, f.Message, want.confidence, want.message)
		}
	}
	for _, h := range scanResult.Hints {
		if h.Function != "(*chQuotientUnranged).Define" {
			continue
		}
		for _, invariant := range h.Invariants {
			if invariant.Kind == "field_safety" && (invariant.Status == report.InvariantSatisfied || !strings.Contains(strings.Join(invariant.Evidence, " "), "no range check of q")) {
				t.Errorf("field_safety must name the unranged quotient: %#v", invariant)
			}
		}
	}
}
