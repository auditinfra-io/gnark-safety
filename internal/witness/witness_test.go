package witness

import (
	"context"
	"math/big"
	"strings"
	"sync"
	"testing"

	"github.com/auditinfra-io/gnark-safety/internal/analyzer"
	"github.com/auditinfra-io/gnark-safety/internal/rules"
	"github.com/auditinfra-io/gnark-safety/pkg/report"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/math/bits"
)

// witnesses maps each high rule to its executable witness.
var witnesses = map[string]func(*testing.T){
	rules.TagVisibilityAsName:  testTagVisibility,
	rules.GoEqualityOnVariable: testGoEquality,
	rules.DiscardedPredicate:   testDiscardedPredicate,
	rules.VacuousAssert:        testVacuousAssert,
	rules.BitsUnconstrained:    testBitsUnconstrained,
}

// externalWitnesses names high rules whose witness lives elsewhere.
var externalWitnesses = map[string]string{
	rules.HintRelationIncomplete: "examples/divmod: TestRequiredHintSafetyMatrix and TestGroth16 (noncanonical quotient/remainder accepted, then rejected once r < d is enforced)",
}

func TestEveryHighRuleHasAWitness(t *testing.T) {
	for _, spec := range rules.All() {
		if spec.DefaultSeverity().Rank() < report.SeverityHigh.Rank() {
			continue
		}
		if witnesses[spec.ID] == nil && externalWitnesses[spec.ID] == "" {
			t.Errorf("%s is high severity but has no executable witness", spec.ID)
		}
	}
}

func TestWitnesses(t *testing.T) {
	for id, witness := range witnesses {
		t.Run(id, witness)
	}
}

// --- shared helpers ---

func compile(t *testing.T, circuit frontend.Circuit) constraint.ConstraintSystem {
	t.Helper()
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit)
	if err != nil {
		t.Fatalf("compile %T: %v", circuit, err)
	}
	return ccs
}

func solve(t *testing.T, circuit, assignment frontend.Circuit, opts ...solver.Option) error {
	t.Helper()
	w, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatalf("witness: %v", err)
	}
	return compile(t, circuit).IsSolved(w, opts...)
}

// requireDivergence checks the core claim of a witness: the reported
// circuit accepts the invalid assignment and the corrected one rejects it.
func requireDivergence(t *testing.T, vulnerable, fixed error) {
	t.Helper()
	if vulnerable != nil {
		t.Fatalf("reported circuit rejected the invalid witness: %v", vulnerable)
	}
	if fixed == nil {
		t.Fatal("corrected circuit accepted the invalid witness")
	}
	if !strings.Contains(fixed.Error(), "is not satisfied") {
		t.Fatalf("corrected circuit failed for a reason other than an unsatisfied constraint: %v", fixed)
	}
}

var (
	scanOnce   sync.Once
	scanResult report.Report
	scanErr    error
)

// requireReported checks the analyzer reports rule for the vulnerable
// function and nothing for the corrected one.
func requireReported(t *testing.T, rule, vulnerable, fixed string) {
	t.Helper()
	scanOnce.Do(func() {
		scanResult, scanErr = analyzer.ScanContext(context.Background(), "../..", []string{"./internal/witness"}, analyzer.Options{IncludeTests: true})
	})
	if scanErr != nil {
		t.Fatal(scanErr)
	}
	found := false
	for _, f := range scanResult.Findings {
		if f.Function == fixed {
			t.Errorf("corrected %s is reported: %s %s", fixed, f.RuleID, f.Message)
		}
		if f.Function == vulnerable && f.RuleID == rule && f.Severity == report.SeverityHigh {
			found = true
		}
	}
	if !found {
		t.Errorf("%s is not reported as high %s", vulnerable, rule)
	}
}

// --- GNARK_TAG_VISIBILITY_AS_NAME ---

type tagVulnerable struct {
	Threshold frontend.Variable `gnark:"public"`
	Balance   frontend.Variable
}

func (c *tagVulnerable) Define(api frontend.API) error {
	api.AssertIsLessOrEqual(c.Balance, c.Threshold)
	return nil
}

type tagFixed struct {
	Threshold frontend.Variable `gnark:",public"`
	Balance   frontend.Variable
}

func (c *tagFixed) Define(api frontend.API) error {
	api.AssertIsLessOrEqual(c.Balance, c.Threshold)
	return nil
}

// The verifier means to check "balance <= 100". With the tag typo the
// threshold is secret, so a prover who picks threshold 1000 produces a
// Groth16 proof that verifies against the verifier's public input 100.
func testTagVisibility(t *testing.T) {
	requireReported(t, rules.TagVisibilityAsName, "tagVulnerable", "tagFixed")
	verify := func(circuit, proverAssignment, verifierAssignment frontend.Circuit) (int, error) {
		ccs := compile(t, circuit)
		pk, vk, err := groth16.Setup(ccs)
		if err != nil {
			t.Fatal(err)
		}
		full, err := frontend.NewWitness(proverAssignment, ecc.BN254.ScalarField())
		if err != nil {
			t.Fatal(err)
		}
		proof, err := groth16.Prove(ccs, pk, full)
		if err != nil {
			t.Fatalf("prove: %v", err)
		}
		public, err := frontend.NewWitness(verifierAssignment, ecc.BN254.ScalarField(), frontend.PublicOnly())
		if err != nil {
			t.Fatal(err)
		}
		return ccs.GetNbPublicVariables(), groth16.Verify(proof, vk, public)
	}
	vulnerablePublic, vulnerable := verify(&tagVulnerable{}, &tagVulnerable{Threshold: 1000, Balance: 500}, &tagVulnerable{Threshold: 100})
	fixedPublic, fixed := verify(&tagFixed{}, &tagFixed{Threshold: 1000, Balance: 500}, &tagFixed{Threshold: 100})
	if vulnerablePublic != 1 || fixedPublic != 2 {
		t.Fatalf("public variables: vulnerable %d (want only the constant 1), fixed %d (want 2)", vulnerablePublic, fixedPublic)
	}
	if vulnerable != nil {
		t.Fatalf("proof for threshold 1000 should verify against the vulnerable circuit's empty public input: %v", vulnerable)
	}
	if fixed == nil {
		t.Fatal("proof for threshold 1000 verified against public threshold 100 in the corrected circuit")
	}
}

// --- GNARK_GO_EQUALITY_ON_VARIABLE ---

type equalityVulnerable struct {
	Flag, X, Y, Sum frontend.Variable
}

// Define means "if Flag is set, X must equal Y", but decides it in Go.
func (c *equalityVulnerable) Define(api frontend.API) error {
	api.AssertIsBoolean(c.Flag)
	api.AssertIsEqual(c.Sum, api.Add(c.X, c.Y))
	if c.Flag == 1 {
		api.AssertIsEqual(c.X, c.Y)
	}
	return nil
}

type equalityFixed struct {
	Flag, X, Y, Sum frontend.Variable
}

func (c *equalityFixed) Define(api frontend.API) error {
	api.AssertIsBoolean(c.Flag)
	api.AssertIsEqual(c.Sum, api.Add(c.X, c.Y))
	api.AssertIsEqual(api.Mul(c.Flag, api.Sub(c.X, c.Y)), 0)
	return nil
}

func testGoEquality(t *testing.T) {
	requireReported(t, rules.GoEqualityOnVariable, "(*equalityVulnerable).Define", "(*equalityFixed).Define")
	requireDivergence(t,
		solve(t, &equalityVulnerable{}, &equalityVulnerable{Flag: 1, X: 2, Y: 3, Sum: 5}),
		solve(t, &equalityFixed{}, &equalityFixed{Flag: 1, X: 2, Y: 3, Sum: 5}))
	if err := solve(t, &equalityFixed{}, &equalityFixed{Flag: 1, X: 2, Y: 2, Sum: 4}); err != nil {
		t.Fatalf("corrected circuit rejected an honest witness: %v", err)
	}
}

// --- GNARK_DISCARDED_PREDICATE ---

type discardedVulnerable struct{ X frontend.Variable }

// Define means "X must be zero" but drops the predicate's result.
func (c *discardedVulnerable) Define(api frontend.API) error {
	api.IsZero(c.X)
	return nil
}

type discardedFixed struct{ X frontend.Variable }

func (c *discardedFixed) Define(api frontend.API) error {
	api.AssertIsEqual(api.IsZero(c.X), 1)
	return nil
}

func testDiscardedPredicate(t *testing.T) {
	requireReported(t, rules.DiscardedPredicate, "(*discardedVulnerable).Define", "(*discardedFixed).Define")
	requireDivergence(t,
		solve(t, &discardedVulnerable{}, &discardedVulnerable{X: 5}),
		solve(t, &discardedFixed{}, &discardedFixed{X: 5}))
}

// --- GNARK_VACUOUS_ASSERT ---

type vacuousVulnerable struct{ X, Y, Total frontend.Variable }

// Define means "X equals Y and they sum to Total" but compares Y with Y.
func (c *vacuousVulnerable) Define(api frontend.API) error {
	api.AssertIsEqual(c.Total, api.Add(c.X, c.Y))
	api.AssertIsEqual(c.Y, c.Y)
	return nil
}

type vacuousFixed struct{ X, Y, Total frontend.Variable }

func (c *vacuousFixed) Define(api frontend.API) error {
	api.AssertIsEqual(c.Total, api.Add(c.X, c.Y))
	api.AssertIsEqual(c.X, c.Y)
	return nil
}

func testVacuousAssert(t *testing.T) {
	requireReported(t, rules.VacuousAssert, "(*vacuousVulnerable).Define", "(*vacuousFixed).Define")
	requireDivergence(t,
		solve(t, &vacuousVulnerable{}, &vacuousVulnerable{X: 1, Y: 3, Total: 4}),
		solve(t, &vacuousFixed{}, &vacuousFixed{X: 1, Y: 3, Total: 4}))
}

// --- GNARK_BITS_UNCONSTRAINED ---

type bitsVulnerable struct {
	X frontend.Variable `gnark:",public"`
}

// Define means "X is an even byte" but leaves the digits unconstrained.
func (c *bitsVulnerable) Define(api frontend.API) error {
	b := bits.ToBinary(api, c.X, bits.WithNbDigits(8), bits.WithUnconstrainedOutputs())
	api.AssertIsEqual(b[0], 0)
	return nil
}

type bitsFixed struct {
	X frontend.Variable `gnark:",public"`
}

func (c *bitsFixed) Define(api frontend.API) error {
	b := bits.ToBinary(api, c.X, bits.WithNbDigits(8))
	api.AssertIsEqual(b[0], 0)
	return nil
}

// nonBooleanDigits decomposes x as 0 + 2*(x/2) with the division taken in
// the field: the weighted sum is right, the digits are not bits.
func nonBooleanDigits(field *big.Int, inputs, outputs []*big.Int) error {
	half := new(big.Int).ModInverse(big.NewInt(2), field)
	for i := range outputs {
		outputs[i].SetUint64(0)
	}
	outputs[1].Mul(inputs[0], half).Mod(outputs[1], field)
	return nil
}

func testBitsUnconstrained(t *testing.T) {
	requireReported(t, rules.BitsUnconstrained, "(*bitsVulnerable).Define", "(*bitsFixed).Define")
	var decompose solver.Hint
	for _, hint := range bits.GetHints() {
		if strings.HasSuffix(solver.GetHintName(hint), ".nBits") {
			decompose = hint
		}
	}
	if decompose == nil {
		t.Fatal("bits decomposition hint not found")
	}
	override := solver.OverrideHint(solver.GetHintID(decompose), nonBooleanDigits)
	// 257 is odd and does not fit in a byte.
	requireDivergence(t,
		solve(t, &bitsVulnerable{}, &bitsVulnerable{X: 257}, override),
		solve(t, &bitsFixed{}, &bitsFixed{X: 257}, override))
}
