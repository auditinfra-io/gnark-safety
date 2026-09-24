package gnarksafety

import (
	"math/big"
	"sort"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

func compileCircuit(t *testing.T, circuit frontend.Circuit) constraint.ConstraintSystem {
	t.Helper()
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit)
	if err != nil {
		t.Fatalf("compile circuit: %v", err)
	}
	return ccs
}

// successfulHint wraps adversarial advice so a rejection test can distinguish
// an unsatisfied constraint from a failure to invoke or execute the hint.
func successfulHint(hint solver.Hint) (solver.Hint, *atomic.Bool) {
	var completed atomic.Bool
	return func(field *big.Int, inputs, outputs []*big.Int) error {
		if err := hint(field, inputs, outputs); err != nil {
			return err
		}
		completed.Store(true)
		return nil
	}, &completed
}

func requireConstraintRejection(t *testing.T, err error, hintCompleted *atomic.Bool) {
	t.Helper()
	if !hintCompleted.Load() {
		t.Fatal("adversarial hint did not run to successful completion")
	}
	if err == nil {
		t.Fatal("circuit accepted adversarial hint output")
	}
	if message := err.Error(); !strings.Contains(message, "constraint") || !strings.Contains(message, "is not satisfied") {
		t.Fatalf("expected an unsatisfied-constraint error, got: %v", err)
	}
}

func solve(t *testing.T, ccs constraint.ConstraintSystem, assignment frontend.Circuit, opts ...solver.Option) error {
	t.Helper()
	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatalf("build witness: %v", err)
	}
	return ccs.IsSolved(witness, opts...)
}

func TestRequiredHintSafetyMatrix(t *testing.T) {
	vulnerable := compileCircuit(t, &VulnerableCircuit{})
	corrected := compileCircuit(t, &CorrectedCircuit{})
	validVulnerable := &VulnerableCircuit{N: 17, D: 5}
	validCorrected := &CorrectedCircuit{N: 17, D: 5}
	override := solver.OverrideHint(solver.GetHintID(QuotientRemainderHint), InvalidQuotientRemainderHint)

	t.Run("A vulnerable accepts valid output", func(t *testing.T) {
		if err := solve(t, vulnerable, validVulnerable, solver.WithHints(QuotientRemainderHint)); err != nil {
			t.Fatalf("valid output rejected: %v", err)
		}
	})
	t.Run("B corrected accepts valid output", func(t *testing.T) {
		if err := solve(t, corrected, validCorrected, solver.WithHints(QuotientRemainderHint)); err != nil {
			t.Fatalf("valid output rejected: %v", err)
		}
	})
	t.Run("C vulnerable accepts invalid output", func(t *testing.T) {
		outputs := []*big.Int{new(big.Int), new(big.Int)}
		if err := InvalidQuotientRemainderHint(nil, []*big.Int{big.NewInt(17), big.NewInt(5)}, outputs); err != nil {
			t.Fatal(err)
		}
		reconstructed := new(big.Int).Add(new(big.Int).Mul(outputs[0], big.NewInt(5)), outputs[1])
		if reconstructed.Cmp(big.NewInt(17)) != 0 {
			t.Fatalf("test fixture does not preserve reconstruction: got %s", reconstructed)
		}
		if outputs[1].Cmp(big.NewInt(5)) < 0 {
			t.Fatalf("test fixture is not adversarial: remainder %s is less than divisor 5", outputs[1])
		}
		if err := solve(t, vulnerable, validVulnerable, override); err != nil {
			t.Fatalf("underconstrained circuit rejected reconstruction-preserving output: %v", err)
		}
	})
	t.Run("D corrected rejects identical invalid output", func(t *testing.T) {
		tracked, completed := successfulHint(InvalidQuotientRemainderHint)
		override := solver.OverrideHint(solver.GetHintID(QuotientRemainderHint), tracked)
		err := solve(t, corrected, validCorrected, override)
		requireConstraintRejection(t, err, completed)
	})
}

func TestBoundaryControls(t *testing.T) {
	cases := []struct {
		name string
		n, d int
	}{
		{name: "exact division", n: 20, d: 5},
		{name: "n less than d", n: 3, d: 5},
		{name: "lower in-range", n: 0, d: 1},
		{name: "upper in-range exact", n: 255, d: 255},
		{name: "largest quotient", n: 255, d: 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fixtures := []struct {
				name       string
				circuit    frontend.Circuit
				assignment frontend.Circuit
			}{
				{name: "vulnerable", circuit: &VulnerableCircuit{}, assignment: &VulnerableCircuit{N: tc.n, D: tc.d}},
				{name: "corrected", circuit: &CorrectedCircuit{}, assignment: &CorrectedCircuit{N: tc.n, D: tc.d}},
			}
			for _, fixture := range fixtures {
				t.Run(fixture.name, func(t *testing.T) {
					ccs := compileCircuit(t, fixture.circuit)
					if err := solve(t, ccs, fixture.assignment, solver.WithHints(QuotientRemainderHint)); err != nil {
						t.Fatalf("n=%d d=%d rejected: %v", tc.n, tc.d, err)
					}
				})
			}
		})
	}
}

func TestAdversarialSafetyMatrix(t *testing.T) {
	cases := []struct {
		name       string
		n, d, q, r int64
		vulnerable bool
	}{
		{name: "remainder equals divisor", n: 15, d: 5, q: 2, r: 5, vulnerable: true},
		{name: "remainder greater than divisor", n: 17, d: 2, q: 7, r: 3, vulnerable: true},
		{name: "divisor one", n: 255, d: 1, q: 254, r: 1, vulnerable: true},
		{name: "quotient zero", n: 3, d: 2, q: 0, r: 3, vulnerable: true},
		{name: "n less than d", n: 3, d: 5, q: 0, r: 3, vulnerable: true},
		{name: "outside eight bits", n: 255, d: 255, q: -1, r: 510, vulnerable: false},
		{name: "negative output", n: 0, d: 2, q: -1, r: 2, vulnerable: false},
	}

	vulnerable := compileCircuit(t, &VulnerableCircuit{})
	corrected := compileCircuit(t, &CorrectedCircuit{})
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hint := fixedHint(tc.n, tc.d, tc.q, tc.r)
			override := solver.OverrideHint(solver.GetHintID(QuotientRemainderHint), hint)
			vulnerableErr := solve(t, vulnerable, &VulnerableCircuit{N: tc.n, D: tc.d}, override)
			if tc.vulnerable && vulnerableErr != nil {
				t.Fatalf("vulnerable circuit should accept reconstruction-preserving advice: %v", vulnerableErr)
			}
			if !tc.vulnerable && vulnerableErr == nil {
				t.Fatal("vulnerable circuit accepted advice that violates a constrained property")
			}
			tracked, completed := successfulHint(hint)
			override = solver.OverrideHint(solver.GetHintID(QuotientRemainderHint), tracked)
			err := solve(t, corrected, &CorrectedCircuit{N: tc.n, D: tc.d}, override)
			if tc.name == "n less than d" {
				if err != nil {
					t.Fatalf("canonical quotient-zero advice rejected: %v", err)
				}
				return
			}
			requireConstraintRejection(t, err, completed)
		})
	}
}

// TestHintMutationMatrix treats hint advice as prover-controlled and exercises
// every output, declared integer boundary, and the native field boundary. The
// coverage guard in hint_inventory_test.go requires each source NewHint call to
// have a registered target that runs this reusable matrix.
func TestHintMutationMatrix(t *testing.T) {
	var names []string
	for name := range mutationTargets {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		t.Run(name, mutationTargets[name])
	}
}

func testQuotientRemainderHintMutations(t *testing.T) {
	field := ecc.BN254.ScalarField()
	vulnerable := compileCircuit(t, &VulnerableCircuit{})
	corrected := compileCircuit(t, &CorrectedCircuit{})
	assignmentVulnerable := &VulnerableCircuit{N: 17, D: 5}
	assignmentCorrected := &CorrectedCircuit{N: 17, D: 5}

	classes := make(map[hintMutationClass]bool)
	for _, mutation := range quotientRemainderMutations(field) {
		mutation := mutation
		classes[mutation.class] = true
		t.Run(string(mutation.class)+"/"+mutation.name, func(t *testing.T) {
			hint := bigIntHint(integer(17), integer(5), mutation.q, mutation.r)
			override := solver.OverrideHint(solver.GetHintID(QuotientRemainderHint), hint)
			vulnerableErr := solve(t, vulnerable, assignmentVulnerable, override)
			if got := vulnerableErr == nil; got != mutation.vulnerableShouldAccept {
				t.Fatalf("vulnerable acceptance=%t, want %t (error: %v)", got, mutation.vulnerableShouldAccept, vulnerableErr)
			}

			tracked, completed := successfulHint(hint)
			override = solver.OverrideHint(solver.GetHintID(QuotientRemainderHint), tracked)
			correctedErr := solve(t, corrected, assignmentCorrected, override)
			if got := correctedErr == nil; got != mutation.correctedShouldAccept {
				t.Fatalf("corrected acceptance=%t, want %t (error: %v)", got, mutation.correctedShouldAccept, correctedErr)
			}
			if !completed.Load() {
				t.Fatal("mutation hint did not run to successful completion")
			}
		})
	}

	for _, class := range []hintMutationClass{mutationHonest, mutationSingleOutput, mutationNonCanonical, mutationNegative, mutationOutsideDeclaredBits, mutationFieldBoundary} {
		if !classes[class] {
			t.Fatalf("mutation corpus does not exercise %q", class)
		}
	}
}

func FuzzQuotientRemainderHint(f *testing.F) {
	for _, seed := range [][2]uint8{{0, 1}, {17, 5}, {255, 1}, {255, 254}, {255, 255}} {
		f.Add(seed[0], seed[1])
	}
	f.Fuzz(func(t *testing.T, n, d uint8) {
		inputs := []*big.Int{new(big.Int).SetUint64(uint64(n)), new(big.Int).SetUint64(uint64(d))}
		outputs := []*big.Int{new(big.Int), new(big.Int)}
		err := QuotientRemainderHint(nil, inputs, outputs)
		if d == 0 {
			if err == nil {
				t.Fatal("zero divisor unexpectedly succeeded")
			}
			return
		}
		if err != nil {
			t.Fatalf("valid inputs failed: %v", err)
		}
		reconstructed := new(big.Int).Add(new(big.Int).Mul(outputs[0], inputs[1]), outputs[1])
		if reconstructed.Cmp(inputs[0]) != 0 || outputs[1].Sign() < 0 || outputs[1].Cmp(inputs[1]) >= 0 {
			t.Fatalf("invalid q=%s r=%s for n=%d d=%d", outputs[0], outputs[1], n, d)
		}
	})
}

func TestZeroDivisorRejected(t *testing.T) {
	ccs := compileCircuit(t, &VulnerableCircuit{})
	tracked, completed := successfulHint(ZeroDivisorHint)
	override := solver.OverrideHint(solver.GetHintID(QuotientRemainderHint), tracked)
	err := solve(t, ccs, &VulnerableCircuit{N: 17, D: 0}, override)
	requireConstraintRejection(t, err, completed)
}
