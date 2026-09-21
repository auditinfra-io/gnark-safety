package hintsafetydemo

import (
	"math/big"
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
		if err := solve(t, corrected, validCorrected, override); err == nil {
			t.Fatal("corrected circuit accepted r=7 with d=5; expected r<d constraint failure")
		}
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

func TestZeroDivisorRejected(t *testing.T) {
	fixtures := []struct {
		name       string
		circuit    frontend.Circuit
		assignment frontend.Circuit
	}{
		{name: "vulnerable", circuit: &VulnerableCircuit{}, assignment: &VulnerableCircuit{N: 17, D: 0}},
		{name: "corrected", circuit: &CorrectedCircuit{}, assignment: &CorrectedCircuit{N: 17, D: 0}},
	}
	for _, fixture := range fixtures {
		t.Run(fixture.name, func(t *testing.T) {
			ccs := compileCircuit(t, fixture.circuit)
			if err := solve(t, ccs, fixture.assignment, solver.WithHints(QuotientRemainderHint)); err == nil {
				t.Fatal("zero divisor unexpectedly satisfied the circuit")
			}
		})
	}
}
