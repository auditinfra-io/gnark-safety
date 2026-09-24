package divmod

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/test/unsafekzg"
)

func proveAndVerify(t *testing.T, circuit, assignment frontend.Circuit, opts ...solver.Option) {
	t.Helper()
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	fullWitness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatalf("full witness: %v", err)
	}
	publicWitness, err := fullWitness.Public()
	if err != nil {
		t.Fatalf("public witness: %v", err)
	}
	proof, err := groth16.Prove(ccs, pk, fullWitness, backend.WithSolverOptions(opts...))
	if err != nil {
		t.Fatalf("prove: %v", err)
	}
	if err := groth16.Verify(proof, vk, publicWitness); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestGroth16VulnerableInvalidHintProofVerifies(t *testing.T) {
	override := solver.OverrideHint(solver.GetHintID(QuotientRemainderHint), InvalidQuotientRemainderHint)
	proveAndVerify(t, &VulnerableCircuit{}, &VulnerableCircuit{N: 17, D: 5}, override)
}

func TestGroth16CorrectedValidHintProofVerifies(t *testing.T) {
	proveAndVerify(t, &CorrectedCircuit{}, &CorrectedCircuit{N: 17, D: 5}, solver.WithHints(QuotientRemainderHint))
}

func TestGroth16CorrectedInvalidHintCannotProve(t *testing.T) {
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &CorrectedCircuit{})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	pk, _, err := groth16.Setup(ccs)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	witness, err := frontend.NewWitness(&CorrectedCircuit{N: 17, D: 5}, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatalf("witness: %v", err)
	}
	tracked, completed := successfulHint(InvalidQuotientRemainderHint)
	override := solver.OverrideHint(solver.GetHintID(QuotientRemainderHint), tracked)
	_, err = groth16.Prove(ccs, pk, witness, backend.WithSolverOptions(override))
	requireConstraintRejection(t, err, completed)
}

func TestCorrectedProofBackendCurveMatrix(t *testing.T) {
	for _, curve := range []ecc.ID{ecc.BN254, ecc.BLS12_381} {
		t.Run(curve.String(), func(t *testing.T) {
			t.Run("groth16", func(t *testing.T) {
				ccs, err := frontend.Compile(curve.ScalarField(), r1cs.NewBuilder, &CorrectedCircuit{})
				if err != nil {
					t.Fatal(err)
				}
				full, public := matrixWitnesses(t, curve)
				pk, vk, err := groth16.Setup(ccs)
				if err != nil {
					t.Fatal(err)
				}
				proof, err := groth16.Prove(ccs, pk, full, backend.WithSolverOptions(solver.WithHints(QuotientRemainderHint)))
				if err != nil {
					t.Fatal(err)
				}
				if err := groth16.Verify(proof, vk, public); err != nil {
					t.Fatal(err)
				}
			})
			t.Run("plonk", func(t *testing.T) {
				ccs, err := frontend.Compile(curve.ScalarField(), scs.NewBuilder, &CorrectedCircuit{})
				if err != nil {
					t.Fatal(err)
				}
				full, public := matrixWitnesses(t, curve)
				srs, srsLagrange, err := unsafekzg.NewSRS(ccs)
				if err != nil {
					t.Fatal(err)
				}
				pk, vk, err := plonk.Setup(ccs, srs, srsLagrange)
				if err != nil {
					t.Fatal(err)
				}
				proof, err := plonk.Prove(ccs, pk, full, backend.WithSolverOptions(solver.WithHints(QuotientRemainderHint)))
				if err != nil {
					t.Fatal(err)
				}
				if err := plonk.Verify(proof, vk, public); err != nil {
					t.Fatal(err)
				}
			})
		})
	}
}

func matrixWitnesses(t *testing.T, curve ecc.ID) (witness.Witness, witness.Witness) {
	t.Helper()
	full, err := frontend.NewWitness(&CorrectedCircuit{N: 17, D: 5}, curve.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	public, err := full.Public()
	if err != nil {
		t.Fatal(err)
	}
	return full, public
}
