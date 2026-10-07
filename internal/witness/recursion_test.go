package witness

import (
	"testing"

	"github.com/auditinfra-io/gnark-safety/internal/rules"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	"github.com/consensys/gnark/std/math/emulated"
	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"
)

// --- GNARK_RECURSION_WITNESS_UNVERIFIED ---

// The witness is registered here so that the table in witness_test.go
// stays as it is.
func init() {
	witnesses[rules.RecursionUnverified] = testRecursionUnverified
}

type (
	innerProof   = stdgroth16.Proof[sw_bls12377.G1Affine, sw_bls12377.G2Affine]
	innerKey     = stdgroth16.VerifyingKey[sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT]
	innerWitness = stdgroth16.Witness[sw_bls12377.ScalarField]
	innerScalar  = emulated.Element[sw_bls12377.ScalarField]
)

// squareCircuit is the inner statement: the prover knows a square root of
// Square.
type squareCircuit struct {
	Root   frontend.Variable
	Square frontend.Variable `gnark:",public"`
}

func (c *squareCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(api.Mul(c.Root, c.Root), c.Square)
	return nil
}

type recursionVulnerable struct {
	VerifyingKey innerKey `gnark:"-"`
	Proof        innerProof
	Witness      innerWitness
	Square       innerScalar `gnark:",public"`
}

// Define means "an inner proof shows that Square has a square root" but
// never verifies the proof, so Witness.Public is whatever the prover says.
func (c *recursionVulnerable) Define(api frontend.API) error {
	f, err := emulated.NewField[sw_bls12377.ScalarField](api)
	if err != nil {
		return err
	}
	f.AssertIsEqual(&c.Witness.Public[0], &c.Square)
	return nil
}

type recursionFixed struct {
	VerifyingKey innerKey `gnark:"-"`
	Proof        innerProof
	Witness      innerWitness
	Square       innerScalar `gnark:",public"`
}

func (c *recursionFixed) Define(api frontend.API) error {
	verifier, err := stdgroth16.NewVerifier[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT](api)
	if err != nil {
		return err
	}
	f, err := emulated.NewField[sw_bls12377.ScalarField](api)
	if err != nil {
		return err
	}
	f.AssertIsEqual(&c.Witness.Public[0], &c.Square)
	return verifier.AssertProof(c.VerifyingKey, c.Proof, c.Witness)
}

func testRecursionUnverified(t *testing.T) {
	requireReported(t, rules.RecursionUnverified, "(*recursionVulnerable).Define", "(*recursionFixed).Define")

	// A real inner proof that 9 has a square root, on BLS12-377 so that the
	// outer circuits verify it natively on BW6-761.
	inner, err := frontend.Compile(ecc.BLS12_377.ScalarField(), r1cs.NewBuilder, &squareCircuit{})
	if err != nil {
		t.Fatalf("compile inner: %v", err)
	}
	pk, vk, err := groth16.Setup(inner)
	if err != nil {
		t.Fatalf("setup inner: %v", err)
	}
	full, err := frontend.NewWitness(&squareCircuit{Root: 3, Square: 9}, ecc.BLS12_377.ScalarField())
	if err != nil {
		t.Fatalf("inner witness: %v", err)
	}
	proof, err := groth16.Prove(inner, pk, full, stdgroth16.GetNativeProverOptions(ecc.BW6_761.ScalarField(), ecc.BLS12_377.ScalarField()))
	if err != nil {
		t.Fatalf("prove inner: %v", err)
	}
	public, err := full.Public()
	if err != nil {
		t.Fatalf("inner public witness: %v", err)
	}
	key, err := stdgroth16.ValueOfVerifyingKeyFixed[sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT](vk)
	if err != nil {
		t.Fatalf("verifying key: %v", err)
	}
	proofValue, err := stdgroth16.ValueOfProof[sw_bls12377.G1Affine, sw_bls12377.G2Affine](proof)
	if err != nil {
		t.Fatalf("proof value: %v", err)
	}
	honest, err := stdgroth16.ValueOfWitness[sw_bls12377.ScalarField](public)
	if err != nil {
		t.Fatalf("witness value: %v", err)
	}
	// The forged claim reuses the proof for 9 to claim the statement for 10,
	// which that proof does not show.
	forged := innerWitness{Public: []innerScalar{emulated.ValueOf[sw_bls12377.ScalarField](10)}}

	placeholderProof := stdgroth16.PlaceholderProof[sw_bls12377.G1Affine, sw_bls12377.G2Affine](inner)
	placeholderWitness := stdgroth16.PlaceholderWitness[sw_bls12377.ScalarField](inner)
	// gnark refuses to compile the vulnerable circuit by default, because
	// its proof is unused; the option stands for any build where that check
	// does not fire.
	vulnerable := compileOuter(t, &recursionVulnerable{VerifyingKey: key, Proof: placeholderProof, Witness: placeholderWitness}, frontend.IgnoreUnconstrainedInputs())
	fixed := compileOuter(t, &recursionFixed{VerifyingKey: key, Proof: placeholderProof, Witness: placeholderWitness})

	if err := solveOuter(t, fixed, &recursionFixed{Proof: proofValue, Witness: honest, Square: emulated.ValueOf[sw_bls12377.ScalarField](9)}); err != nil {
		t.Fatalf("corrected circuit rejected the honest proof: %v", err)
	}
	requireDivergence(t,
		solveOuter(t, vulnerable, &recursionVulnerable{Proof: proofValue, Witness: forged, Square: emulated.ValueOf[sw_bls12377.ScalarField](10)}),
		solveOuter(t, fixed, &recursionFixed{Proof: proofValue, Witness: forged, Square: emulated.ValueOf[sw_bls12377.ScalarField](10)}))
}

func compileOuter(t *testing.T, circuit frontend.Circuit, opts ...frontend.CompileOption) constraint.ConstraintSystem {
	t.Helper()
	ccs, err := frontend.Compile(ecc.BW6_761.ScalarField(), r1cs.NewBuilder, circuit, opts...)
	if err != nil {
		t.Fatalf("compile %T: %v", circuit, err)
	}
	return ccs
}

func solveOuter(t *testing.T, ccs constraint.ConstraintSystem, assignment frontend.Circuit) error {
	t.Helper()
	w, err := frontend.NewWitness(assignment, ecc.BW6_761.ScalarField())
	if err != nil {
		t.Fatalf("outer witness: %v", err)
	}
	return ccs.IsSolved(w)
}
