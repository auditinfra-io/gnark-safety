package recursionwitness

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/math/emulated"
	stdplonk "github.com/consensys/gnark/std/recursion/plonk"
)

// BatchCircuit uses plonk's batch idiom: AssertSameProofs verifies every
// proof against its witness, and the circuit sums their public inputs.
type BatchCircuit struct {
	VerifyingKey stdplonk.VerifyingKey[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine] `gnark:"-"`
	Proofs       []stdplonk.Proof[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine]
	Witnesses    []stdplonk.Witness[sw_bn254.ScalarField]
	Total        scalar `gnark:",public"`
}

func (c *BatchCircuit) Define(api frontend.API) error {
	verifier, err := stdplonk.NewVerifier[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](api)
	if err != nil {
		return err
	}
	f, err := emulated.NewField[sw_bn254.ScalarField](api)
	if err != nil {
		return err
	}
	sum := f.Zero()
	for i := range c.Witnesses {
		sum = f.Add(sum, &c.Witnesses[i].Public[0])
	}
	f.AssertIsEqual(sum, &c.Total)
	return verifier.AssertSameProofs(c.VerifyingKey, c.Proofs, c.Witnesses)
}

// PairCircuit batch-verifies two named witnesses through a composite
// literal and sums their inputs.
type PairCircuit struct {
	VerifyingKey stdplonk.VerifyingKey[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine] `gnark:"-"`
	Proofs       []stdplonk.Proof[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine]
	Left, Right  stdplonk.Witness[sw_bn254.ScalarField]
	Total        scalar `gnark:",public"`
}

func (c *PairCircuit) Define(api frontend.API) error {
	verifier, err := stdplonk.NewVerifier[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](api)
	if err != nil {
		return err
	}
	f, err := emulated.NewField[sw_bn254.ScalarField](api)
	if err != nil {
		return err
	}
	f.AssertIsEqual(f.Add(&c.Left.Public[0], &c.Right.Public[0]), &c.Total)
	return verifier.AssertSameProofs(c.VerifyingKey, c.Proofs, []stdplonk.Witness[sw_bn254.ScalarField]{c.Left, c.Right})
}

// LocalBatchCircuit builds the batch in a local before verifying it.
type LocalBatchCircuit struct {
	VerifyingKey stdplonk.VerifyingKey[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine] `gnark:"-"`
	Proofs       []stdplonk.Proof[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine]
	First, Last  stdplonk.Witness[sw_bn254.ScalarField]
	Total        scalar `gnark:",public"`
}

func (c *LocalBatchCircuit) Define(api frontend.API) error {
	verifier, err := stdplonk.NewVerifier[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](api)
	if err != nil {
		return err
	}
	f, err := emulated.NewField[sw_bn254.ScalarField](api)
	if err != nil {
		return err
	}
	f.AssertIsEqual(f.Add(&c.First.Public[0], &c.Last.Public[0]), &c.Total)
	batch := []stdplonk.Witness[sw_bn254.ScalarField]{c.First, c.Last}
	return verifier.AssertSameProofs(c.VerifyingKey, c.Proofs, batch)
}
