// Package recursionwitness covers GNARK_RECURSION_WITNESS_UNVERIFIED on
// synthetic circuits. tp_*.go must be reported and fp_*.go must stay quiet;
// UnverifiedCircuit is VerifiedCircuit with its enforcement line removed.
package recursionwitness

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/math/emulated"
	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"
)

type (
	proof        = stdgroth16.Proof[sw_bn254.G1Affine, sw_bn254.G2Affine]
	verifyingKey = stdgroth16.VerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]
	witness      = stdgroth16.Witness[sw_bn254.ScalarField]
	scalar       = emulated.Element[sw_bn254.ScalarField]
)

func newVerifier(api frontend.API) (*stdgroth16.Verifier[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl], error) {
	return stdgroth16.NewVerifier[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](api)
}

// UnverifiedCircuit claims the sum of two inner proofs' public inputs but
// verifies only the first proof, so the second input is free.
type UnverifiedCircuit struct {
	VerifyingKey  verifyingKey `gnark:"-"`
	First         proof
	FirstWitness  witness
	Second        proof
	SecondWitness witness
	Total         scalar `gnark:",public"`
}

func (c *UnverifiedCircuit) Define(api frontend.API) error {
	verifier, err := newVerifier(api)
	if err != nil {
		return err
	}
	f, err := emulated.NewField[sw_bn254.ScalarField](api)
	if err != nil {
		return err
	}
	f.AssertIsEqual(f.Add(&c.FirstWitness.Public[0], &c.SecondWitness.Public[0]), &c.Total) // want GNARK_RECURSION_WITNESS_UNVERIFIED:high
	err = verifier.AssertProof(c.VerifyingKey, c.First, c.FirstWitness)
	if err != nil {
		return err
	}
	if err != nil {
		return err
	}
	return nil
}

// DiscardedCircuit invokes the verifier but drops the validity it computes.
type DiscardedCircuit struct {
	VerifyingKey verifyingKey `gnark:"-"`
	Proof        proof
	Witness      witness
	Claim        scalar `gnark:",public"`
}

func (c *DiscardedCircuit) Define(api frontend.API) error {
	verifier, err := newVerifier(api)
	if err != nil {
		return err
	}
	_, err = verifier.IsValidProof(c.VerifyingKey, c.Proof, c.Witness) // want GNARK_DISCARDED_PREDICATE
	if err != nil {
		return err
	}
	f, err := emulated.NewField[sw_bn254.ScalarField](api)
	if err != nil {
		return err
	}
	f.AssertIsEqual(&c.Witness.Public[0], &c.Claim) // want GNARK_RECURSION_WITNESS_UNVERIFIED:high
	return nil
}

// NoVerifierCircuit consumes an inner witness and never verifies a proof.
type NoVerifierCircuit struct {
	Proof   proof
	Witness witness
	Claim   scalar `gnark:",public"`
}

func (c *NoVerifierCircuit) Define(api frontend.API) error {
	f, err := emulated.NewField[sw_bn254.ScalarField](api)
	if err != nil {
		return err
	}
	for i := range c.Witness.Public {
		f.AssertIsEqual(&c.Witness.Public[i], &c.Claim) // want GNARK_RECURSION_WITNESS_UNVERIFIED:high
	}
	return nil
}
