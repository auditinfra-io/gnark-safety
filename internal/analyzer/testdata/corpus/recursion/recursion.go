// Package recursion covers discarded proof-validity results for
// GNARK_DISCARDED_PREDICATE.
package recursion

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"
)

type Circuit struct {
	Proof        stdgroth16.Proof[sw_bn254.G1Affine, sw_bn254.G2Affine]
	VerifyingKey stdgroth16.VerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl] `gnark:"-"`
	Witness      stdgroth16.Witness[sw_bn254.ScalarField]
}

func (c *Circuit) Define(api frontend.API) error {
	verifier, err := stdgroth16.NewVerifier[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](api)
	if err != nil {
		return err
	}
	_, err = verifier.IsValidProof(c.VerifyingKey, c.Proof, c.Witness) // want GNARK_DISCARDED_PREDICATE
	if err != nil {
		return err
	}
	valid, err := verifier.IsValidProof(c.VerifyingKey, c.Proof, c.Witness)
	if err != nil {
		return err
	}
	api.AssertIsEqual(valid, 1)
	return nil
}
