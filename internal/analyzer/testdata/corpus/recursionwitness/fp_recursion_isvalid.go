package recursionwitness

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/math/emulated"
)

// ValidityCircuit uses groth16's second idiom: IsValidProof returns a
// variable, and the circuit asserts it.
type ValidityCircuit struct {
	VerifyingKey verifyingKey `gnark:"-"`
	Proof        proof
	Witness      witness
	Claim        scalar `gnark:",public"`
}

func (c *ValidityCircuit) Define(api frontend.API) error {
	verifier, err := newVerifier(api)
	if err != nil {
		return err
	}
	valid, err := verifier.IsValidProof(c.VerifyingKey, c.Proof, c.Witness)
	if err != nil {
		return err
	}
	api.AssertIsEqual(valid, 1)
	f, err := emulated.NewField[sw_bn254.ScalarField](api)
	if err != nil {
		return err
	}
	f.AssertIsEqual(&c.Witness.Public[0], &c.Claim)
	return nil
}
