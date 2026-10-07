package recursionwitness

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/math/emulated"
)

// HelperCircuit verifies in a method that Define calls on its receiver.
type HelperCircuit struct {
	VerifyingKey verifyingKey `gnark:"-"`
	Proof        proof
	Witness      witness
	Claim        scalar `gnark:",public"`
}

func (c *HelperCircuit) Define(api frontend.API) error {
	f, err := emulated.NewField[sw_bn254.ScalarField](api)
	if err != nil {
		return err
	}
	f.AssertIsEqual(&c.Witness.Public[0], &c.Claim)
	return c.verify(api)
}

func (c *HelperCircuit) verify(api frontend.API) error {
	verifier, err := newVerifier(api)
	if err != nil {
		return err
	}
	return verifier.AssertProof(c.VerifyingKey, c.Proof, c.Witness)
}
