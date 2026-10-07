package recursionwitness

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/math/emulated"
)

// VerifiedCircuit is UnverifiedCircuit with both proofs verified. The line
// marked "enforcement" is the one TestRecursionWitnessMutation removes.
type VerifiedCircuit struct {
	VerifyingKey  verifyingKey `gnark:"-"`
	First         proof
	FirstWitness  witness
	Second        proof
	SecondWitness witness
	Total         scalar `gnark:",public"`
}

func (c *VerifiedCircuit) Define(api frontend.API) error {
	verifier, err := newVerifier(api)
	if err != nil {
		return err
	}
	f, err := emulated.NewField[sw_bn254.ScalarField](api)
	if err != nil {
		return err
	}
	f.AssertIsEqual(f.Add(&c.FirstWitness.Public[0], &c.SecondWitness.Public[0]), &c.Total)
	err = verifier.AssertProof(c.VerifyingKey, c.First, c.FirstWitness)
	if err != nil {
		return err
	}
	err = verifier.AssertProof(c.VerifyingKey, c.Second, c.SecondWitness) // enforcement
	if err != nil {
		return err
	}
	return nil
}
