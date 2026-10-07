package recursionwitness

import (
	"fmt"

	"github.com/auditinfra-io/gnark-safety/internal/analyzer/testdata/corpus/recursionwitness/external"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/math/emulated"
)

// EmbeddedCircuit embeds the inner witness and reads it through the
// promoted field; nothing verifies it.
type EmbeddedCircuit struct {
	witness
	Proof proof
	Claim scalar `gnark:",public"`
}

func (c *EmbeddedCircuit) Define(api frontend.API) error {
	f, err := emulated.NewField[sw_bn254.ScalarField](api)
	if err != nil {
		return err
	}
	f.AssertIsEqual(&c.Public[0], &c.Claim) // want GNARK_RECURSION_WITNESS_UNVERIFIED:high
	return nil
}

// claimWitness is a type defined over the recursion witness.
type claimWitness witness

// DefinedTypeCircuit verifies Main but consumes Side, whose type is
// defined over the witness.
type DefinedTypeCircuit struct {
	VerifyingKey verifyingKey `gnark:"-"`
	Proof        proof
	Main         witness
	Side         claimWitness
	Claim        scalar `gnark:",public"`
}

func (c *DefinedTypeCircuit) Define(api frontend.API) error {
	verifier, err := newVerifier(api)
	if err != nil {
		return err
	}
	if err := verifier.AssertProof(c.VerifyingKey, c.Proof, c.Main); err != nil {
		return err
	}
	f, err := emulated.NewField[sw_bn254.ScalarField](api)
	if err != nil {
		return err
	}
	f.AssertIsEqual(&c.Side.Public[0], &c.Claim) // want GNARK_RECURSION_WITNESS_UNVERIFIED:high
	return nil
}

// VarDiscardCircuit drops IsValidProof's result in a var declaration.
type VarDiscardCircuit struct {
	VerifyingKey verifyingKey `gnark:"-"`
	Proof        proof
	Witness      witness
	Claim        scalar `gnark:",public"`
}

func (c *VarDiscardCircuit) Define(api frontend.API) error {
	verifier, err := newVerifier(api)
	if err != nil {
		return err
	}
	var _, verr = verifier.IsValidProof(c.VerifyingKey, c.Proof, c.Witness) // want GNARK_DISCARDED_PREDICATE
	if verr != nil {
		return verr
	}
	f, err := emulated.NewField[sw_bn254.ScalarField](api)
	if err != nil {
		return err
	}
	f.AssertIsEqual(&c.Witness.Public[0], &c.Claim) // want GNARK_RECURSION_WITNESS_UNVERIFIED:high
	return nil
}

// DeferDiscardCircuit defers IsValidProof, whose results a deferred call
// always drops.
type DeferDiscardCircuit struct {
	VerifyingKey verifyingKey `gnark:"-"`
	Proof        proof
	Witness      witness
	Claim        scalar `gnark:",public"`
}

func (c *DeferDiscardCircuit) Define(api frontend.API) error {
	verifier, err := newVerifier(api)
	if err != nil {
		return err
	}
	defer verifier.IsValidProof(c.VerifyingKey, c.Proof, c.Witness) // want GNARK_DISCARDED_PREDICATE
	f, err := emulated.NewField[sw_bn254.ScalarField](api)
	if err != nil {
		return err
	}
	f.AssertIsEqual(&c.Witness.Public[0], &c.Claim) // want GNARK_RECURSION_WITNESS_UNVERIFIED:high
	return nil
}

// DigestCircuit hands the inputs to code in another package and verifies
// nothing: inputs alone cannot be verified without the proof and key.
type DigestCircuit struct {
	VerifyingKey verifyingKey `gnark:"-"`
	Proof        proof
	Witness      witness
	Claim        scalar `gnark:",public"`
}

func (c *DigestCircuit) Define(api frontend.API) error {
	f, err := emulated.NewField[sw_bn254.ScalarField](api)
	if err != nil {
		return err
	}
	f.AssertIsEqual(external.Digest(f, c.Witness.Public), &c.Claim) // want GNARK_RECURSION_WITNESS_UNVERIFIED:high
	return nil
}

// TreeCircuit composes copies of itself; the self-call does not make it a
// sub-circuit of anything, and nothing verifies its witness.
type TreeCircuit struct {
	Witness  witness
	Claim    scalar `gnark:",public"`
	Children []TreeCircuit
}

func (c *TreeCircuit) Define(api frontend.API) error {
	f, err := emulated.NewField[sw_bn254.ScalarField](api)
	if err != nil {
		return err
	}
	f.AssertIsEqual(&c.Witness.Public[0], &c.Claim) // want GNARK_RECURSION_WITNESS_UNVERIFIED:high
	for i := range c.Children {
		if err := c.Children[i].Define(api); err != nil {
			return err
		}
	}
	return nil
}

// LoopCircuit verifies each batch witness through the range variable but
// also consumes Extra, which nothing verifies.
type LoopCircuit struct {
	VerifyingKey verifyingKey `gnark:"-"`
	Proofs       []proof
	Witnesses    []witness
	Extra        witness
	Total        scalar `gnark:",public"`
}

func (c *LoopCircuit) Define(api frontend.API) error {
	verifier, err := newVerifier(api)
	if err != nil {
		return err
	}
	f, err := emulated.NewField[sw_bn254.ScalarField](api)
	if err != nil {
		return err
	}
	sum := f.Zero()
	for i, w := range c.Witnesses {
		if err := verifier.AssertProof(c.VerifyingKey, c.Proofs[i], w); err != nil {
			return err
		}
		sum = f.Add(sum, &w.Public[0])
	}
	f.AssertIsEqual(f.Add(sum, &c.Extra.Public[0]), &c.Total) // want GNARK_RECURSION_WITNESS_UNVERIFIED:high
	return nil
}

// AssertedCircuit checks that it implements frontend.Circuit, which stores
// nothing, verifies Main, and consumes Side, which nothing verifies.
type AssertedCircuit struct {
	VerifyingKey verifyingKey `gnark:"-"`
	Proof        proof
	Main, Side   witness
	Claim        scalar `gnark:",public"`
}

func (c *AssertedCircuit) Define(api frontend.API) error {
	var _ frontend.Circuit = (*AssertedCircuit)(nil)
	verifier, err := newVerifier(api)
	if err != nil {
		return err
	}
	if err := verifier.AssertProof(c.VerifyingKey, c.Proof, c.Main); err != nil {
		return err
	}
	f, err := emulated.NewField[sw_bn254.ScalarField](api)
	if err != nil {
		return err
	}
	f.AssertIsEqual(&c.Side.Public[0], &c.Claim) // want GNARK_RECURSION_WITNESS_UNVERIFIED:high
	return nil
}

// ErrorPathCircuit prints the witness in an error message; the standard
// library cannot verify it, and nothing else does.
type ErrorPathCircuit struct {
	Proof   proof
	Witness witness
	Claim   scalar `gnark:",public"`
}

func (c *ErrorPathCircuit) Define(api frontend.API) error {
	if len(c.Witness.Public) == 0 {
		return fmt.Errorf("empty witness %v", c.Witness)
	}
	f, err := emulated.NewField[sw_bn254.ScalarField](api)
	if err != nil {
		return err
	}
	f.AssertIsEqual(&c.Witness.Public[0], &c.Claim) // want GNARK_RECURSION_WITNESS_UNVERIFIED:high
	return nil
}
