package discarded

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/hash/mimc"
	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"
)

// Forms throws predicate results away in the other ways Go allows.
type Forms struct{ X frontend.Variable }

func (c *Forms) Define(api frontend.API) error {
	var _ = api.IsZero(c.X)   // want GNARK_DISCARDED_PREDICATE
	(api.IsZero(c.X))         // want GNARK_DISCARDED_PREDICATE
	_ = (api.Cmp(c.X, 1))     // want GNARK_DISCARDED_PREDICATE
	defer api.Cmp(c.X, 2)     // want GNARK_DISCARDED_PREDICATE
	go api.IsZero(c.X)        // want GNARK_DISCARDED_PREDICATE
	isZero := api.IsZero(c.X) // kept: not reported
	api.AssertIsEqual(isZero, 0)
	return nil
}

// gadget embeds the API; a predicate on its own receiver is still a
// predicate.
type gadget struct{ frontend.API }

func (g gadget) check(x frontend.Variable) {
	g.IsZero(x) // want GNARK_DISCARDED_PREDICATE
}

// EmbeddedVerifier embeds the recursive verifier and drops the validity
// that IsValidProof computes on its own receiver.
type EmbeddedVerifier struct {
	*stdgroth16.Verifier[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl] `gnark:"-"`
	VerifyingKey                                                                                    stdgroth16.VerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl] `gnark:"-"`
	Proof                                                                                           stdgroth16.Proof[sw_bn254.G1Affine, sw_bn254.G2Affine]
	Witness                                                                                         stdgroth16.Witness[sw_bn254.ScalarField]
}

func (c *EmbeddedVerifier) Define(api frontend.API) error {
	_, err := c.IsValidProof(c.VerifyingKey, c.Proof, c.Witness) // want GNARK_DISCARDED_PREDICATE
	return err
}

// Pairs binds several values at once.
type Pairs struct{ X, Y frontend.Variable }

func (c *Pairs) Define(api frontend.API) error {
	_, kept := api.IsZero(c.X), api.Cmp(c.X, c.Y)  // want GNARK_DISCARDED_PREDICATE
	var held, _ = api.IsZero(c.Y), api.IsZero(c.X) // want GNARK_DISCARDED_PREDICATE
	api.AssertIsEqual(kept, held)
	return nil
}

// wrapper flushes its embedded hasher through the field it embeds: not
// reported, like flushing.
type wrapper struct{ mimc.MiMC }

func (w *wrapper) State() []frontend.Variable {
	w.MiMC.Sum()
	return nil
}

// HashingCircuit embeds a hasher and drops the digest in Define; a circuit
// is not a hasher flushing itself.
type HashingCircuit struct {
	mimc.MiMC `gnark:"-"`
	X         frontend.Variable
}

func (c *HashingCircuit) Define(api frontend.API) error {
	c.Write(c.X)
	c.Sum() // want GNARK_DISCARDED_PREDICATE
	return nil
}
