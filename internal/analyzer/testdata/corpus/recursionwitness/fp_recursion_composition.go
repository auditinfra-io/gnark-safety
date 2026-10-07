package recursionwitness

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/math/emulated"
	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"
)

// Leaf consumes an inner witness and is used only as a sub-circuit:
// AggregatorCircuit verifies the witness and then calls Leaf.Define.
type Leaf struct {
	Witness witness
	Claim   scalar
}

func (l *Leaf) Define(api frontend.API) error {
	f, err := emulated.NewField[sw_bn254.ScalarField](api)
	if err != nil {
		return err
	}
	f.AssertIsEqual(&l.Witness.Public[0], &l.Claim)
	return nil
}

type AggregatorCircuit struct {
	VerifyingKey verifyingKey `gnark:"-"`
	Proof        proof
	Leaf         Leaf
}

func (c *AggregatorCircuit) Define(api frontend.API) error {
	verifier, err := newVerifier(api)
	if err != nil {
		return err
	}
	if err := verifier.AssertProof(c.VerifyingKey, c.Proof, c.Leaf.Witness); err != nil {
		return err
	}
	return c.Leaf.Define(api)
}

// gadget has a Define without an error result, so it is not a
// frontend.Circuit; GadgetCircuit verifies its witness and runs it.
type gadget struct {
	Witness witness
	Claim   scalar
}

func (g *gadget) Define(api frontend.API) {
	f, err := emulated.NewField[sw_bn254.ScalarField](api)
	if err != nil {
		panic(err)
	}
	f.AssertIsEqual(&g.Witness.Public[0], &g.Claim)
}

type GadgetCircuit struct {
	VerifyingKey verifyingKey `gnark:"-"`
	Proof        proof
	Gadget       gadget
}

func (c *GadgetCircuit) Define(api frontend.API) error {
	verifier, err := newVerifier(api)
	if err != nil {
		return err
	}
	if err := verifier.AssertProof(c.VerifyingKey, c.Proof, c.Gadget.Witness); err != nil {
		return err
	}
	c.Gadget.Define(api)
	return nil
}

// PublicHelperCircuit hands the public inputs, not the witness, to a
// helper that rebuilds the witness and verifies it.
type PublicHelperCircuit struct {
	VerifyingKey verifyingKey `gnark:"-"`
	Proof        proof
	Witness      witness
	Claim        scalar `gnark:",public"`
}

func (c *PublicHelperCircuit) Define(api frontend.API) error {
	f, err := emulated.NewField[sw_bn254.ScalarField](api)
	if err != nil {
		return err
	}
	f.AssertIsEqual(&c.Witness.Public[0], &c.Claim)
	return verifyInputs(api, c.VerifyingKey, c.Proof, c.Witness.Public)
}

func verifyInputs(api frontend.API, vk verifyingKey, p proof, public []scalar) error {
	verifier, err := newVerifier(api)
	if err != nil {
		return err
	}
	return verifier.AssertProof(vk, p, stdgroth16.Witness[sw_bn254.ScalarField]{Public: public})
}

// CallbackCircuit passes its verifying method as a callback.
type CallbackCircuit struct {
	VerifyingKey verifyingKey `gnark:"-"`
	Proof        proof
	Witness      witness
	Claim        scalar `gnark:",public"`
}

func (c *CallbackCircuit) Define(api frontend.API) error {
	f, err := emulated.NewField[sw_bn254.ScalarField](api)
	if err != nil {
		return err
	}
	f.AssertIsEqual(&c.Witness.Public[0], &c.Claim)
	return runStep(api, c.verify)
}

func (c *CallbackCircuit) verify(api frontend.API) error {
	verifier, err := newVerifier(api)
	if err != nil {
		return err
	}
	return verifier.AssertProof(c.VerifyingKey, c.Proof, c.Witness)
}

func runStep(api frontend.API, step func(frontend.API) error) error {
	return step(api)
}

// NestedCircuit keeps its witnesses several levels deep and verifies them
// in a method on the receiver.
type NestedCircuit struct {
	VerifyingKey verifyingKey `gnark:"-"`
	Batches      []batch
	Total        scalar `gnark:",public"`
}

type batch struct{ Items []item }

type item struct {
	Proof   proof
	Witness witness
}

func (c *NestedCircuit) Define(api frontend.API) error {
	f, err := emulated.NewField[sw_bn254.ScalarField](api)
	if err != nil {
		return err
	}
	sum := f.Zero()
	for i := range c.Batches {
		for j := range c.Batches[i].Items {
			sum = f.Add(sum, &c.Batches[i].Items[j].Witness.Public[0])
		}
	}
	f.AssertIsEqual(sum, &c.Total)
	return c.verifyAll(api)
}

func (c *NestedCircuit) verifyAll(api frontend.API) error {
	verifier, err := newVerifier(api)
	if err != nil {
		return err
	}
	for i := range c.Batches {
		for j := range c.Batches[i].Items {
			if err := verifier.AssertProof(c.VerifyingKey, c.Batches[i].Items[j].Proof, c.Batches[i].Items[j].Witness); err != nil {
				return err
			}
		}
	}
	return nil
}

// InterfaceCircuit runs a verifying sub-circuit through frontend.Circuit;
// the rule cannot see which Define runs, so it stays quiet.
type InterfaceCircuit struct {
	Step  verifiedStep
	Claim scalar `gnark:",public"`
}

type verifiedStep struct {
	VerifyingKey verifyingKey `gnark:"-"`
	Proof        proof
	Witness      witness
}

func (s *verifiedStep) Define(api frontend.API) error {
	verifier, err := newVerifier(api)
	if err != nil {
		return err
	}
	return verifier.AssertProof(s.VerifyingKey, s.Proof, s.Witness)
}

func (c *InterfaceCircuit) Define(api frontend.API) error {
	f, err := emulated.NewField[sw_bn254.ScalarField](api)
	if err != nil {
		return err
	}
	f.AssertIsEqual(&c.Step.Witness.Public[0], &c.Claim)
	var step frontend.Circuit = &c.Step
	return step.Define(api)
}

// LocalInputsCircuit names the public inputs once and hands that local to
// the helper that rebuilds and verifies the witness.
type LocalInputsCircuit struct {
	VerifyingKey verifyingKey `gnark:"-"`
	Proof        proof
	Witness      witness
	Claim        scalar `gnark:",public"`
}

func (c *LocalInputsCircuit) Define(api frontend.API) error {
	f, err := emulated.NewField[sw_bn254.ScalarField](api)
	if err != nil {
		return err
	}
	inputs := c.Witness.Public
	f.AssertIsEqual(&inputs[0], &c.Claim)
	return verifyInputs(api, c.VerifyingKey, c.Proof, inputs)
}

// RebuiltCircuit verifies a witness rebuilt from the inputs it consumes.
type RebuiltCircuit struct {
	VerifyingKey verifyingKey `gnark:"-"`
	Proof        proof
	Inner        witness
	Claim        scalar `gnark:",public"`
}

func (c *RebuiltCircuit) Define(api frontend.API) error {
	verifier, err := newVerifier(api)
	if err != nil {
		return err
	}
	f, err := emulated.NewField[sw_bn254.ScalarField](api)
	if err != nil {
		return err
	}
	f.AssertIsEqual(&c.Inner.Public[0], &c.Claim)
	return verifier.AssertProof(c.VerifyingKey, c.Proof, witness{Public: c.Inner.Public})
}

// StepsCircuit collects verifying sub-circuits in a []frontend.Circuit.
type StepsCircuit struct {
	Step  verifiedStep
	Claim scalar `gnark:",public"`
}

func (c *StepsCircuit) Define(api frontend.API) error {
	f, err := emulated.NewField[sw_bn254.ScalarField](api)
	if err != nil {
		return err
	}
	f.AssertIsEqual(&c.Step.Witness.Public[0], &c.Claim)
	var steps []frontend.Circuit
	steps = append(steps, &c.Step)
	for _, step := range steps {
		if err := step.Define(api); err != nil {
			return err
		}
	}
	return nil
}
