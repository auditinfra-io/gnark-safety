package recursionwitness

import "github.com/consensys/gnark/frontend"

// ShapeCircuit reads only how many public inputs the witness has, a number
// fixed when the circuit compiles, not any input value. It verifies
// nothing, but this rule reports only consumed input values, and none of
// the inner proof's inputs are consumed here.
type ShapeCircuit struct {
	Proof   proof
	Witness witness
	Count   frontend.Variable `gnark:",public"`
	Rest    frontend.Variable `gnark:",public"`
}

func (c *ShapeCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(c.Count, len(c.Witness.Public))
	api.AssertIsEqual(c.Rest, len(c.Witness.Public[1:]))
	for range c.Witness.Public {
		api.AssertIsDifferent(c.Count, 0)
	}
	return nil
}
