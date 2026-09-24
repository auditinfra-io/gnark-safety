// Command setupmain generates Groth16 keys with a single-party setup.
package main

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

type circuit struct{ X, Y frontend.Variable }

func (c *circuit) Define(api frontend.API) error {
	api.AssertIsEqual(api.Mul(c.X, c.X), c.Y)
	return nil
}

func main() {
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit{})
	if err != nil {
		panic(err)
	}
	if _, _, err := groth16.Setup(ccs); err != nil { // want GNARK_UNSAFE_SETUP:low
		panic(err)
	}
}
