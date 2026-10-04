// Package corrected is examples/divmod's CorrectedCircuit on its own: the
// remainder is range-checked and bounded by r < d, so no rule reports it.
package corrected

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/cmp"
)

func quotientRemainder(_ *big.Int, inputs, outputs []*big.Int) error {
	outputs[0].QuoRem(inputs[0], inputs[1], outputs[1])
	return nil
}

type CorrectedCircuit struct {
	N frontend.Variable `gnark:",public"`
	D frontend.Variable `gnark:",public"`
}

func (c *CorrectedCircuit) Define(api frontend.API) error {
	qr, err := api.Compiler().NewHint(quotientRemainder, 2, c.N, c.D)
	if err != nil {
		return err
	}
	q, r := qr[0], qr[1]
	api.ToBinary(c.N, 8)
	api.ToBinary(c.D, 8)
	api.ToBinary(q, 8)
	api.ToBinary(r, 8)
	api.AssertIsDifferent(c.D, 0)
	api.AssertIsEqual(c.N, api.Add(api.Mul(q, c.D), r))
	cmp.NewBoundedComparator(api, big.NewInt(255), false).AssertIsLess(r, c.D)
	return nil
}
