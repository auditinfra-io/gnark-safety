// Package demo sits under an examples directory, so its findings are
// downgraded to low unless example severities are kept.
package demo

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
)

func hint(_ *big.Int, _ []*big.Int, _ []*big.Int) error { return nil }

func incomplete(api frontend.API, n, d frontend.Variable) error {
	out, err := api.Compiler().NewHint(hint, 2, n, d)
	if err != nil {
		return err
	}
	q, r := out[0], out[1]
	api.AssertIsEqual(n, api.Add(api.Mul(q, d), r))
	return nil
}
