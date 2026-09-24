// Package testonly has a safe production helper and an incomplete relation
// that exists only in a _test.go file, to exercise --include-tests.
package testonly

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/cmp"
)

func hint(_ *big.Int, _ []*big.Int, _ []*big.Int) error { return nil }

func safe(api frontend.API, n, d frontend.Variable) error {
	out, err := api.Compiler().NewHint(hint, 2, n, d)
	if err != nil {
		return err
	}
	q, r := out[0], out[1]
	api.AssertIsEqual(n, api.Add(api.Mul(q, d), r))
	cmp.NewBoundedComparator(api, big.NewInt(255), false).AssertIsLess(r, d)
	return nil
}
