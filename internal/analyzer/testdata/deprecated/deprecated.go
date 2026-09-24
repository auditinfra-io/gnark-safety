// Package deprecated exercises the frontend.API.NewHint shortcut, which gnark
// deprecated in favor of Compiler.NewHint but still exports. Before the
// analyzer recognized it, this package scanned as zero hints and zero
// findings despite containing the incomplete relation.
package deprecated

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/cmp"
)

func hint(_ *big.Int, _ []*big.Int, _ []*big.Int) error { return nil }

type Circuit struct {
	N frontend.Variable `gnark:",public"`
	D frontend.Variable `gnark:",public"`
}

// Define omits r < d through the deprecated shortcut.
func (c *Circuit) Define(api frontend.API) error {
	qr, err := api.NewHint(hint, 2, c.N, c.D)
	if err != nil {
		return err
	}
	api.AssertIsEqual(c.N, api.Add(api.Mul(qr[0], c.D), qr[1]))
	return nil
}

// methodExpression omits r < d through a method expression.
func methodExpression(api frontend.API, n, d frontend.Variable) error {
	qr, err := frontend.API.NewHint(api, hint, 2, n, d)
	if err != nil {
		return err
	}
	q, r := qr[0], qr[1]
	api.AssertIsEqual(n, api.Add(api.Mul(q, d), r))
	return nil
}

type wrapped struct{ frontend.API }

// promoted omits r < d through a method promoted by embedding.
func promoted(w wrapped, n, d frontend.Variable) error {
	qr, err := w.NewHint(hint, 2, n, d)
	if err != nil {
		return err
	}
	q, r := qr[0], qr[1]
	w.AssertIsEqual(n, w.Add(w.Mul(q, d), r))
	return nil
}

// safe uses the deprecated shortcut but constrains r < d.
func safe(api frontend.API, n, d frontend.Variable) error {
	qr, err := api.NewHint(hint, 2, n, d)
	if err != nil {
		return err
	}
	q, r := qr[0], qr[1]
	api.AssertIsEqual(n, api.Add(api.Mul(q, d), r))
	cmp.NewBoundedComparator(api, big.NewInt(255), false).AssertIsLess(r, d)
	return nil
}
