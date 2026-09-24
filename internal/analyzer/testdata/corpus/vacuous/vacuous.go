// Package vacuous is the corpus for GNARK_VACUOUS_ASSERT.
package vacuous

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/cmp"
)

type point struct{ X, Y frontend.Variable }

type Circuit struct {
	X, Y   frontend.Variable
	A, B   point
	Values [2]frontend.Variable
}

func (c *Circuit) Define(api frontend.API) error {
	api.AssertIsEqual(c.Y, c.Y)                 // want GNARK_VACUOUS_ASSERT:high
	api.AssertIsLessOrEqual(c.X, (c.X))         // want GNARK_VACUOUS_ASSERT:high
	api.AssertIsEqual(c.Values[1], c.Values[1]) // want GNARK_VACUOUS_ASSERT:high
	api.AssertIsEqual(1, 1)                     // want GNARK_VACUOUS_ASSERT:medium
	api.AssertIsBoolean(0)                      // want GNARK_VACUOUS_ASSERT:medium
	comparator := cmp.NewBoundedComparator(api, big.NewInt(255), false)
	comparator.AssertIsLessEq(c.X, c.X) // want GNARK_VACUOUS_ASSERT:high

	// Distinct operands are real checks, even when they share a field name.
	api.AssertIsEqual(c.X, c.Y)
	api.AssertIsEqual(c.A.X, c.B.X)
	api.AssertIsEqual(c.Values[0], c.Values[1])
	api.AssertIsBoolean(c.X)
	// Unsatisfiable, not vacuous: a liveness bug this rule leaves alone.
	api.AssertIsDifferent(c.Y, c.Y)
	comparator.AssertIsLess(c.Y, c.Y)
	return nil
}
