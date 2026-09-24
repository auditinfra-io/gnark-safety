// Package discarded is the corpus for GNARK_DISCARDED_PREDICATE.
package discarded

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/std/math/cmp"
)

type Circuit struct{ X, Y frontend.Variable }

func (c *Circuit) Define(api frontend.API) error {
	api.IsZero(c.X)     // want GNARK_DISCARDED_PREDICATE
	_ = api.Cmp(c.X, 3) // want GNARK_DISCARDED_PREDICATE
	comparator := cmp.NewBoundedComparator(api, big.NewInt(255), false)
	comparator.IsLess(c.X, c.Y) // want GNARK_DISCARDED_PREDICATE
	h, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}
	h.Write(c.X)
	h.Sum() // want GNARK_DISCARDED_PREDICATE

	// Results that reach a constraint are not reported.
	api.AssertIsEqual(api.IsZero(c.Y), 0)
	isSmall := comparator.IsLessEq(c.X, 10)
	api.AssertIsEqual(isSmall, 1)
	h.Reset()
	h.Write(c.Y)
	api.AssertIsEqual(h.Sum(), c.X)
	return nil
}

// flushing embeds a hasher and flushes it by calling Sum on its own
// receiver, as gnark's MiMC.State does: not reported.
type flushing struct{ mimc.MiMC }

func (f *flushing) State() []frontend.Variable {
	f.Sum()
	return nil
}
