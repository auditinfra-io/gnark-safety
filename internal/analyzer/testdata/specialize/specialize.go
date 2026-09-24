// Package specialize exercises call-site specialization: an r < d bound
// guarded by a bool parameter is reported at calls that disable it when every
// call passes a constant, and at the hint otherwise.
package specialize

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/cmp"
)

func hint(_ *big.Int, _ []*big.Int, _ []*big.Int) error { return nil }

func bound(api frontend.API, r, d frontend.Variable) {
	cmp.NewBoundedComparator(api, big.NewInt(255), false).AssertIsLess(r, d)
}

// guarded enforces r < d only when enforce is true.
func guarded(api frontend.API, n, d frontend.Variable, enforce bool) {
	out, _ := api.Compiler().NewHint(hint, 2, n, d)
	q, r := out[0], out[1]
	api.AssertIsEqual(n, api.Add(api.Mul(q, d), r))
	if enforce {
		cmp.NewBoundedComparator(api, big.NewInt(255), false).AssertIsLess(r, d)
	}
}

type Vulnerable struct{ N, D frontend.Variable }

func (c *Vulnerable) Define(api frontend.API) error {
	guarded(api, c.N, c.D, false) // reported here
	return nil
}

type Corrected struct{ N, D frontend.Variable }

func (c *Corrected) Define(api frontend.API) error {
	guarded(api, c.N, c.D, true)
	return nil
}

const strict = true

func namedConstant(api frontend.API, n, d frontend.Variable) {
	guarded(api, n, d, strict)
}

// negated skips the helper-provided bound when skip is true.
func negated(api frontend.API, n, d frontend.Variable, skip bool) {
	out, _ := api.Compiler().NewHint(hint, 2, n, d)
	api.AssertIsEqual(n, api.Add(api.Mul(out[0], d), out[1]))
	if !skip {
		bound(api, out[1], d)
	}
}

func skipsBound(api frontend.API, n, d frontend.Variable) { negated(api, n, d, true) } // reported here
func keepsBound(api frontend.API, n, d frontend.Variable) { negated(api, n, d, false) }

// elseBranch enforces r < d only in the else branch.
func elseBranch(api frontend.API, n, d frontend.Variable, relaxed bool) {
	out, _ := api.Compiler().NewHint(hint, 2, n, d)
	api.AssertIsEqual(n, api.Add(api.Mul(out[0], d), out[1]))
	if relaxed {
		api.AssertIsEqual(out[0], out[0])
	} else {
		bound(api, out[1], d)
	}
}

func relaxedCaller(api frontend.API, n, d frontend.Variable) { elseBranch(api, n, d, true) } // reported here
func strictCaller(api frontend.API, n, d frontend.Variable)  { elseBranch(api, n, d, false) }

// escaping is also used as a function value, so its calls cannot all be
// resolved and the finding stays at the hint.
func escaping(api frontend.API, n, d frontend.Variable, enforce bool) {
	out, _ := api.Compiler().NewHint(hint, 2, n, d)
	api.AssertIsEqual(n, api.Add(api.Mul(out[0], d), out[1]))
	if enforce {
		bound(api, out[1], d)
	}
}

var escaped = escaping

func escapingCaller(api frontend.API, n, d frontend.Variable) { escaping(api, n, d, true) }

// dynamic receives a runtime guard, so the finding stays at the hint.
func dynamic(api frontend.API, n, d frontend.Variable, enforce bool) {
	out, _ := api.Compiler().NewHint(hint, 2, n, d)
	api.AssertIsEqual(n, api.Add(api.Mul(out[0], d), out[1]))
	if enforce {
		bound(api, out[1], d)
	}
}

func dynamicCaller(api frontend.API, n, d frontend.Variable, flag bool) { dynamic(api, n, d, flag) }

// reassigned overwrites its guard, so the argument does not decide it.
func reassigned(api frontend.API, n, d frontend.Variable, enforce bool) {
	enforce = !enforce
	out, _ := api.Compiler().NewHint(hint, 2, n, d)
	api.AssertIsEqual(n, api.Add(api.Mul(out[0], d), out[1]))
	if enforce {
		bound(api, out[1], d)
	}
}

func reassignedCaller(api frontend.API, n, d frontend.Variable) { reassigned(api, n, d, true) }

// Uncalled has no package-local callers, so the finding stays at the hint.
func Uncalled(api frontend.API, n, d frontend.Variable, enforce bool) {
	out, _ := api.Compiler().NewHint(hint, 2, n, d)
	api.AssertIsEqual(n, api.Add(api.Mul(out[0], d), out[1]))
	if enforce {
		bound(api, out[1], d)
	}
}
