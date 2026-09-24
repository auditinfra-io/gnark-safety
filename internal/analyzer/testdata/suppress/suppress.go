// Package suppress exercises //gnark-safety:ignore directives. Every function
// omits r < d, so each would report GNARK_HINT_RELATION_INCOMPLETE unless a
// valid directive silences it.
package suppress

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
)

func hint(_ *big.Int, _ []*big.Int, _ []*big.Int) error { return nil }

func aboveLine(api frontend.API, n, d frontend.Variable) {
	//gnark-safety:ignore GNARK_HINT_RELATION_INCOMPLETE the caller constrains r < d
	out, _ := api.Compiler().NewHint(hint, 2, n, d)
	api.AssertIsEqual(n, api.Add(api.Mul(out[0], d), out[1]))
}

func trailing(api frontend.API, n, d frontend.Variable) {
	out, _ := api.Compiler().NewHint(hint, 2, n, d) //gnark-safety:ignore GNARK_HINT_RELATION_INCOMPLETE reviewed in audit 12
	api.AssertIsEqual(n, api.Add(api.Mul(out[0], d), out[1]))
}

func multipleIDs(api frontend.API, n, d frontend.Variable) {
	//gnark-safety:ignore GNARK_HINT_RELATION_INCOMPLETE,GNARK_HINT_OUTPUT_UNUSED both reviewed
	out, _ := api.Compiler().NewHint(hint, 2, n, d)
	api.AssertIsEqual(n, api.Add(api.Mul(out[0], d), out[1]))
}

func wrongRule(api frontend.API, n, d frontend.Variable) {
	//gnark-safety:ignore GNARK_HINT_OUTPUT_UNUSED silences a different rule
	out, _ := api.Compiler().NewHint(hint, 2, n, d)
	api.AssertIsEqual(n, api.Add(api.Mul(out[0], d), out[1]))
}

func noReason(api frontend.API, n, d frontend.Variable) {
	//gnark-safety:ignore GNARK_HINT_RELATION_INCOMPLETE
	out, _ := api.Compiler().NewHint(hint, 2, n, d)
	api.AssertIsEqual(n, api.Add(api.Mul(out[0], d), out[1]))
}

func spaced(api frontend.API, n, d frontend.Variable) {
	// gnark-safety:ignore GNARK_HINT_RELATION_INCOMPLETE a space makes this ordinary prose
	out, _ := api.Compiler().NewHint(hint, 2, n, d)
	api.AssertIsEqual(n, api.Add(api.Mul(out[0], d), out[1]))
}

func unknownRule(api frontend.API, n, d frontend.Variable) {
	//gnark-safety:ignore GNARK_NO_SUCH_RULE misspelled rule
	out, _ := api.Compiler().NewHint(hint, 2, n, d)
	api.AssertIsEqual(n, api.Add(api.Mul(out[0], d), out[1]))
}

func tooFar(api frontend.API, n, d frontend.Variable) {
	//gnark-safety:ignore GNARK_HINT_RELATION_INCOMPLETE two lines above the call

	out, _ := api.Compiler().NewHint(hint, 2, n, d)
	api.AssertIsEqual(n, api.Add(api.Mul(out[0], d), out[1]))
}
