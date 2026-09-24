// Package unused pins how GNARK_HINT_OUTPUT_UNUSED classifies each way an
// output can be referenced. The shapes come from gnark's own std/algebra
// code, where an earlier version reported every output as unused.
package unused

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
)

func hint(_ *big.Int, _ []*big.Int, _ []*big.Int) error { return nil }

type pair struct{ A, B frontend.Variable }

var global frontend.Variable

func consume(api frontend.API, values []frontend.Variable) { api.AssertIsEqual(values[0], values[1]) }

// fieldStores assigns every output into struct fields: all are used.
func fieldStores(api frontend.API, x frontend.Variable) pair {
	out, _ := api.Compiler().NewHint(hint, 2, x)
	var p pair
	p.A, p.B = out[0], out[1]
	return p
}

// sliced passes sub-slices along, so any output may be used: unknown.
func sliced(api frontend.API, x frontend.Variable) {
	out, _ := api.Compiler().NewHint(hint, 4, x)
	consume(api, out[:2])
	var rest [2]frontend.Variable
	copy(rest[:], out[2:4])
	consume(api, rest[:])
}

// wholeSlice passes the slice itself: unknown.
func wholeSlice(api frontend.API, x frontend.Variable) {
	out, _ := api.Compiler().NewHint(hint, 2, x)
	consume(api, out)
}

// dynamicIndex reads outputs by a loop index: unknown.
func dynamicIndex(api frontend.API, x frontend.Variable) {
	out, _ := api.Compiler().NewHint(hint, 3, x)
	for i := range 3 {
		api.AssertIsBoolean(out[i])
	}
}

// globalStore assigns into a package variable read elsewhere: used.
func globalStore(api frontend.API, x frontend.Variable) {
	out, _ := api.Compiler().NewHint(hint, 1, x)
	global = out[0]
}

// localAliases reads both outputs through local aliases, one declared with
// := and one with var: both are used.
func localAliases(api frontend.API, x frontend.Variable) {
	out, _ := api.Compiler().NewHint(hint, 2, x)
	a := out[0]
	var b = out[1]
	api.AssertIsEqual(a, b)
}

// discarded drops output 1 explicitly: unused.
func discarded(api frontend.API, x frontend.Variable) {
	out, _ := api.Compiler().NewHint(hint, 2, x) // want GNARK_HINT_OUTPUT_UNUSED
	a, _ := out[0], out[1]
	api.AssertIsBoolean(a)
}
