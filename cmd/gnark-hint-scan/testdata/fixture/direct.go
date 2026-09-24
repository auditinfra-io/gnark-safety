package fixture

import (
	"math/big"

	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
)

const outputs = 2

func knownHint(_ *big.Int, _ []*big.Int, _ []*big.Int) error { return nil }

func direct(api frontend.API, input frontend.Variable) {
	api.Compiler().NewHint(knownHint, outputs, input)
}

func helper(api frontend.API) {
	api.Compiler().NewHint(knownHint, 1)
}

func multiple(api frontend.API) {
	api.Compiler().NewHint(knownHint, 1)
	api.Compiler().NewHint(knownHint, 1)
}

func unresolved(api frontend.API, hint solver.Hint, n int) {
	api.Compiler().NewHint(hint, n)
}

func expanded(api frontend.API, inputs []frontend.Variable) {
	api.Compiler().NewHint(knownHint, 1, inputs...)
}

func methodExpression(api frontend.API, input frontend.Variable) {
	frontend.Compiler.NewHint(api.Compiler(), knownHint, 2, input)
}

func deprecatedShortcut(api frontend.API) {
	api.NewHint(knownHint, 1)
}

func genericHint[T any](_ *big.Int, _ []*big.Int, _ []*big.Int) error { return nil }

func instantiated(api frontend.API) {
	api.Compiler().NewHint(genericHint[int], 1)
}

type hintHandler struct{}

func (hintHandler) Compute(_ *big.Int, _ []*big.Int, _ []*big.Int) error { return nil }

func methodValue(api frontend.API, handler hintHandler) {
	api.Compiler().NewHint(handler.Compute, 1)
}

type unrelated struct{}

func (unrelated) NewHint(any, int, ...any) {}
func ignored()                             { unrelated{}.NewHint(knownHint, 1) }
