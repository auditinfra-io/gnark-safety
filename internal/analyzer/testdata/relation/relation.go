package relation

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/cmp"
)

func hint(_ *big.Int, _ []*big.Int, _ []*big.Int) error { return nil }

// separateAssertions must not be mistaken for a reconstruction.
func separateAssertions(api frontend.API, n, d frontend.Variable) error {
	out, err := api.Compiler().NewHint(hint, 2, n, d)
	if err != nil {
		return err
	}
	q, r := out[0], out[1]
	api.AssertIsEqual(q, 3)
	api.AssertIsEqual(r, 2)
	return nil
}

// wrongBound still lacks the required r < d bound.
func wrongBound(api frontend.API, n, d frontend.Variable) error {
	out, err := api.Compiler().NewHint(hint, 2, n, d)
	if err != nil {
		return err
	}
	q, r := out[0], out[1]
	api.AssertIsEqual(n, api.Add(api.Mul(q, d), r))
	cmp.NewBoundedComparator(api, big.NewInt(255), false).AssertIsLess(r, 256)
	return nil
}

// invertedBound constrains the remainder in the wrong argument position.
func invertedBound(api frontend.API, n, d frontend.Variable) error {
	out, err := api.Compiler().NewHint(hint, 2, n, d)
	if err != nil {
		return err
	}
	q, r := out[0], out[1]
	api.AssertIsEqual(n, api.Add(api.Mul(q, d), r))
	cmp.NewBoundedComparator(api, big.NewInt(255), false).AssertIsLess(0, r)
	return nil
}

// elseBound is not universal because the else branch may not execute.
func elseBound(api frontend.API, n, d frontend.Variable, checked bool) error {
	out, err := api.Compiler().NewHint(hint, 2, n, d)
	if err != nil {
		return err
	}
	q, r := out[0], out[1]
	api.AssertIsEqual(n, api.Add(api.Mul(q, d), r))
	if checked {
		api.AssertIsEqual(q, q)
	} else {
		cmp.NewBoundedComparator(api, big.NewInt(255), false).AssertIsLess(r, d)
	}
	return nil
}

// loopBound is not universal because the loop may execute zero times.
func loopBound(api frontend.API, n, d frontend.Variable, count int) error {
	out, err := api.Compiler().NewHint(hint, 2, n, d)
	if err != nil {
		return err
	}
	q, r := out[0], out[1]
	api.AssertIsEqual(n, api.Add(api.Mul(q, d), r))
	for i := 0; i < count; i++ {
		cmp.NewBoundedComparator(api, big.NewInt(255), false).AssertIsLess(r, d)
	}
	return nil
}

// directIndex exercises reconstruction without q/r aliases.
func directIndex(api frontend.API, n, d frontend.Variable) error {
	out, err := api.Compiler().NewHint(hint, 2, n, d)
	if err != nil {
		return err
	}
	api.AssertIsEqual(n, api.Add(api.Mul(out[0], d), out[1]))
	return nil
}

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
