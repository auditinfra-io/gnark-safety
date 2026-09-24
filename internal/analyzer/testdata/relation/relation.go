package relation

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/cmp"
)

func hint(_ *big.Int, _ []*big.Int, _ []*big.Int) error { return nil }

const (
	quotientIndex  = 1 - 1
	remainderIndex = quotientIndex + 1
)

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

func unusedRemainder(api frontend.API, n, d frontend.Variable) error {
	out, err := api.Compiler().NewHint(hint, 2, n, d)
	if err != nil {
		return err
	}
	q, _ := out[quotientIndex], out[remainderIndex]
	api.AssertIsEqual(q, n)
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

func assertCanonical(api frontend.API, r, d frontend.Variable) {
	cmp.NewBoundedComparator(api, big.NewInt(255), false).AssertIsLess(r, d)
}

func assertCanonicalLessOrEqual(api frontend.API, r, d frontend.Variable) {
	api.AssertIsLessOrEqual(r, api.Sub(d, 1))
}

func constrain8(api frontend.API, value frontend.Variable) {
	api.ToBinary(value, 8)
}

func helperSafe(api frontend.API, n, d frontend.Variable) error {
	out, err := api.Compiler().NewHint(hint, 2, n, d)
	if err != nil {
		return err
	}
	q, r := out[0], out[1]
	api.AssertIsEqual(n, api.Add(api.Mul(q, d), r))
	constrain8(api, q)
	constrain8(api, r)
	constrain8(api, d)
	assertCanonical(api, r, d)
	return nil
}

func helperConditional(api frontend.API, n, d frontend.Variable, checked bool) error {
	out, err := api.Compiler().NewHint(hint, 2, n, d)
	if err != nil {
		return err
	}
	q, r := out[0], out[1]
	api.AssertIsEqual(n, api.Add(api.Mul(q, d), r))
	if checked {
		assertCanonical(api, r, d)
	}
	return nil
}

func successfulEarlyReturn(api frontend.API, n, d frontend.Variable, skip bool) error {
	out, err := api.Compiler().NewHint(hint, 2, n, d)
	if err != nil {
		return err
	}
	q, r := out[0], out[1]
	api.AssertIsEqual(n, api.Add(api.Mul(q, d), r))
	if skip {
		return nil
	}
	cmp.NewBoundedComparator(api, big.NewInt(255), false).AssertIsLess(r, d)
	return nil
}

func lessOrEqualSafe(api frontend.API, n, d frontend.Variable) error {
	out, err := api.Compiler().NewHint(hint, 2, n, d)
	if err != nil {
		return err
	}
	api.AssertIsEqual(n, api.Add(api.Mul(out[quotientIndex], d), out[remainderIndex]))
	api.AssertIsLessOrEqual(out[remainderIndex], api.Sub(d, 1))
	return nil
}

func helperLessOrEqualSafe(api frontend.API, n, d frontend.Variable) error {
	out, err := api.Compiler().NewHint(hint, 2, n, d)
	if err != nil {
		return err
	}
	q, r := out[quotientIndex], out[remainderIndex]
	api.AssertIsEqual(n, api.Add(api.Mul(q, d), r))
	assertCanonicalLessOrEqual(api, r, d)
	return nil
}
