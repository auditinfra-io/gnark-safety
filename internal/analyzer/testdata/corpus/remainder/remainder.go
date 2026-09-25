// Package remainder is the corpus for the canonical bound r < d of
// GNARK_HINT_RELATION_INCOMPLETE when d is known at compile time: bounds
// written as constants, bounds proved by range-checked limbs, and bounds
// inside a block that every successful path runs.
package remainder

import (
	"math"
	"math/big"

	"github.com/consensys/gnark/frontend"
)

const lanes = 17

func divModHint(_ *big.Int, inputs, outputs []*big.Int) error {
	outputs[0].Div(inputs[0], inputs[1])
	outputs[1].Mod(inputs[0], inputs[1])
	return nil
}

func splitHint(_ *big.Int, inputs, outputs []*big.Int) error {
	outputs[0].Rsh(inputs[0], 24)
	outputs[1].And(inputs[0], big.NewInt(1<<24-1))
	return nil
}

// divLanes bounds r by a constant, and does all its work in a block that runs
// whenever the function succeeds: not reported.
func divLanes(api frontend.API, x frontend.Variable) (q, r frontend.Variable, err error) {
	out, err := api.Compiler().NewHint(divModHint, 2, x, lanes)
	if err == nil {
		q, r = out[0], out[1]
		api.AssertIsLessOrEqual(r, lanes-1)
		api.AssertIsEqual(x, api.Add(api.Mul(q, lanes), r))
	}
	return
}

// divLanesExplicit returns the error explicitly: not reported.
func divLanesExplicit(api frontend.API, x frontend.Variable) (frontend.Variable, error) {
	out, err := api.Compiler().NewHint(divModHint, 2, x, lanes)
	if err == nil {
		api.AssertIsLessOrEqual(out[1], lanes-1)
		api.AssertIsEqual(x, api.Add(api.Mul(out[0], lanes), out[1]))
	}
	return out[0], err
}

// divLanesLoose allows r = d: reported.
func divLanesLoose(api frontend.API, x frontend.Variable) frontend.Variable {
	out, _ := api.Compiler().NewHint(divModHint, 2, x, lanes) // want GNARK_HINT_RELATION_INCOMPLETE:high
	api.AssertIsLessOrEqual(out[1], lanes)
	api.AssertIsEqual(x, api.Add(api.Mul(out[0], lanes), out[1]))
	return out[0]
}

// divLanesSwallowed runs its checks only when the hint succeeds, but returns
// success either way, so the bound can be skipped: reported.
func divLanesSwallowed(api frontend.API, x frontend.Variable) error {
	out, err := api.Compiler().NewHint(divModHint, 2, x, lanes) // want GNARK_HINT_RELATION_INCOMPLETE:high
	if err == nil {
		api.AssertIsLessOrEqual(out[1], lanes-1)
		api.AssertIsEqual(x, api.Add(api.Mul(out[0], lanes), out[1]))
	}
	return nil
}

// A 31-bit prime of the form 2^31 - 2^24 + 1.
var modulus = new(big.Int).SetUint64(2130706433)

type chip struct {
	api     frontend.API
	checker frontend.Rangechecker
	native  bool
}

// reduce proves r < modulus by splitting r into a 7-bit and a 24-bit limb and
// forcing the low limb to zero when the high limb is all ones. The limbs are
// range-checked in both branches: not reported.
func (c *chip) reduce(x frontend.Variable) frontend.Variable {
	out, err := c.api.Compiler().NewHint(divModHint, 2, x, modulus)
	if err != nil {
		panic(err)
	}
	quotient, remainder := out[0], out[1]
	c.checker.Check(quotient, 64)
	limbs, err := c.api.Compiler().NewHint(splitHint, 2, remainder)
	if err != nil {
		panic(err)
	}
	high, low := limbs[0], limbs[1]
	c.api.AssertIsEqual(c.api.Add(c.api.Mul(high, frontend.Variable(uint64(math.Pow(2, 24)))), low), remainder)
	if c.native {
		c.checker.Check(high, 7)
		c.checker.Check(low, 24)
	} else {
		c.api.ToBinary(high, 7)
		c.api.ToBinary(low, 24)
	}
	allOnes := c.api.IsZero(c.api.Sub(high, uint64(math.Pow(2, 7))-1))
	c.api.AssertIsEqual(c.api.Mul(allOnes, low), 0)
	c.api.AssertIsEqual(x, c.api.Add(c.api.Mul(quotient, modulus), remainder))
	return remainder
}

// reduceUnchecked omits the all-ones check, so r can reach 2^31 - 1, above
// the modulus: reported.
func (c *chip) reduceUnchecked(x frontend.Variable) frontend.Variable {
	out, _ := c.api.Compiler().NewHint(divModHint, 2, x, modulus) // want GNARK_HINT_RELATION_INCOMPLETE:high
	quotient, remainder := out[0], out[1]
	limbs, _ := c.api.Compiler().NewHint(splitHint, 2, remainder)
	high, low := limbs[0], limbs[1]
	c.api.AssertIsEqual(c.api.Add(c.api.Mul(high, 1<<24), low), remainder)
	c.api.ToBinary(high, 7)
	c.api.ToBinary(low, 24)
	c.api.AssertIsEqual(x, c.api.Add(c.api.Mul(quotient, modulus), remainder))
	return remainder
}

// reduceOneBranch range-checks the low limb in only one branch, so neither r nor
// the low limb (the remainder of the split by 2^24) is bounded: both hints are
// reported.
func (c *chip) reduceOneBranch(x frontend.Variable) frontend.Variable {
	out, _ := c.api.Compiler().NewHint(divModHint, 2, x, modulus) // want GNARK_HINT_RELATION_INCOMPLETE:high
	quotient, remainder := out[0], out[1]
	limbs, _ := c.api.Compiler().NewHint(splitHint, 2, remainder) // want GNARK_HINT_RELATION_INCOMPLETE:high
	high, low := limbs[0], limbs[1]
	c.api.AssertIsEqual(c.api.Add(c.api.Mul(high, 1<<24), low), remainder)
	if c.native {
		c.checker.Check(high, 7)
		c.checker.Check(low, 24)
	} else {
		c.api.ToBinary(high, 7)
	}
	allOnes := c.api.IsZero(c.api.Sub(high, 127))
	c.api.AssertIsEqual(c.api.Select(allOnes, low, 0), 0)
	c.api.AssertIsEqual(x, c.api.Add(c.api.Mul(quotient, modulus), remainder))
	return remainder
}

// A modulus that init changes cannot be trusted at compile time.
var changedModulus = new(big.Int).SetUint64(2130706433)

func init() {
	changedModulus.SetUint64(1 << 40)
}

// reduceChanged proves r < 2130706433, but the divisor is not that value by
// the time the circuit compiles: reported.
func (c *chip) reduceChanged(x frontend.Variable) frontend.Variable {
	out, _ := c.api.Compiler().NewHint(divModHint, 2, x, changedModulus) // want GNARK_HINT_RELATION_INCOMPLETE:high
	quotient, remainder := out[0], out[1]
	c.api.ToBinary(remainder, 30)
	c.api.AssertIsEqual(x, c.api.Add(c.api.Mul(quotient, changedModulus), remainder))
	return remainder
}

// rangeCheck delegates to a helper that checks nothing in one configuration,
// so the limb split is not bounded on every path: reported.
func (c *chip) rangeCheck(x frontend.Variable) {
	out, _ := c.api.Compiler().NewHint(splitHint, 2, x) // want GNARK_HINT_RELATION_INCOMPLETE:high
	high, low := out[0], out[1]
	c.api.AssertIsEqual(c.api.Add(c.api.Mul(high, uint64(math.Pow(2, 24))), low), x)
	c.check(high, 8)
	c.check(low, 24)
}

func (c *chip) check(v frontend.Variable, bits int) {
	switch {
	case c.native:
	default:
		c.checker.Check(v, bits)
	}
}
