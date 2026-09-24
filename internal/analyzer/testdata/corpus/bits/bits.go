// Package bits is the corpus for GNARK_BITS_UNCONSTRAINED.
package bits

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
	mathbits "github.com/consensys/gnark/std/math/bits"
)

func hint(_ *big.Int, _ []*big.Int, _ []*big.Int) error { return nil }

// evenByte means to prove X < 256 and X even, but its digits are free.
func evenByte(api frontend.API, x frontend.Variable) {
	b := mathbits.ToBinary(api, x, mathbits.WithNbDigits(8), mathbits.WithUnconstrainedOutputs()) // want GNARK_BITS_UNCONSTRAINED:high
	api.AssertIsEqual(b[0], 0)
}

// rangeOnly treats an unconstrained decomposition as a range check.
func rangeOnly(api frontend.API, x frontend.Variable) {
	mathbits.ToBinary(api, x, mathbits.WithNbDigits(8), mathbits.WithUnconstrainedOutputs()) // want GNARK_BITS_UNCONSTRAINED:high
}

// fromAdvice recomposes hint outputs without checking they are bits.
func fromAdvice(api frontend.API, x frontend.Variable) frontend.Variable {
	out, _ := api.Compiler().NewHint(hint, 8, x)
	return mathbits.FromBinary(api, out, mathbits.WithUnconstrainedInputs()) // want GNARK_BITS_UNCONSTRAINED:medium
}

// The cases below constrain or hand off their digits and are not reported.

func booleanLoop(api frontend.API, x frontend.Variable) {
	b := mathbits.ToBinary(api, x, mathbits.WithNbDigits(8), mathbits.WithUnconstrainedOutputs())
	for _, bit := range b {
		api.AssertIsBoolean(bit)
	}
	api.AssertIsEqual(b[0], 0)
}

func recomposed(api frontend.API, x frontend.Variable) frontend.Variable {
	b := mathbits.ToBinary(api, x, mathbits.WithNbDigits(8), mathbits.WithUnconstrainedOutputs())
	return api.FromBinary(b...)
}

func mustBeBits(api frontend.API, digits []frontend.Variable) {
	for _, d := range digits {
		api.AssertIsBoolean(d)
	}
}

func handedOff(api frontend.API, x frontend.Variable) {
	b := mathbits.ToBinary(api, x, mathbits.WithNbDigits(8), mathbits.WithUnconstrainedOutputs())
	mustBeBits(api, b)
}

func returned(api frontend.API, x frontend.Variable) []frontend.Variable {
	return mathbits.ToBinary(api, x, mathbits.WithNbDigits(8), mathbits.WithUnconstrainedOutputs())
}

func fromConstrainedBits(api frontend.API, x frontend.Variable) frontend.Variable {
	b := mathbits.ToBinary(api, x, mathbits.WithNbDigits(8))
	return mathbits.FromBinary(api, b[:4], mathbits.WithUnconstrainedInputs())
}

func fromParameter(api frontend.API, digits []frontend.Variable) frontend.Variable {
	return mathbits.FromBinary(api, digits, mathbits.WithUnconstrainedInputs())
}

func fromCheckedAdvice(api frontend.API, x frontend.Variable) frontend.Variable {
	out, _ := api.Compiler().NewHint(hint, 8, x)
	for i := range out {
		api.AssertIsBoolean(out[i])
	}
	return mathbits.FromBinary(api, out, mathbits.WithUnconstrainedInputs())
}
