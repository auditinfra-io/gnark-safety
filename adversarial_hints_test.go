package gnarksafety

import (
	"fmt"
	"math/big"
)

// fixedHint returns test-only advice after checking the expected public input.
func fixedHint(n, d, q, r int64) func(*big.Int, []*big.Int, []*big.Int) error {
	return func(_ *big.Int, inputs, outputs []*big.Int) error {
		if len(inputs) != 2 || len(outputs) != 2 {
			return fmt.Errorf("quotient/remainder hint expects 2 inputs and 2 outputs")
		}
		if inputs[0].Cmp(big.NewInt(n)) != 0 || inputs[1].Cmp(big.NewInt(d)) != 0 {
			return fmt.Errorf("adversarial hint expected n=%d,d=%d", n, d)
		}
		outputs[0].SetInt64(q)
		outputs[1].SetInt64(r)
		return nil
	}
}

var (
	InvalidQuotientRemainderHint = fixedHint(17, 5, 2, 7)
	ZeroDivisorHint              = fixedHint(17, 0, 0, 17)
)
