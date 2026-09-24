package divmod

import (
	"fmt"
	"math/big"
)

// QuotientRemainderHint computes Euclidean quotient and remainder as witness
// values. Its result is advice only: circuits must constrain both outputs.
func QuotientRemainderHint(_ *big.Int, inputs, outputs []*big.Int) error {
	if len(inputs) != 2 || len(outputs) != 2 {
		return fmt.Errorf("quotient/remainder hint expects 2 inputs and 2 outputs")
	}
	if inputs[1].Sign() == 0 {
		return fmt.Errorf("division by zero")
	}
	outputs[0].QuoRem(inputs[0], inputs[1], outputs[1])
	return nil
}
