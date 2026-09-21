package hintsafetydemo

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

// InvalidQuotientRemainderHint is test-only adversarial advice for n=17,d=5.
// It preserves reconstruction (2*5+7=17) but violates the Euclidean r<d rule.
func InvalidQuotientRemainderHint(_ *big.Int, inputs, outputs []*big.Int) error {
	if len(inputs) != 2 || len(outputs) != 2 {
		return fmt.Errorf("quotient/remainder hint expects 2 inputs and 2 outputs")
	}
	if inputs[0].Cmp(big.NewInt(17)) != 0 || inputs[1].Cmp(big.NewInt(5)) != 0 {
		return fmt.Errorf("adversarial hint only supports n=17,d=5")
	}
	outputs[0].SetUint64(2)
	outputs[1].SetUint64(7)
	return nil
}

// ZeroDivisorHint is test-only adversarial advice for n=17,d=0. It returns
// successfully and preserves reconstruction, isolating the circuit's d != 0
// constraint from the honest hint's division-by-zero error.
func ZeroDivisorHint(_ *big.Int, inputs, outputs []*big.Int) error {
	if len(inputs) != 2 || len(outputs) != 2 {
		return fmt.Errorf("quotient/remainder hint expects 2 inputs and 2 outputs")
	}
	if inputs[0].Cmp(big.NewInt(17)) != 0 || inputs[1].Sign() != 0 {
		return fmt.Errorf("zero-divisor hint only supports n=17,d=0")
	}
	outputs[0].SetUint64(0)
	outputs[1].SetUint64(17)
	return nil
}
