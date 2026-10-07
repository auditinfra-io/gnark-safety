// Package external stands for code in another package that receives a
// recursion witness's public inputs, such as a hasher or a commitment.
package external

import (
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/math/emulated"
)

// Digest folds the inputs into one element.
func Digest(f *emulated.Field[sw_bn254.ScalarField], inputs []emulated.Element[sw_bn254.ScalarField]) *emulated.Element[sw_bn254.ScalarField] {
	sum := f.Zero()
	for i := range inputs {
		sum = f.Add(sum, &inputs[i])
	}
	return sum
}
