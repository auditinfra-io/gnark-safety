// Package config is the corpus for configuration rules.
package config

import (
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/std/math/bits"
	"github.com/consensys/gnark/std/math/cmp"
	_ "github.com/consensys/gnark/test/unsafekzg" // want GNARK_UNSAFE_SETUP:medium
)

func decompose(api frontend.API, x frontend.Variable) []frontend.Variable {
	return bits.ToBinary(api, x, bits.OmitModulusCheck()) // want GNARK_BITS_OMIT_MODULUS_CHECK
}

func compare(api frontend.API, a, b frontend.Variable) {
	loose := cmp.NewBoundedComparator(api, big.NewInt(1<<16), true) // want GNARK_COMPARATOR_NONDETERMINISTIC
	loose.AssertIsLess(a, b)
	strict := cmp.NewBoundedComparator(api, big.NewInt(1<<16), false)
	strict.AssertIsLess(a, b)
}

type empty struct{ X frontend.Variable }

func (e *empty) Define(api frontend.API) error { return nil }

func compile() error {
	_, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &empty{}, frontend.IgnoreUnconstrainedInputs()) // want GNARK_IGNORE_UNCONSTRAINED_INPUTS
	return err
}
