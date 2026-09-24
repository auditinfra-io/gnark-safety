package gnarksafety

import (
	"fmt"
	"math/big"
)

type hintMutationClass string

const (
	mutationHonest              hintMutationClass = "honest baseline"
	mutationSingleOutput        hintMutationClass = "single-output change"
	mutationNonCanonical        hintMutationClass = "reconstruction-preserving noncanonical output"
	mutationNegative            hintMutationClass = "negative field representation"
	mutationOutsideDeclaredBits hintMutationClass = "outside declared bit width"
	mutationFieldBoundary       hintMutationClass = "field-modulus boundary"
)

type hintMutation struct {
	name                   string
	class                  hintMutationClass
	q, r                   *big.Int
	vulnerableShouldAccept bool
	correctedShouldAccept  bool
}

func integer(value int64) *big.Int { return new(big.Int).SetInt64(value) }

// quotientRemainderMutations begins with honest advice and then changes each
// output independently and in security-relevant combinations. Callers get
// fresh big.Int values so an executing hint cannot corrupt another test case.
func quotientRemainderMutations(field *big.Int) []hintMutation {
	return []hintMutation{
		{name: "honest", class: mutationHonest, q: integer(3), r: integer(2), vulnerableShouldAccept: true, correctedShouldAccept: true},
		{name: "quotient only", class: mutationSingleOutput, q: integer(4), r: integer(2)},
		{name: "remainder only", class: mutationSingleOutput, q: integer(3), r: integer(3)},
		{name: "noncanonical remainder", class: mutationNonCanonical, q: integer(2), r: integer(7), vulnerableShouldAccept: true},
		{name: "negative quotient", class: mutationNegative, q: integer(-1), r: integer(22)},
		{name: "negative remainder", class: mutationNegative, q: integer(4), r: integer(-3)},
		{name: "quotient above eight bits", class: mutationOutsideDeclaredBits, q: integer(256), r: integer(-1263)},
		{name: "remainder above eight bits", class: mutationOutsideDeclaredBits, q: integer(-48), r: integer(257)},
		// A hint output is a field element: field modulus is the same element as
		// zero. The vulnerable circuit consequently accepts this alias, while the
		// corrected remainder bound still rejects r=17.
		{name: "quotient at field modulus", class: mutationFieldBoundary, q: new(big.Int).Set(field), r: integer(17), vulnerableShouldAccept: true},
		{name: "remainder at field modulus", class: mutationFieldBoundary, q: integer(0), r: new(big.Int).Set(field)},
	}
}

func bigIntHint(n, d, q, r *big.Int) func(*big.Int, []*big.Int, []*big.Int) error {
	return func(_ *big.Int, inputs, outputs []*big.Int) error {
		if len(inputs) != 2 || len(outputs) != 2 {
			return fmt.Errorf("quotient/remainder hint expects 2 inputs and 2 outputs")
		}
		if inputs[0].Cmp(n) != 0 || inputs[1].Cmp(d) != 0 {
			return fmt.Errorf("adversarial hint expected n=%s,d=%s", n, d)
		}
		outputs[0].Set(q)
		outputs[1].Set(r)
		return nil
	}
}

// fixedHint returns test-only advice after checking the expected public input.
func fixedHint(n, d, q, r int64) func(*big.Int, []*big.Int, []*big.Int) error {
	return bigIntHint(integer(n), integer(d), integer(q), integer(r))
}

var (
	InvalidQuotientRemainderHint = fixedHint(17, 5, 2, 7)
	ZeroDivisorHint              = fixedHint(17, 0, 0, 17)
)
