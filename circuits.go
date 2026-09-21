package hintsafetydemo

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/cmp"
)

const valueBits = 8

// VulnerableCircuit demonstrates an incomplete hint-output check. N and D are
// public; Q and R are private variables produced by QuotientRemainderHint.
type VulnerableCircuit struct {
	N frontend.Variable `gnark:",public"`
	D frontend.Variable `gnark:",public"`
}

func constrainDivision(api frontend.API, n, d frontend.Variable, enforceCanonicalRemainder bool) error {
	qr, err := api.Compiler().NewHint(QuotientRemainderHint, 2, n, d)
	if err != nil {
		return err
	}
	q, r := qr[0], qr[1]

	// Every value is an unsigned 8-bit integer. Thus q*d+r <= 255*255+255
	// = 65,280, far below BN254's scalar-field modulus, so the equality cannot
	// hold merely by wrapping around the field.
	api.ToBinary(n, valueBits)
	api.ToBinary(d, valueBits)
	api.ToBinary(q, valueBits)
	api.ToBinary(r, valueBits)
	api.AssertIsDifferent(d, 0)
	api.AssertIsEqual(n, api.Add(api.Mul(q, d), r))

	if enforceCanonicalRemainder {
		// Since r and d are in [0,255], |r-d| <= 255.
		cmp.NewBoundedComparator(api, big.NewInt(255), false).AssertIsLess(r, d)
	}
	return nil
}

func (c *VulnerableCircuit) Define(api frontend.API) error {
	return constrainDivision(api, c.N, c.D, false) // deliberately omits r < d
}

// CorrectedCircuit is identical except that it enforces the missing r < d rule.
type CorrectedCircuit struct {
	N frontend.Variable `gnark:",public"`
	D frontend.Variable `gnark:",public"`
}

func (c *CorrectedCircuit) Define(api frontend.API) error {
	return constrainDivision(api, c.N, c.D, true)
}
