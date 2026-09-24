package gnarksafety

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
)

// divisionSpecification is deliberately ordinary integer code. It is the
// independent semantic oracle used by differential tests; it does not reuse a
// circuit gadget or field operation.
func divisionSpecification(n, d, q, r *big.Int) bool {
	limit := big.NewInt(1 << valueBits)
	for _, value := range []*big.Int{n, d, q, r} {
		if value.Sign() < 0 || value.Cmp(limit) >= 0 {
			return false
		}
	}
	if d.Sign() == 0 || r.Cmp(d) >= 0 {
		return false
	}
	reconstructed := new(big.Int).Add(new(big.Int).Mul(q, d), r)
	return reconstructed.Cmp(n) == 0
}

func TestHintMatchesSpecificationExhaustively(t *testing.T) {
	for n := int64(0); n < 1<<valueBits; n++ {
		for d := int64(1); d < 1<<valueBits; d++ {
			inputs := []*big.Int{big.NewInt(n), big.NewInt(d)}
			outputs := []*big.Int{new(big.Int), new(big.Int)}
			if err := QuotientRemainderHint(nil, inputs, outputs); err != nil {
				t.Fatalf("n=%d d=%d: %v", n, d, err)
			}
			if !divisionSpecification(inputs[0], inputs[1], outputs[0], outputs[1]) {
				t.Fatalf("specification rejected n=%d d=%d q=%s r=%s", n, d, outputs[0], outputs[1])
			}
			if outputs[0].Sign() > 0 {
				alternativeQ := new(big.Int).Sub(outputs[0], big.NewInt(1))
				alternativeR := new(big.Int).Add(outputs[1], inputs[1])
				if divisionSpecification(inputs[0], inputs[1], alternativeQ, alternativeR) {
					t.Fatalf("specification accepted noncanonical n=%d d=%d q=%s r=%s", n, d, alternativeQ, alternativeR)
				}
			}
		}
	}
}

func TestCorrectedCircuitMatchesSpecificationMatrix(t *testing.T) {
	type sample struct{ n, d, q, r int64 }
	samples := []sample{
		{0, 1, 0, 0}, {17, 5, 3, 2}, {255, 1, 255, 0}, {255, 255, 1, 0},
		{17, 5, 2, 7}, {17, 5, 4, -3}, {255, 255, -1, 510}, {17, 0, 0, 17},
	}
	builders := []struct {
		name string
		new  frontend.NewBuilder
	}{{"r1cs", r1cs.NewBuilder[constraint.U64]}, {"scs", scs.NewBuilder[constraint.U64]}}
	curves := []ecc.ID{ecc.BN254, ecc.BLS12_381}

	for _, curve := range curves {
		for _, builder := range builders {
			t.Run(curve.String()+"/"+builder.name, func(t *testing.T) {
				ccs, err := frontend.Compile(curve.ScalarField(), builder.new, &CorrectedCircuit{})
				if err != nil {
					t.Fatal(err)
				}
				for _, tc := range samples {
					name := fmt.Sprintf("n%d_d%d_q%d_r%d", tc.n, tc.d, tc.q, tc.r)
					t.Run(name, func(t *testing.T) {
						values := []*big.Int{big.NewInt(tc.n), big.NewInt(tc.d), big.NewInt(tc.q), big.NewInt(tc.r)}
						want := divisionSpecification(values[0], values[1], values[2], values[3])
						witness, err := frontend.NewWitness(&CorrectedCircuit{N: tc.n, D: tc.d}, curve.ScalarField())
						if err != nil {
							t.Fatal(err)
						}
						hint := bigIntHint(values[0], values[1], values[2], values[3])
						err = ccs.IsSolved(witness, solver.OverrideHint(solver.GetHintID(QuotientRemainderHint), hint))
						if got := err == nil; got != want {
							t.Fatalf("circuit acceptance=%t, specification=%t (solver error: %v)", got, want, err)
						}
					})
				}
			})
		}
	}
}
