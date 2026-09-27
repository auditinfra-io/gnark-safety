package analyzer

import (
	"context"
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
)

// TestFieldConstant: a compile-time value counts as bound evidence only if
// the circuit sees the same number. A constant at or above the field modulus
// is reduced by it, so p+5 is 5 in the circuit, not a divisor above 100.
func TestFieldConstant(t *testing.T) {
	p := ecc.BN254.ScalarField()
	info := &types.Info{Types: map[ast.Expr]types.TypeAndValue{}}
	ev := newEvaluator(info, nil)
	literal := func(v *big.Int) ast.Expr {
		e := &ast.BasicLit{Kind: token.INT, Value: v.String()}
		info.Types[e] = types.TypeAndValue{Value: constant.Make(v)}
		return e
	}
	add := func(a *big.Int, b int64) *big.Int { return new(big.Int).Add(a, big.NewInt(b)) }
	limit := new(big.Int).Lsh(big.NewInt(1), maximumReconstructionBits)
	for _, tc := range []struct {
		name  string
		value *big.Int
		field *big.Int
		want  bool
	}{
		{"p+5 is 5 in the field", add(p, 5), p, false},
		{"p is 0 in the field", p, p, false},
		{"p-1 is itself", add(p, -1), p, true},
		{"negative values wrap", big.NewInt(-1), p, false},
		{"without a field, 2^240 is not trusted", limit, nil, false},
		{"without a field, 2^240-1 is", add(limit, -1), nil, true},
		{"with BN254, 2^240 is", limit, p, true},
	} {
		got := fieldConstant(ev, literal(tc.value), tc.field)
		if (got != nil) != tc.want || (got != nil && got.Cmp(tc.value) != 0) {
			t.Errorf("%s: fieldConstant = %v, want trusted=%v", tc.name, got, tc.want)
		}
	}
}

// TestExact: Go arithmetic on variables wraps or rounds in its type, so the
// evaluator trusts only results that the type holds exactly.
func TestExact(t *testing.T) {
	pow := func(n uint) *big.Int { return new(big.Int).Lsh(big.NewInt(1), n) }
	for _, tc := range []struct {
		name  string
		value *big.Int
		kind  types.BasicKind
		want  bool
	}{
		{"2^62 fits int", pow(62), types.Int, true},
		{"2^64+5 wraps in int", new(big.Int).Add(pow(64), big.NewInt(5)), types.Int, false},
		{"2^64-1 fits uint64", new(big.Int).Sub(pow(64), big.NewInt(1)), types.Uint64, true},
		{"2^60 is exact in float64", pow(60), types.Float64, true},
		{"2^60+1 rounds in float64", new(big.Int).Add(pow(60), big.NewInt(1)), types.Float64, false},
		{"2^24+1 rounds in float32", new(big.Int).Add(pow(24), big.NewInt(1)), types.Float32, false},
	} {
		if got := exact(tc.value, types.Typ[tc.kind]); got != tc.want {
			t.Errorf("%s: exact = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// TestConfiguredFieldTrustsLargerConstants: with --field, a divisor below
// the modulus but above 2^240 is trusted, so the range check of r proves the
// bound; without it, the same code is reported.
func TestConfiguredFieldTrustsLargerConstants(t *testing.T) {
	pattern := []string{"./internal/analyzer/testdata/corpus/remainder"}
	reported := func(opts Options) map[string]bool {
		r, err := ScanContext(context.Background(), "../..", pattern, opts)
		if err != nil {
			t.Fatal(err)
		}
		got := map[string]bool{}
		for _, f := range r.Findings {
			got[f.Function] = true
		}
		return got
	}
	unconfigured := reported(Options{})
	configured := reported(Options{FieldModulus: ecc.BN254.ScalarField(), FieldName: "BN254 scalar field"})
	if !unconfigured["largeDivisor"] || configured["largeDivisor"] {
		t.Errorf("largeDivisor: reported without --field=%v, with=%v; want true, false", unconfigured["largeDivisor"], configured["largeDivisor"])
	}
	for _, function := range []string{"powerDivisor", "wrappedBound"} {
		if !configured[function] {
			t.Errorf("%s: must stay reported with --field bn254", function)
		}
	}
}
