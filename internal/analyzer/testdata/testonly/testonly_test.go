package testonly

import (
	"testing"

	"github.com/consensys/gnark/frontend"
)

// vulnerableInTest omits r < d, but only test code contains it.
func vulnerableInTest(api frontend.API, n, d frontend.Variable) error {
	out, err := api.Compiler().NewHint(hint, 2, n, d)
	if err != nil {
		return err
	}
	q, r := out[0], out[1]
	api.AssertIsEqual(n, api.Add(api.Mul(q, d), r))
	return nil
}

func TestReferences(t *testing.T) { _, _ = safe, vulnerableInTest }
