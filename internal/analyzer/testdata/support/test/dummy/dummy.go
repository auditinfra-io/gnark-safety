// Package dummy sits under a test directory, so its findings are downgraded
// to low unless test-support severities are kept.
package dummy

import "github.com/consensys/gnark/frontend"

type Circuit struct {
	Count frontend.Variable `gnark:",public"`
}

// Define marks the input as used, as dummy circuits for tests do.
func (c *Circuit) Define(api frontend.API) error {
	api.AssertIsEqual(c.Count, c.Count)
	return nil
}
