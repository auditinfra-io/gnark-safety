// Package broken does not type-check, like a package that only builds for
// another platform.
package broken

import "github.com/consensys/gnark/frontend"

type Circuit struct {
	X frontend.Variable
}

func (c *Circuit) Define(api frontend.API) error {
	var count int = "one"
	_ = count
	api.AssertIsEqual(c.X, 0)
	return nil
}
