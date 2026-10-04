// Package broken imports gnark but does not type-check.
package broken

import "github.com/consensys/gnark/frontend"

type Circuit struct{ X frontend.Variable }

func (c *Circuit) Define(api frontend.API) error {
	var n int = "not an int"
	_ = n
	return nil
}
