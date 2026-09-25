// Package good loads and has one finding.
package good

import "github.com/consensys/gnark/frontend"

type Circuit struct {
	X frontend.Variable
}

func (c *Circuit) Define(api frontend.API) error {
	api.AssertIsEqual(c.X, c.X)
	return nil
}
