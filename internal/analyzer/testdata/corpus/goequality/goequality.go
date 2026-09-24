// Package goequality is the corpus for GNARK_GO_EQUALITY_ON_VARIABLE.
package goequality

import (
	"errors"

	"github.com/consensys/gnark/frontend"
)

type Circuit struct {
	Flag frontend.Variable
	X, Y frontend.Variable
	Mode frontend.Variable
	// Depth is not a witness element: it holds a Go value at compile time.
	Depth frontend.Variable `gnark:"-"`
	Count int
}

func (c *Circuit) Define(api frontend.API) error {
	if c.Flag == 1 { // want GNARK_GO_EQUALITY_ON_VARIABLE
		api.AssertIsEqual(c.X, c.Y)
	}
	if c.X != c.Y { // want GNARK_GO_EQUALITY_ON_VARIABLE
		api.AssertIsDifferent(c.X, 0)
	}
	switch c.Mode { // want GNARK_GO_EQUALITY_ON_VARIABLE
	case 0:
		api.AssertIsEqual(c.X, 0)
	}
	if c.Depth == 3 { // compile-time parameter: not reported
		api.AssertIsEqual(c.Y, 0)
	}
	if c.Count == 2 { // plain int: not reported
		api.AssertIsEqual(c.Y, 1)
	}
	var optional frontend.Variable
	if optional == nil { // nil check: not reported
		optional = 0
	}
	switch v := c.X.(type) { // type switch: not reported
	case int:
		_ = v
	}
	api.AssertIsEqual(optional, 0)
	return c.check(api)
}

// check compares variables only to guard Go control flow that emits no
// constraints, such as API-misuse errors: not reported. A comparison whose
// result is kept for later is not followed (a documented miss).
func (c *Circuit) check(api frontend.API) error {
	if c.X == c.Y {
		return errors.New("inputs must be distinct objects")
	}
	same := c.X == c.Y
	_ = same
	if c.Mode != nil && c.Flag == 0 { // want GNARK_GO_EQUALITY_ON_VARIABLE
		constrainHelper(api, c.X)
	}
	return nil
}

// constrainHelper takes the API, so calling it can add constraints.
func constrainHelper(api frontend.API, x frontend.Variable) { api.AssertIsBoolean(x) }
