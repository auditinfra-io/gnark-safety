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

// pad XORs a padding mask into data. The mask holds only Go constants, so
// comparing its elements chooses code, not constraints: not reported. Once a
// witness value is stored into a slice, directly or through an alias sharing
// its elements, comparing its elements is reported.
func (c *Circuit) pad(api frontend.API, data []frontend.Variable) {
	mask := make([]frontend.Variable, len(data))
	for i := range mask {
		mask[i] = 0
	}
	mask[len(mask)-1] = 1
	for i := range data {
		if mask[i] != 0 {
			data[i] = api.Xor(data[i], mask[i])
		}
	}
	mixed := make([]frontend.Variable, 2)
	mixed[0] = c.X
	if mixed[0] == 0 { // want GNARK_GO_EQUALITY_ON_VARIABLE
		api.AssertIsEqual(c.Y, 0)
	}
	shared := make([]frontend.Variable, 1)
	alias := shared
	alias[0] = c.Y
	if shared[0] != 0 { // want GNARK_GO_EQUALITY_ON_VARIABLE
		api.AssertIsEqual(c.X, 1)
	}
}
