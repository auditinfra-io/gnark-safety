// Package tags is the corpus for GNARK_TAG_VISIBILITY_AS_NAME.
package tags

import "github.com/consensys/gnark/frontend"

type Circuit struct {
	Threshold frontend.Variable `gnark:"public"`  // want GNARK_TAG_VISIBILITY_AS_NAME:high
	Nonce     frontend.Variable `gnark:"secret"`  // want GNARK_TAG_VISIBILITY_AS_NAME:info
	Trailing  frontend.Variable `gnark:"public,"` // want GNARK_TAG_VISIBILITY_AS_NAME:high

	Root     frontend.Variable `gnark:",public"`
	Named    frontend.Variable `gnark:"root,public"`
	Secret   frontend.Variable `gnark:",secret"`
	Omitted  frontend.Variable `gnark:"-"`
	Capital  frontend.Variable `gnark:"Public"`
	Untagged frontend.Variable
	JSONOnly frontend.Variable `json:"public"`
	BothTags frontend.Variable `json:"x" gnark:",public"`
}

func (c *Circuit) Define(api frontend.API) error { return nil }
