// Package gnarkapi identifies gnark API objects by resolved type rather than
// by spelling, so import aliases, embedding, and unrelated methods that share
// a name are handled consistently by every command.
package gnarkapi

import "go/types"

// FrontendPath is the import path of gnark's circuit frontend.
const FrontendPath = "github.com/consensys/gnark/frontend"

// hintReceivers are the frontend interfaces that declare NewHint.
// API.NewHint is deprecated in favor of Compiler.NewHint but is still
// exported by gnark v0.16.3; ignoring it would make those circuits scan as
// having no hints at all.
var hintReceivers = map[string]bool{"API": true, "Compiler": true}

// IsNewHint reports whether obj is gnark's frontend NewHint method. Methods
// promoted through embedding resolve to the declaring interface and match.
func IsNewHint(obj types.Object) bool {
	f, ok := obj.(*types.Func)
	if !ok || f.Name() != "NewHint" || f.Pkg() == nil || f.Pkg().Path() != FrontendPath {
		return false
	}
	sig, ok := f.Type().(*types.Signature)
	if !ok || sig.Recv() == nil {
		return false
	}
	named, ok := types.Unalias(sig.Recv().Type()).(*types.Named)
	return ok && hintReceivers[named.Obj().Name()]
}
