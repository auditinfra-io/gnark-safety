// Package gnarkapi identifies gnark API objects by resolved type rather than
// by spelling, so import aliases, embedding, and unrelated methods that share
// a name are handled consistently by every command.
package gnarkapi

import (
	"go/ast"
	"go/types"
)

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

// HintIdentity names the function passed as a hint: "pkg/path.Func" for a
// function (including an instantiated generic), "(recv).Method" for a
// method value, and "unknown" when the hint is chosen dynamically.
func HintIdentity(info *types.Info, e ast.Expr) string {
	switch x := e.(type) {
	case *ast.ParenExpr:
		return HintIdentity(info, x.X)
	case *ast.IndexExpr:
		return HintIdentity(info, x.X)
	case *ast.IndexListExpr:
		return HintIdentity(info, x.X)
	}
	var obj types.Object
	switch x := e.(type) {
	case *ast.Ident:
		obj = info.Uses[x]
	case *ast.SelectorExpr:
		obj = info.Uses[x.Sel]
	}
	f, ok := obj.(*types.Func)
	if !ok || f.Pkg() == nil {
		return "unknown"
	}
	if sig, ok := f.Type().(*types.Signature); ok && sig.Recv() != nil {
		receiver := types.TypeString(sig.Recv().Type(), func(p *types.Package) string { return p.Path() })
		return "(" + receiver + ")." + f.Name()
	}
	return f.Pkg().Path() + "." + f.Name()
}
