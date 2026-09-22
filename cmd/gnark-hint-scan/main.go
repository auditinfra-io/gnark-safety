// gnark-hint-scan inventories direct calls to gnark's Compiler.NewHint API.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/tools/go/packages"
)

const schemaVersion = "1.0"

var limitations = []string{
	"Inventory only: constraint completeness and circuit soundness were not analyzed.",
	"Only direct calls to github.com/consensys/gnark/frontend.Compiler.NewHint are reported; reachability and call graphs are not analyzed.",
	"Dynamically selected hint functions and non-constant output counts may be reported as unknown.",
}

type unknownInt struct{ Value *int }

func (v unknownInt) MarshalJSON() ([]byte, error) {
	if v.Value == nil {
		return json.Marshal("unknown")
	}
	return json.Marshal(*v.Value)
}
func (v *unknownInt) UnmarshalJSON(data []byte) error {
	if string(data) == `"unknown"` {
		v.Value = nil
		return nil
	}
	var n int
	if err := json.Unmarshal(data, &n); err != nil {
		return err
	}
	v.Value = &n
	return nil
}

type hintRecord struct {
	Package     string     `json:"package"`
	File        string     `json:"file"`
	Line        int        `json:"line"`
	Column      int        `json:"column"`
	Function    string     `json:"function"`
	Hint        string     `json:"hint"`
	OutputCount unknownInt `json:"output_count"`
	InputCount  unknownInt `json:"input_count"`
}
type report struct {
	SchemaVersion string       `json:"schema_version"`
	Hints         []hintRecord `json:"hints"`
	Diagnostics   []string     `json:"diagnostics"`
	Limitations   []string     `json:"limitations"`
}

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, ".")) }

func run(args []string, stdout, stderr io.Writer, dir string) int {
	if len(args) == 0 || args[0] != "scan" {
		fmt.Fprintln(stderr, "usage: gnark-hint-scan scan [--format text|json] <package patterns...>")
		return 2
	}
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	format := fs.String("format", "text", "output format: text or json")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	if (*format != "text" && *format != "json") || fs.NArg() == 0 {
		fmt.Fprintln(stderr, "scan requires package patterns and --format must be text or json")
		return 2
	}
	r, err := scan(dir, fs.Args())
	if err != nil {
		fmt.Fprintf(stderr, "gnark-hint-scan: %v\n", err)
		return 2
	}
	if *format == "json" {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(r); err != nil {
			fmt.Fprintf(stderr, "gnark-hint-scan: %v\n", err)
			return 2
		}
		return 0
	}
	for _, h := range r.Hints {
		fmt.Fprintf(stdout, "%s:%d:%d: %s: %s (hint=%s, outputs=%s, inputs=%s)\n", h.File, h.Line, h.Column, h.Package, h.Function, h.Hint, display(h.OutputCount), display(h.InputCount))
	}
	if len(r.Hints) == 0 {
		fmt.Fprintln(stdout, "No direct gnark hint calls found in the scanned packages.")
	}
	fmt.Fprintln(stdout, "Inventory only: constraint completeness and circuit soundness were not analyzed.")
	return 0
}

func display(v unknownInt) string {
	if v.Value == nil {
		return "unknown"
	}
	return fmt.Sprint(*v.Value)
}

func scan(dir string, patterns []string) (report, error) {
	r := report{SchemaVersion: schemaVersion, Hints: []hintRecord{}, Diagnostics: []string{}, Limitations: append([]string(nil), limitations...)}
	fset := token.NewFileSet()
	pkgs, err := packages.Load(&packages.Config{Dir: dir, Fset: fset, Mode: packages.NeedName | packages.NeedFiles | packages.NeedCompiledGoFiles | packages.NeedSyntax | packages.NeedTypes | packages.NeedTypesInfo | packages.NeedImports | packages.NeedDeps}, patterns...)
	if err != nil {
		return r, err
	}
	if len(pkgs) == 0 {
		return r, errors.New("package patterns matched no packages")
	}
	var loadErrs []string
	packages.Visit(pkgs, nil, func(p *packages.Package) {
		for _, e := range p.Errors {
			loadErrs = append(loadErrs, e.Error())
		}
	})
	if len(loadErrs) != 0 {
		sort.Strings(loadErrs)
		return r, fmt.Errorf("package loading/type checking failed:\n%s", strings.Join(loadErrs, "\n"))
	}
	absDir, _ := filepath.Abs(dir)
	for _, p := range pkgs { // packages.Load returns requested roots; dependencies are only in Imports.
		for _, file := range p.Syntax {
			inspectFile(&r, p, file, fset, absDir)
		}
	}
	sort.Slice(r.Hints, func(i, j int) bool {
		a, b := r.Hints[i], r.Hints[j]
		if a.Package != b.Package {
			return a.Package < b.Package
		}
		if a.File != b.File {
			return a.File < b.File
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		return a.Column < b.Column
	})
	return r, nil
}

func inspectFile(r *report, p *packages.Package, file *ast.File, fset *token.FileSet, dir string) {
	var stack []ast.Node
	ast.Inspect(file, func(n ast.Node) bool {
		if n == nil {
			stack = stack[:len(stack)-1]
			return true
		}
		stack = append(stack, n)
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		selExpr, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		sel := p.TypesInfo.Selections[selExpr]
		if sel == nil || !isGnarkNewHint(sel.Obj()) {
			return true
		}
		// A method expression (Compiler.NewHint(compiler, ...)) has an explicit
		// receiver as its first argument. A method value (compiler.NewHint(...))
		// does not.
		argOffset := 0
		if sel.Kind() == types.MethodExpr {
			argOffset = 1
		}
		pos := fset.Position(call.Lparen)
		path := pos.Filename
		if rel, err := filepath.Rel(dir, path); err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			path = rel
		}
		h := hintRecord{Package: p.PkgPath, File: filepath.ToSlash(path), Line: pos.Line, Column: pos.Column, Function: enclosing(stack), Hint: "unknown"}
		if len(call.Args) > argOffset {
			h.Hint = hintIdentity(p.TypesInfo, call.Args[argOffset])
		}
		if len(call.Args) > argOffset+1 {
			if v := p.TypesInfo.Types[call.Args[argOffset+1]].Value; v != nil && v.Kind() == constant.Int {
				if x, ok := constant.Int64Val(v); ok && int64(int(x)) == x {
					n := int(x)
					h.OutputCount.Value = &n
				}
			}
		}
		if call.Ellipsis == token.NoPos {
			n := len(call.Args) - argOffset - 2
			if n < 0 {
				n = 0
			}
			h.InputCount.Value = &n
		}
		r.Hints = append(r.Hints, h)
		return true
	})
}

func isGnarkNewHint(obj types.Object) bool {
	f, ok := obj.(*types.Func)
	if !ok || f.Name() != "NewHint" || f.Pkg() == nil || f.Pkg().Path() != "github.com/consensys/gnark/frontend" {
		return false
	}
	sig, ok := f.Type().(*types.Signature)
	if !ok || sig.Recv() == nil {
		return false
	}
	named, ok := types.Unalias(sig.Recv().Type()).(*types.Named)
	if ok {
		return named.Obj().Name() == "Compiler"
	}
	return false
}

func hintIdentity(info *types.Info, e ast.Expr) string {
	switch x := e.(type) {
	case *ast.ParenExpr:
		return hintIdentity(info, x.X)
	case *ast.IndexExpr:
		return hintIdentity(info, x.X)
	case *ast.IndexListExpr:
		return hintIdentity(info, x.X)
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

func enclosing(stack []ast.Node) string {
	for i := len(stack) - 1; i >= 0; i-- {
		if f, ok := stack[i].(*ast.FuncDecl); ok {
			if f.Recv != nil && len(f.Recv.List) > 0 {
				return "(" + types.ExprString(f.Recv.List[0].Type) + ")." + f.Name.Name
			}
			return f.Name.Name
		}
		if _, ok := stack[i].(*ast.FuncLit); ok {
			return "function literal"
		}
	}
	return "unknown"
}
