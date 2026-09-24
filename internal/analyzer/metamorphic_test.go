package analyzer

import (
	"bytes"
	"context"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/tools/go/ast/astutil"
)

// The analyzer resolves gnark APIs by type, so rewrites that change only
// spelling must not change what it reports. Each mutation rewrites every
// fixture package without changing its meaning, and the reported
// (package, rule, severity, function) multiset must stay identical. Lines
// are excluded: they are expected to move.
//
// knownFragile records the exact mutation/package pairs whose verdict
// changes today. A new gap fails the test, and so does a gap that gets
// fixed, so the manifest cannot drift from reality.
var knownFragile = map[string]map[string]string{}

type mutation struct {
	name  string
	apply func(fset *token.FileSet, file *ast.File)
}

var mutations = []mutation{
	{"reformat", func(*token.FileSet, *ast.File) {}},
	{"alias-imports", aliasGnarkImports},
	{"paren-args", parenthesizeArguments},
	{"swap-commutative", swapCommutative},
}

// metamorphicSources are the fixture packages the suite rewrites. The
// suppression fixture is excluded: its directives are line-relative.
func metamorphicSources(t *testing.T) []string {
	sources := []string{"./internal/analyzer/testdata/relation", "./internal/analyzer/testdata/deprecated", "./internal/analyzer/testdata/specialize", "./internal/analyzer/testdata/unused"}
	return append(sources, corpusPatterns(t)...)
}

func TestMetamorphic(t *testing.T) {
	sources := metamorphicSources(t)
	baseline := findingsByPackage(t, sources)

	scratch, err := os.MkdirTemp(filepath.Join("../..", "internal/analyzer/testdata"), "metamorphic-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(scratch) })
	scratchPattern := "./" + filepath.ToSlash(strings.TrimPrefix(scratch, "../../"))

	for _, m := range mutations {
		var patterns []string
		for _, source := range sources {
			target := filepath.Join(scratch, m.name, path.Base(source))
			writeMutated(t, filepath.Join("../..", source), target, m.apply)
			patterns = append(patterns, scratchPattern+"/"+m.name+"/"+path.Base(source))
		}
		mutated := findingsByPackage(t, patterns)
		for _, source := range sources {
			pkg := path.Base(source)
			want, got := baseline[pkg], mutated[pkg]
			reason, fragile := knownFragile[m.name][pkg]
			switch {
			case want != got && !fragile:
				t.Errorf("%s changes the verdict on %s\n before:\n%s\n after:\n%s", m.name, pkg, want, got)
			case want == got && fragile:
				t.Errorf("%s no longer changes the verdict on %s (%s): remove it from knownFragile", m.name, pkg, reason)
			}
		}
	}
}

// findingsByPackage scans patterns and summarizes findings per package
// directory as sorted "rule severity function" lines.
func findingsByPackage(t *testing.T, patterns []string) map[string]string {
	t.Helper()
	r, err := ScanContext(context.Background(), "../..", patterns, Options{IncludeExamples: true})
	if err != nil {
		t.Fatal(err)
	}
	lines := map[string][]string{}
	for _, f := range r.Findings {
		pkg := path.Base(path.Dir(f.File))
		lines[pkg] = append(lines[pkg], fmt.Sprintf("%s %s %s", f.RuleID, f.Severity, f.Function))
	}
	summary := map[string]string{}
	for pkg, entries := range lines {
		sort.Strings(entries)
		summary[pkg] = strings.Join(entries, "\n")
	}
	return summary
}

func writeMutated(t *testing.T, sourceDir, targetDir string, apply func(*token.FileSet, *ast.File)) {
	t.Helper()
	if err := os.MkdirAll(targetDir, 0o755); err != nil {
		t.Fatal(err)
	}
	files, err := filepath.Glob(filepath.Join(sourceDir, "*.go"))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range files {
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, name, nil, parser.ParseComments)
		if err != nil {
			t.Fatal(err)
		}
		apply(fset, file)
		var out bytes.Buffer
		if err := format.Node(&out, fset, file); err != nil {
			t.Fatalf("print %s: %v", name, err)
		}
		if err := os.WriteFile(filepath.Join(targetDir, filepath.Base(name)), out.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// aliasGnarkImports gives every gnark import an explicit alias and renames
// its uses, so matching cannot depend on a package's usual name.
func aliasGnarkImports(_ *token.FileSet, file *ast.File) {
	renames := map[string]string{}
	for _, spec := range file.Imports {
		importPath, _ := strconv.Unquote(spec.Path.Value)
		if !strings.HasPrefix(importPath, "github.com/consensys/gnark/") || (spec.Name != nil && (spec.Name.Name == "_" || spec.Name.Name == ".")) {
			continue
		}
		old := path.Base(importPath)
		if spec.Name != nil {
			old = spec.Name.Name
		}
		alias := "m" + strings.ReplaceAll(old, "-", "") + "alias"
		renames[old] = alias
		spec.Name = ast.NewIdent(alias)
	}
	ast.Inspect(file, func(n ast.Node) bool {
		if sel, ok := n.(*ast.SelectorExpr); ok {
			if id, ok := sel.X.(*ast.Ident); ok && id.Obj == nil {
				if alias, ok := renames[id.Name]; ok {
					id.Name = alias
				}
			}
		}
		return true
	})
}

// parenthesizeArguments wraps call arguments in parentheses. Package-
// qualified names, functions, and predeclared identifiers stay bare, since
// parentheses block type-argument inference for generic function values
// (frontend.Compile(..., (scs.NewBuilder), ...) does not compile).
func parenthesizeArguments(_ *token.FileSet, file *ast.File) {
	imported := map[string]bool{}
	for _, spec := range file.Imports {
		importPath, _ := strconv.Unquote(spec.Path.Value)
		if spec.Name != nil {
			imported[spec.Name.Name] = true
		} else {
			imported[path.Base(importPath)] = true
		}
	}
	wrappable := func(arg ast.Expr) bool {
		switch x := arg.(type) {
		case *ast.ParenExpr:
			return false
		case *ast.Ident:
			return x.Obj != nil && (x.Obj.Kind == ast.Var || x.Obj.Kind == ast.Con)
		case *ast.SelectorExpr:
			id, ok := x.X.(*ast.Ident)
			return !ok || !imported[id.Name] || id.Obj != nil
		}
		return true
	}
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if id, ok := call.Fun.(*ast.Ident); ok && (id.Name == "make" || id.Name == "new") {
			return true // their first argument is a type
		}
		for i, arg := range call.Args {
			if wrappable(arg) {
				call.Args[i] = &ast.ParenExpr{X: arg}
			}
		}
		return true
	})
}

// swapCommutative swaps the operands of Add, Mul, and AssertIsEqual calls
// with exactly two arguments, and of Go == and != comparisons.
func swapCommutative(_ *token.FileSet, file *ast.File) {
	astutil.Apply(file, func(c *astutil.Cursor) bool {
		switch x := c.Node().(type) {
		case *ast.CallExpr:
			sel, ok := x.Fun.(*ast.SelectorExpr)
			if ok && len(x.Args) == 2 && x.Ellipsis == token.NoPos && (sel.Sel.Name == "Add" || sel.Sel.Name == "Mul" || sel.Sel.Name == "AssertIsEqual") {
				x.Args[0], x.Args[1] = x.Args[1], x.Args[0]
			}
		case *ast.BinaryExpr:
			if x.Op == token.EQL || x.Op == token.NEQ {
				x.X, x.Y = x.Y, x.X
			}
		}
		return true
	}, nil)
}
