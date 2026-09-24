package analyzer

import (
	"fmt"
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"reflect"
	"strconv"
	"strings"

	"github.com/auditinfra-io/gnark-safety/internal/gnarkapi"
	"github.com/auditinfra-io/gnark-safety/internal/rules"
	"github.com/auditinfra-io/gnark-safety/pkg/report"
	"golang.org/x/tools/go/packages"
)

const (
	bitsPath          = "github.com/consensys/gnark/std/math/bits"
	cmpPath           = "github.com/consensys/gnark/std/math/cmp"
	gnarkStdPrefix    = "github.com/consensys/gnark/std/"
	unsafeKZGPath     = "github.com/consensys/gnark/test/unsafekzg"
	groth16Path       = "github.com/consensys/gnark/backend/groth16"
	recursionGroth16  = "github.com/consensys/gnark/std/recursion/groth16"
	recursionPlonk    = "github.com/consensys/gnark/std/recursion/plonk"
	unconstrainedOut  = "WithUnconstrainedOutputs"
	unconstrainedIn   = "WithUnconstrainedInputs"
	variableTypeName  = "Variable"
	omitModulusOption = "OmitModulusCheck"
)

// ruleContext carries what every per-file rule needs to emit findings.
type ruleContext struct {
	p        *packages.Package
	info     *types.Info
	fset     *token.FileSet
	absDir   string
	isTest   bool
	findings []report.Finding
}

func (c *ruleContext) add(rule string, severity report.Severity, pos token.Pos, function, message string, evidence ...string) {
	position := c.fset.Position(pos)
	if evidence == nil {
		evidence = []string{}
	}
	c.findings = append(c.findings, report.Finding{RuleID: rule, Severity: severity, Confidence: confidenceOf(rule), File: relative(c.absDir, position.Filename), Line: position.Line, Column: position.Column, Function: function, Message: message, Evidence: evidence, Limitations: []string{}})
}

func confidenceOf(rule string) string {
	if spec, ok := rules.Lookup(rule); ok {
		return spec.Confidence
	}
	return "unknown"
}

// syntaxFindings runs the rules that need only one file's syntax and types:
// struct tags, imports, and call or comparison shapes inside functions.
func syntaxFindings(p *packages.Package, file *ast.File, fset *token.FileSet, absDir string) []report.Finding {
	c := &ruleContext{p: p, info: p.TypesInfo, fset: fset, absDir: absDir, isTest: strings.HasSuffix(fset.Position(file.Package).Filename, "_test.go")}
	c.checkImports(file)
	c.checkTags(file)
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		c.checkFunction(fn)
	}
	return c.findings
}

func (c *ruleContext) checkImports(file *ast.File) {
	if c.isTest {
		return
	}
	for _, spec := range file.Imports {
		if path, err := strconv.Unquote(spec.Path.Value); err == nil && path == unsafeKZGPath {
			c.add(rules.UnsafeSetup, report.SeverityMedium, spec.Pos(), "", "Production code imports gnark's test-only unsafekzg package, whose KZG parameters come from locally known randomness.", "import: "+unsafeKZGPath)
		}
	}
}

// checkTags reports gnark struct tags whose name part is a visibility.
func (c *ruleContext) checkTags(file *ast.File) {
	var stack []ast.Node
	ast.Inspect(file, func(n ast.Node) bool {
		if n == nil {
			stack = stack[:len(stack)-1]
			return true
		}
		stack = append(stack, n)
		st, ok := n.(*ast.StructType)
		if !ok || st.Fields == nil {
			return true
		}
		owner := ""
		for i := len(stack) - 2; i >= 0; i-- {
			if spec, ok := stack[i].(*ast.TypeSpec); ok {
				owner = spec.Name.Name
				break
			}
		}
		for _, field := range st.Fields.List {
			if field.Tag == nil {
				continue
			}
			raw, err := strconv.Unquote(field.Tag.Value)
			if err != nil {
				continue
			}
			tag, ok := reflect.StructTag(raw).Lookup("gnark")
			if !ok {
				continue
			}
			name, _, _ := strings.Cut(tag, ",")
			switch name {
			case "public":
				c.add(rules.TagVisibilityAsName, report.SeverityHigh, field.Tag.Pos(), owner, fmt.Sprintf("Struct tag gnark:%q names this witness element \"public\" and leaves it secret, so the verifier cannot fix its value; write gnark:\",public\".", tag), "tag: gnark:"+strconv.Quote(tag), "gnark parses the text before the first comma as the name")
			case "secret":
				c.add(rules.TagVisibilityAsName, report.SeverityInfo, field.Tag.Pos(), owner, fmt.Sprintf("Struct tag gnark:%q names this witness element \"secret\"; it is secret by default, but gnark:\",secret\" states the visibility as intended.", tag), "tag: gnark:"+strconv.Quote(tag))
			}
		}
		return true
	})
}

func (c *ruleContext) checkFunction(fn *ast.FuncDecl) {
	function := functionName(fn)
	var stack []ast.Node
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if n == nil {
			stack = stack[:len(stack)-1]
			return true
		}
		stack = append(stack, n)
		switch x := n.(type) {
		case *ast.BinaryExpr:
			if branches := c.guardedBranches(stack); branches != nil && c.emitsConstraints(branches...) {
				c.checkEquality(x, function)
			}
		case *ast.SwitchStmt:
			if x.Tag != nil && c.isVariable(x.Tag) && !c.isConstantField(x.Tag) && c.emitsConstraints(x.Body) {
				c.add(rules.GoEqualityOnVariable, report.SeverityHigh, x.Tag.Pos(), function, "A Go switch on a frontend.Variable selects a case while the circuit is compiled, not from the witness; no case adds a constraint conditioned on the value.", "switch tag: "+types.ExprString(x.Tag))
			}
		case *ast.CallExpr:
			c.checkCall(x, stack, fn, function)
		}
		return true
	})
}

// guardedBranches returns the branches of the if statement whose condition
// contains the expression at the top of stack (through &&, ||, !, and
// parentheses), or nil when the expression is not part of a condition.
func (c *ruleContext) guardedBranches(stack []ast.Node) []ast.Node {
	child := stack[len(stack)-1]
	for i := len(stack) - 2; i >= 0; i-- {
		switch parent := stack[i].(type) {
		case *ast.ParenExpr, *ast.UnaryExpr:
			child = parent
		case *ast.BinaryExpr:
			if parent.Op != token.LAND && parent.Op != token.LOR {
				return nil
			}
			child = parent
		case *ast.IfStmt:
			if parent.Cond != child {
				return nil
			}
			branches := []ast.Node{parent.Body}
			if parent.Else != nil {
				branches = append(branches, parent.Else)
			}
			return branches
		default:
			return nil
		}
	}
	return nil
}

// emitsConstraints reports whether any of nodes calls something that can
// add constraints: a frontend API method, a gnark gadget method, or a
// function that takes a frontend.API. A Go branch matters for soundness only
// when it decides which of those calls happen.
func (c *ruleContext) emitsConstraints(nodes ...ast.Node) bool {
	found := false
	for _, node := range nodes {
		ast.Inspect(node, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || found {
				return !found
			}
			callee := calledFunc(c.info, call)
			if callee == nil || callee.Pkg() == nil {
				return true
			}
			path := callee.Pkg().Path()
			if (path == gnarkapi.FrontendPath || strings.HasPrefix(path, gnarkStdPrefix)) && receiverName(callee) != "" {
				found = true
				return false
			}
			sig := callee.Type().(*types.Signature)
			for i := 0; i < sig.Params().Len(); i++ {
				if named, ok := types.Unalias(sig.Params().At(i).Type()).(*types.Named); ok && named.Obj().Name() == "API" && named.Obj().Pkg() != nil && named.Obj().Pkg().Path() == gnarkapi.FrontendPath {
					found = true
					return false
				}
			}
			return true
		})
	}
	return found
}

func (c *ruleContext) checkEquality(x *ast.BinaryExpr, function string) {
	if x.Op != token.EQL && x.Op != token.NEQ {
		return
	}
	if c.info.Types[x.X].IsNil() || c.info.Types[x.Y].IsNil() {
		return
	}
	for _, side := range []ast.Expr{x.X, x.Y} {
		if c.isVariable(side) && !c.isConstantField(side) {
			c.add(rules.GoEqualityOnVariable, report.SeverityHigh, x.OpPos, function, fmt.Sprintf("Go %s on a frontend.Variable compares compile-time constraint expressions, not witness values, so the result does not depend on the prover's input.", x.Op), "comparison: "+types.ExprString(x))
			return
		}
	}
}

// isVariable reports whether e has the named type frontend.Variable.
func (c *ruleContext) isVariable(e ast.Expr) bool {
	named, ok := types.Unalias(c.info.TypeOf(e)).(*types.Named)
	return ok && named.Obj().Name() == variableTypeName && named.Obj().Pkg() != nil && named.Obj().Pkg().Path() == gnarkapi.FrontendPath
}

// isConstantField reports whether e selects a struct field tagged
// gnark:"-": such fields are not witness elements and hold Go values while
// the circuit compiles, so comparing them in Go is legitimate.
func (c *ruleContext) isConstantField(e ast.Expr) bool {
	sel, ok := unparen(e).(*ast.SelectorExpr)
	if !ok {
		return false
	}
	selection := c.info.Selections[sel]
	if selection == nil || selection.Kind() != types.FieldVal {
		return false
	}
	t := selection.Recv()
	indexes := selection.Index()
	for i, index := range indexes {
		if pointer, ok := t.Underlying().(*types.Pointer); ok {
			t = pointer.Elem()
		}
		st, ok := t.Underlying().(*types.Struct)
		if !ok || index >= st.NumFields() {
			return false
		}
		if i == len(indexes)-1 {
			tag, _ := reflect.StructTag(st.Tag(index)).Lookup("gnark")
			return tag == "-"
		}
		t = st.Field(index).Type()
	}
	return false
}

func (c *ruleContext) checkCall(call *ast.CallExpr, stack []ast.Node, fn *ast.FuncDecl, function string) {
	callee := calledFunc(c.info, call)
	if callee == nil {
		return
	}
	switch {
	case isPackageFunc(callee, bitsPath, omitModulusOption):
		c.add(rules.BitsOmitModulusCheck, report.SeverityMedium, call.Pos(), function, "bits.OmitModulusCheck() skips the modulus comparison, so a full-width decomposition of a is not distinguished from one of a + r.", "option: bits.OmitModulusCheck()")
	case isPackageFunc(callee, cmpPath, "NewBoundedComparator"):
		if len(call.Args) >= 3 && isBoolConstant(c.info, call.Args[2], true) {
			c.add(rules.ComparatorNondeterminism, report.SeverityMedium, call.Args[2].Pos(), function, "cmp.NewBoundedComparator is created with allowNonDeterministicBehaviour=true, so comparisons of operands farther apart than the bound can have several solutions.", "bound: "+types.ExprString(call.Args[1]))
		}
	case isPackageFunc(callee, gnarkapi.FrontendPath, "IgnoreUnconstrainedInputs"):
		if !c.isTest {
			c.add(rules.IgnoreUnconstrainedInputs, report.SeverityMedium, call.Pos(), function, "frontend.IgnoreUnconstrainedInputs() disables gnark's compile error for inputs that no constraint uses.", "option: frontend.IgnoreUnconstrainedInputs()")
		}
	case isPackageFunc(callee, groth16Path, "Setup"):
		if !c.isTest && c.p.Name == "main" {
			c.add(rules.UnsafeSetup, report.SeverityLow, call.Pos(), function, "A main package runs a single-party groth16.Setup; whoever runs it can forge proofs unless the keys come from a multi-party ceremony.", "call: groth16.Setup")
		}
	case isPackageFunc(callee, bitsPath, "ToBinary", "ToBase", "ToTernary") && hasOption(c.info, call, unconstrainedOut):
		c.checkUnconstrainedOutputs(call, stack, fn, function)
	case isPackageFunc(callee, bitsPath, "FromBinary", "FromBase", "FromTernary") && hasOption(c.info, call, unconstrainedIn):
		c.checkUnconstrainedInputs(call, callee, fn, function)
	}
	c.checkDiscarded(call, callee, stack, fn, function)
	c.checkVacuous(call, callee, function)
}

// checkDiscarded reports a predicate whose result is dropped.
func (c *ruleContext) checkDiscarded(call *ast.CallExpr, callee *types.Func, stack []ast.Node, fn *ast.FuncDecl, function string) {
	if !isPredicate(callee) || len(stack) < 2 || c.onOwnReceiver(call, fn) {
		return
	}
	discarded := false
	switch parent := stack[len(stack)-2].(type) {
	case *ast.ExprStmt:
		discarded = parent.X == call
	case *ast.AssignStmt:
		if len(parent.Rhs) == 1 && parent.Rhs[0] == call && len(parent.Lhs) > 0 {
			id, ok := parent.Lhs[0].(*ast.Ident)
			discarded = ok && id.Name == "_"
		}
	}
	if discarded {
		c.add(rules.DiscardedPredicate, report.SeverityHigh, call.Pos(), function, fmt.Sprintf("The result of %s is discarded, so the check it computes is not part of any constraint.", callee.Name()), "call: "+types.ExprString(call.Fun))
	}
}

// onOwnReceiver reports whether call is a method call on the enclosing
// method's receiver, as when a hasher flushes itself by calling its own Sum.
// That is the type's internal plumbing, not a check its author forgot.
func (c *ruleContext) onOwnReceiver(call *ast.CallExpr, fn *ast.FuncDecl) bool {
	if fn.Recv == nil || len(fn.Recv.List) == 0 || len(fn.Recv.List[0].Names) == 0 {
		return false
	}
	receiver := c.info.Defs[fn.Recv.List[0].Names[0]]
	sel, ok := unparen(call.Fun).(*ast.SelectorExpr)
	if !ok || receiver == nil {
		return false
	}
	id, ok := unparen(sel.X).(*ast.Ident)
	return ok && c.info.Uses[id] == receiver
}

// isPredicate recognizes calls whose value is the whole point of calling
// them: gnark predicates, proof validity, and hash digests.
func isPredicate(fn *types.Func) bool {
	recv := receiverName(fn)
	path := ""
	if fn.Pkg() != nil {
		path = fn.Pkg().Path()
	}
	switch {
	case path == gnarkapi.FrontendPath && recv != "" && (fn.Name() == "IsZero" || fn.Name() == "Cmp"):
		return true
	case path == cmpPath && recv == "BoundedComparator" && (fn.Name() == "IsLess" || fn.Name() == "IsLessEq"):
		return true
	case (path == recursionGroth16 || path == recursionPlonk) && recv == "Verifier" && fn.Name() == "IsValidProof":
		return true
	case strings.HasPrefix(path, gnarkStdPrefix) && recv != "" && fn.Name() == "Sum":
		// Hashers live in several packages (std/hash/..., and MiMC in
		// std/internal/mimc behind an alias), so match the hasher shape: a
		// Sum method with no parameters and one result.
		sig := fn.Type().(*types.Signature)
		return sig.Params().Len() == 0 && sig.Results().Len() == 1
	}
	return false
}

// checkVacuous reports assertions that hold by construction.
func (c *ruleContext) checkVacuous(call *ast.CallExpr, callee *types.Func, function string) {
	path := ""
	if callee.Pkg() != nil {
		path = callee.Pkg().Path()
	}
	isAPI := path == gnarkapi.FrontendPath && receiverName(callee) != ""
	binary := (isAPI && (callee.Name() == "AssertIsEqual" || callee.Name() == "AssertIsLessOrEqual")) ||
		(path == cmpPath && receiverName(callee) == "BoundedComparator" && callee.Name() == "AssertIsLessEq")
	switch {
	case binary && len(call.Args) == 2:
		a, b := call.Args[0], call.Args[1]
		if sameExpr(c.info, a, b) {
			c.add(rules.VacuousAssert, report.SeverityHigh, call.Pos(), function, fmt.Sprintf("%s compares %s with itself, so it always holds; one operand is probably meant to be a different value.", callee.Name(), types.ExprString(a)), "call: "+types.ExprString(call))
		} else if isConstant(c.info, a) && isConstant(c.info, b) {
			c.add(rules.VacuousAssert, report.SeverityMedium, call.Pos(), function, fmt.Sprintf("%s has only constant operands, so it constrains no witness value.", callee.Name()), "call: "+types.ExprString(call))
		}
	case isAPI && (callee.Name() == "AssertIsBoolean" || callee.Name() == "AssertIsCrumb") && len(call.Args) == 1 && isConstant(c.info, call.Args[0]):
		c.add(rules.VacuousAssert, report.SeverityMedium, call.Pos(), function, fmt.Sprintf("%s of a constant constrains no witness value.", callee.Name()), "call: "+types.ExprString(call))
	}
}

// checkUnconstrainedOutputs reports a decomposition whose digits are hint
// outputs that nothing in the function constrains.
func (c *ruleContext) checkUnconstrainedOutputs(call *ast.CallExpr, stack []ast.Node, fn *ast.FuncDecl, function string) {
	message := "bits decomposition uses WithUnconstrainedOutputs, and nothing in this function constrains the digits, so the prover can choose non-boolean digits with the same weighted sum."
	parent := stack[len(stack)-2]
	switch p := parent.(type) {
	case *ast.ExprStmt:
		c.add(rules.BitsUnconstrained, report.SeverityHigh, call.Pos(), function, message, "digits: discarded; the call constrains nothing about its input")
		return
	case *ast.AssignStmt, *ast.ValueSpec:
		target := assignedIdent(p, call)
		if target == nil {
			return
		}
		obj := c.info.Defs[target]
		if obj == nil {
			obj = c.info.Uses[target]
		}
		if obj == nil || target.Name == "_" {
			c.add(rules.BitsUnconstrained, report.SeverityHigh, call.Pos(), function, message, "digits: discarded; the call constrains nothing about its input")
			return
		}
		if c.digitUse(fn.Body, obj) == digitsUnconstrained {
			c.add(rules.BitsUnconstrained, report.SeverityHigh, call.Pos(), function, message, "digits: "+target.Name)
		}
	}
	// Passed straight into another call: constrained, or handed off.
}

// checkUnconstrainedInputs reports recomposition that trusts digits which
// are prover advice with no boolean constraint.
func (c *ruleContext) checkUnconstrainedInputs(call *ast.CallExpr, callee *types.Func, fn *ast.FuncDecl, function string) {
	digitsArg := 1
	if callee.Name() == "FromBase" {
		digitsArg = 2
	}
	if len(call.Args) <= digitsArg {
		return
	}
	root := rootIdent(call.Args[digitsArg])
	if root == nil {
		return
	}
	obj := c.info.Uses[root]
	if obj == nil || !c.isProverAdvice(fn.Body, obj) {
		return
	}
	if c.digitUse(fn.Body, obj) == digitsUnconstrained {
		c.add(rules.BitsUnconstrained, report.SeverityMedium, call.Pos(), function, callee.Name()+" uses WithUnconstrainedInputs on digits that are prover advice, and nothing in this function constrains them.", "digits: "+root.Name)
	}
}

// isProverAdvice reports whether obj is defined from hint outputs or from a
// decomposition with unconstrained outputs.
func (c *ruleContext) isProverAdvice(body *ast.BlockStmt, obj types.Object) bool {
	advice := false
	ast.Inspect(body, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok || advice {
			return !advice
		}
		for i, lhs := range assign.Lhs {
			id, ok := lhs.(*ast.Ident)
			if !ok || (c.info.Defs[id] != obj && c.info.Uses[id] != obj) {
				continue
			}
			var rhs ast.Expr
			if len(assign.Rhs) == len(assign.Lhs) {
				rhs = assign.Rhs[i]
			} else if len(assign.Rhs) == 1 && i == 0 {
				rhs = assign.Rhs[0]
			}
			call, ok := unparen(rhs).(*ast.CallExpr)
			if !ok {
				continue
			}
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok && c.info.Selections[sel] != nil && gnarkapi.IsNewHint(c.info.Selections[sel].Obj()) {
				advice = true
			}
			if callee := calledFunc(c.info, call); callee != nil && isPackageFunc(callee, bitsPath, "ToBinary", "ToBase", "ToTernary") && hasOption(c.info, call, unconstrainedOut) {
				advice = true
			}
		}
		return true
	})
	return advice
}

type digitVerdict int

const (
	digitsUnconstrained digitVerdict = iota
	digitsConstrained
	digitsHandedOff
)

// digitUse classifies how a digit slice (or its elements, including range
// variables and local aliases) is used in body: constrained to be digits,
// handed to code this rule cannot see, or neither.
func (c *ruleContext) digitUse(body *ast.BlockStmt, slice types.Object) digitVerdict {
	tracked := map[types.Object]bool{slice: true}
	// Range variables and aliases of elements inherit the slice's status.
	ast.Inspect(body, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.RangeStmt:
			if id := rootIdent(x.X); id != nil && tracked[c.info.Uses[id]] {
				if v, ok := x.Value.(*ast.Ident); ok && c.info.Defs[v] != nil {
					tracked[c.info.Defs[v]] = true
				}
			}
		case *ast.AssignStmt:
			if len(x.Lhs) == len(x.Rhs) {
				for i, rhs := range x.Rhs {
					id := rootIdent(rhs)
					lhs, ok := x.Lhs[i].(*ast.Ident)
					if id != nil && ok && tracked[c.info.Uses[id]] && c.info.Defs[lhs] != nil {
						tracked[c.info.Defs[lhs]] = true
					}
				}
			}
		}
		return true
	})
	verdict := digitsUnconstrained
	var stack []ast.Node
	ast.Inspect(body, func(n ast.Node) bool {
		if n == nil {
			stack = stack[:len(stack)-1]
			return true
		}
		stack = append(stack, n)
		id, ok := n.(*ast.Ident)
		if !ok || !tracked[c.info.Uses[id]] || verdict == digitsConstrained {
			return true
		}
		switch c.consumer(stack) {
		case digitsConstrained:
			verdict = digitsConstrained
		case digitsHandedOff:
			verdict = digitsHandedOff
		}
		return true
	})
	return verdict
}

// consumer classifies the innermost construct consuming the identifier at
// the top of stack.
func (c *ruleContext) consumer(stack []ast.Node) digitVerdict {
	child := stack[len(stack)-1]
	for i := len(stack) - 2; i >= 0; i-- {
		switch parent := stack[i].(type) {
		case *ast.ParenExpr, *ast.IndexExpr, *ast.SliceExpr, *ast.StarExpr:
			child = parent
			continue
		case *ast.CallExpr:
			if parent.Fun == child {
				return digitsUnconstrained
			}
			callee := calledFunc(c.info, parent)
			if callee == nil {
				if builtin, ok := unparen(parent.Fun).(*ast.Ident); ok && builtin.Name == "len" {
					return digitsUnconstrained
				}
				return digitsHandedOff // append, copy, or a dynamic call
			}
			path := ""
			if callee.Pkg() != nil {
				path = callee.Pkg().Path()
			}
			switch {
			case path == gnarkapi.FrontendPath && receiverName(callee) != "" && (callee.Name() == "AssertIsBoolean" || callee.Name() == "AssertIsCrumb" || callee.Name() == "FromBinary"):
				return digitsConstrained
			case isPackageFunc(callee, bitsPath, "AssertIsTrit"):
				return digitsConstrained
			case isPackageFunc(callee, bitsPath, "FromBinary", "FromBase", "FromTernary"):
				if hasOption(c.info, parent, unconstrainedIn) {
					return digitsUnconstrained
				}
				return digitsConstrained
			case path == gnarkapi.FrontendPath && receiverName(callee) != "":
				return digitsUnconstrained // arithmetic or an assertion that is not a digit check
			default:
				return digitsHandedOff
			}
		case *ast.ReturnStmt, *ast.CompositeLit, *ast.KeyValueExpr, *ast.SendStmt:
			return digitsHandedOff
		case *ast.AssignStmt:
			for _, lhs := range parent.Lhs {
				if lhs == child {
					return digitsUnconstrained // written to, not read
				}
				if _, ok := lhs.(*ast.Ident); !ok {
					return digitsHandedOff // stored into a field or element
				}
			}
			return digitsUnconstrained
		default:
			return digitsUnconstrained
		}
	}
	return digitsUnconstrained
}

// calledFunc returns the declared function or method a call invokes,
// resolving generic instantiations to their origin.
func calledFunc(info *types.Info, call *ast.CallExpr) *types.Func {
	fun := unparen(call.Fun)
	switch x := fun.(type) {
	case *ast.IndexExpr:
		fun = x.X
	case *ast.IndexListExpr:
		fun = x.X
	}
	var obj types.Object
	switch x := fun.(type) {
	case *ast.Ident:
		obj = info.Uses[x]
	case *ast.SelectorExpr:
		obj = info.Uses[x.Sel]
	}
	fn, ok := obj.(*types.Func)
	if !ok {
		return nil
	}
	return fn.Origin()
}

func isPackageFunc(fn *types.Func, path string, names ...string) bool {
	if fn.Pkg() == nil || fn.Pkg().Path() != path || receiverName(fn) != "" {
		return false
	}
	for _, name := range names {
		if fn.Name() == name {
			return true
		}
	}
	return false
}

// receiverName returns the name of a method's receiver type, or "" for a
// plain function.
func receiverName(fn *types.Func) string {
	sig, ok := fn.Type().(*types.Signature)
	if !ok || sig.Recv() == nil {
		return ""
	}
	t := sig.Recv().Type()
	if pointer, ok := t.(*types.Pointer); ok {
		t = pointer.Elem()
	}
	if named, ok := types.Unalias(t).(*types.Named); ok {
		return named.Obj().Name()
	}
	return ""
}

// hasOption reports whether call passes bits.<option>() directly.
func hasOption(info *types.Info, call *ast.CallExpr, option string) bool {
	for _, arg := range call.Args {
		inner, ok := unparen(arg).(*ast.CallExpr)
		if !ok {
			continue
		}
		if fn := calledFunc(info, inner); fn != nil && isPackageFunc(fn, bitsPath, option) {
			return true
		}
	}
	return false
}

func isConstant(info *types.Info, e ast.Expr) bool {
	return info.Types[e].Value != nil
}

func isBoolConstant(info *types.Info, e ast.Expr, want bool) bool {
	value := info.Types[e].Value
	return value != nil && value.Kind() == constant.Bool && constant.BoolVal(value) == want
}

// sameExpr reports whether a and b denote the same variable, field path, or
// constant-index element.
func sameExpr(info *types.Info, a, b ast.Expr) bool {
	a, b = unparen(a), unparen(b)
	switch x := a.(type) {
	case *ast.Ident:
		y, ok := b.(*ast.Ident)
		return ok && objectOf(info, x) != nil && objectOf(info, x) == objectOf(info, y)
	case *ast.SelectorExpr:
		y, ok := b.(*ast.SelectorExpr)
		return ok && info.Uses[x.Sel] != nil && info.Uses[x.Sel] == info.Uses[y.Sel] && sameExpr(info, x.X, y.X)
	case *ast.IndexExpr:
		y, ok := b.(*ast.IndexExpr)
		if !ok {
			return false
		}
		i, j := constantIndex(x.Index, info), constantIndex(y.Index, info)
		return i >= 0 && i == j && sameExpr(info, x.X, y.X)
	}
	return false
}

// rootIdent strips parentheses, slicing, and indexing to the identifier
// being sliced or indexed.
func rootIdent(e ast.Expr) *ast.Ident {
	for {
		switch x := e.(type) {
		case *ast.ParenExpr:
			e = x.X
		case *ast.SliceExpr:
			e = x.X
		case *ast.IndexExpr:
			e = x.X
		case *ast.Ident:
			return x
		default:
			return nil
		}
	}
}

// assignedIdent returns the identifier value is assigned to, or nil.
func assignedIdent(parent ast.Node, value ast.Expr) *ast.Ident {
	switch p := parent.(type) {
	case *ast.AssignStmt:
		for i, rhs := range p.Rhs {
			if rhs == value && i < len(p.Lhs) {
				id, _ := p.Lhs[i].(*ast.Ident)
				return id
			}
		}
	case *ast.ValueSpec:
		for i, v := range p.Values {
			if v == value && i < len(p.Names) {
				return p.Names[i]
			}
		}
	}
	return nil
}
