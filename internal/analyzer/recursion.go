package analyzer

import (
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"sort"
	"strconv"
	"strings"

	"github.com/auditinfra-io/gnark-safety/internal/gnarkapi"
	"github.com/auditinfra-io/gnark-safety/internal/rules"
	"github.com/auditinfra-io/gnark-safety/pkg/report"
)

// verifyingMethods are the std/recursion Verifier methods that put a proof's
// validity into the constraint system. IsValidProof does so only when its
// result is kept; GNARK_DISCARDED_PREDICATE reports the discarded form.
var verifyingMethods = map[string]bool{
	"AssertProof":           true,
	"AssertSameProofs":      true,
	"AssertDifferentProofs": true,
	"PrepareVerification":   true,
	"IsValidProof":          true,
}

// witnessRead is the first read of one recursion witness's public inputs.
type witnessRead struct {
	expr     *ast.SelectorExpr
	witness  string
	key      string
	resolved bool
}

// witnessScope is what the rule knows about one Define body.
type witnessScope struct {
	receiver types.Object
	// aliases maps a local defined once from an expression, and never
	// reassigned or addressed, to that expression. A range variable maps
	// to the ranged expression: indexes are ignored anyway.
	aliases map[types.Object]ast.Expr
	// written holds every node inside an assignment target.
	written map[ast.Node]bool
	// public holds the locals ever assigned a witness's public inputs.
	public map[types.Object]bool
}

// checkRecursionWitness reports a circuit's Define method that reads the
// public inputs of a std/recursion Witness when no verification in Define,
// or in a package-local function Define hands the witness to, takes that
// witness. A Define that other package code refers to may be a sub-circuit
// whose caller verifies, so only entry points are checked.
func (c *ruleContext) checkRecursionWitness(fn *ast.FuncDecl, function string) {
	if !isDefineMethod(c.info, fn) || c.referencedElsewhere(fn) {
		return
	}
	scope := c.newWitnessScope(fn)
	helpers := packageFunctions(c.p)
	// mayVerify reports whether code that receives the witness may verify
	// it: a package-local function that contains a verification, or
	// anything the rule does not read.
	mayVerify := func(target *types.Func) bool {
		if decl := helpers[target]; decl != nil {
			return c.containsVerification(decl.Body)
		}
		return target.Pkg() == nil || !c.isStandardLibrary(target.Pkg())
	}

	var reads []witnessRead
	seen := map[string]bool{}
	verified := map[string]string{}
	verifications := 0
	unknown := false
	var stack []ast.Node
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if n == nil {
			stack = stack[:len(stack)-1]
			return true
		}
		stack = append(stack, n)
		if c.escapesToInterface(n) {
			// An interface value holding the witness can reach any method.
			unknown = true
		}
		switch x := n.(type) {
		case *ast.SelectorExpr:
			sel := c.info.Selections[x]
			if sel == nil {
				return true
			}
			if sel.Kind() == types.MethodVal && !isCalled(x, stack) && c.holdsWitness(x.X) {
				// A method value bound to the witness's holder, such as
				// c.verify passed as a callback, may run that method.
				if method, ok := sel.Obj().(*types.Func); !ok || mayVerify(method.Origin()) {
					unknown = true
				}
				return true
			}
			if scope.written[x] || !isWitnessPublic(sel) || isShapeRead(c.info, stack) {
				return true
			}
			read := c.witnessRead(x, sel, scope)
			if !seen[read.key] {
				seen[read.key] = true
				reads = append(reads, read)
			}
		case *ast.CallExpr:
			callee := calledFunc(c.info, x)
			if isVerifying(callee) {
				if callee.Name() == "IsValidProof" && resultDiscarded(stack) {
					return true
				}
				verifications++
				arg := witnessArgument(c.info, x)
				if arg == nil || !c.resolveVerified(arg, scope, 0, verified) {
					unknown = true
				}
				return true
			}
			switch c.handOff(x, callee, scope) {
			case handsWitness:
				if callee == nil || mayVerify(callee) || returnsInterface(callee) {
					unknown = true
				}
			case handsPublic:
				// Public inputs alone cannot be verified without the proof
				// and key, so only a package-local helper that rebuilds the
				// witness from them is followed.
				if callee != nil && helpers[callee] != nil && c.containsVerification(helpers[callee].Body) {
					unknown = true
				}
			}
		}
		return true
	})
	if unknown {
		return
	}
	for _, read := range reads {
		if _, ok := verified[read.key]; ok {
			continue
		}
		if verifications == 0 {
			c.add(rules.RecursionUnverified, report.SeverityHigh, read.expr.Pos(), function,
				fmt.Sprintf("%s.Public is used, but Define verifies no recursive proof: no AssertProof, AssertSameProofs, AssertDifferentProofs, PrepareVerification, or kept IsValidProof result. A prover can supply any public inputs for the inner proof.", read.witness),
				"witness: "+read.witness, "verifications in Define: 0")
			continue
		}
		if !read.resolved {
			// A verification exists, and this witness is reached through a
			// value the rule cannot match to it.
			continue
		}
		c.add(rules.RecursionUnverified, report.SeverityHigh, read.expr.Pos(), function,
			fmt.Sprintf("%s.Public is used, but no recursive verification in Define takes %s; the verifications here cover %s. A prover can supply any public inputs for it.", read.witness, read.witness, verifiedList(verified)),
			"witness: "+read.witness, "verified witnesses: "+verifiedList(verified))
	}
}

// newWitnessScope collects Define's receiver, assignment targets, and the
// locals that stand for a single expression.
func (c *ruleContext) newWitnessScope(fn *ast.FuncDecl) *witnessScope {
	scope := &witnessScope{aliases: map[types.Object]ast.Expr{}, written: map[ast.Node]bool{}, public: map[types.Object]bool{}}
	if names := fn.Recv.List[0].Names; len(names) > 0 {
		scope.receiver = c.info.Defs[names[0]]
	}
	candidates := map[types.Object]ast.Expr{}
	assignments := map[types.Object]int{}
	defining := map[types.Object]int{}
	addressed := map[types.Object]bool{}
	count := func(target ast.Expr, into map[types.Object]int) {
		if root := assignedRoot(target); root != nil {
			if obj := objectOf(c.info, root); obj != nil {
				into[obj]++
			}
		}
	}
	define := func(id ast.Expr, value ast.Expr, assignsOnce bool) {
		name, ok := id.(*ast.Ident)
		if !ok || name.Name == "_" {
			return
		}
		if obj := c.info.Defs[name]; obj != nil {
			candidates[obj] = value
			if assignsOnce {
				defining[obj] = 1
			}
		}
	}
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.AssignStmt:
			for i, lhs := range x.Lhs {
				ast.Inspect(lhs, func(m ast.Node) bool {
					scope.written[m] = true
					return true
				})
				count(lhs, assignments)
				if x.Tok == token.DEFINE && len(x.Lhs) == len(x.Rhs) {
					define(lhs, x.Rhs[i], true)
				}
			}
		case *ast.ValueSpec:
			if len(x.Names) == len(x.Values) {
				for i, name := range x.Names {
					define(name, x.Values[i], false)
				}
			}
		case *ast.RangeStmt:
			if x.Tok == token.DEFINE && x.Value != nil {
				define(x.Value, x.X, false)
			}
			if x.Tok == token.ASSIGN {
				for _, target := range []ast.Expr{x.Key, x.Value} {
					if target != nil {
						count(target, assignments)
					}
				}
			}
		case *ast.IncDecStmt:
			count(x.X, assignments)
		case *ast.UnaryExpr:
			if x.Op == token.AND {
				c.markAddressed(x.X, addressed)
			}
		case *ast.SelectorExpr:
			// Calling a pointer method on a variable takes its address.
			if sel := c.info.Selections[x]; sel != nil && sel.Kind() == types.MethodVal && !isPointer(c.info.TypeOf(x.X)) {
				if fn, ok := sel.Obj().(*types.Func); ok {
					if recv := fn.Type().(*types.Signature).Recv(); recv != nil && isPointer(recv.Type()) {
						c.markAddressed(x.X, addressed)
					}
				}
			}
		}
		return true
	})
	// Locals assigned public inputs, directly or from another such local.
	for changed := true; changed; {
		changed = false
		mark := func(target, value ast.Expr) {
			if !c.publicExpr(value, scope.public) {
				return
			}
			if root := assignedRoot(target); root != nil {
				if obj := objectOf(c.info, root); obj != nil && !scope.public[obj] {
					scope.public[obj] = true
					changed = true
				}
			}
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.AssignStmt:
				if len(x.Lhs) == len(x.Rhs) {
					for i, lhs := range x.Lhs {
						mark(lhs, x.Rhs[i])
					}
				}
			case *ast.ValueSpec:
				if len(x.Names) == len(x.Values) {
					for i, name := range x.Names {
						mark(name, x.Values[i])
					}
				}
			case *ast.RangeStmt:
				if x.Value != nil {
					mark(x.Value, x.X)
				}
			}
			return true
		})
	}
	for obj, value := range candidates {
		if assignments[obj] == defining[obj] && !addressed[obj] {
			scope.aliases[obj] = value
		}
	}
	return scope
}

// assignedRoot returns the variable an assignment target or operand writes
// into: the identifier under any field selections, indexes, dereferences,
// and parentheses.
func assignedRoot(e ast.Expr) *ast.Ident {
	for {
		switch x := e.(type) {
		case *ast.ParenExpr:
			e = x.X
		case *ast.SelectorExpr:
			e = x.X
		case *ast.IndexExpr:
			e = x.X
		case *ast.StarExpr:
			e = x.X
		case *ast.Ident:
			return x
		default:
			return nil
		}
	}
}

// markAddressed records the variable that taking e's address lets other
// code rebind or rewrite: the identifier under field selections and array
// indexes. The address of a slice element cannot rebind the slice.
func (c *ruleContext) markAddressed(e ast.Expr, addressed map[types.Object]bool) {
	for {
		switch x := e.(type) {
		case *ast.ParenExpr:
			e = x.X
		case *ast.SelectorExpr:
			e = x.X
		case *ast.IndexExpr:
			t := c.info.TypeOf(x.X)
			if t == nil {
				return
			}
			if _, array := types.Unalias(t).Underlying().(*types.Array); !array {
				return
			}
			e = x.X
		case *ast.Ident:
			if obj := objectOf(c.info, x); obj != nil {
				addressed[obj] = true
			}
			return
		default:
			return
		}
	}
}

func isPointer(t types.Type) bool {
	if t == nil {
		return false
	}
	_, ok := types.Unalias(t).Underlying().(*types.Pointer)
	return ok
}

// isStandardLibrary reports whether pkg is a standard-library package this
// package imports, which cannot reach std/recursion to verify anything.
func (c *ruleContext) isStandardLibrary(pkg *types.Package) bool {
	imported := c.p.Imports[pkg.Path()]
	first, _, _ := strings.Cut(pkg.Path(), "/")
	return imported != nil && imported.Module == nil && !strings.Contains(first, ".")
}

// returnsInterface reports whether fn returns an interface other than
// error, through which a witness it receives can reach any method.
func returnsInterface(fn *types.Func) bool {
	results := fn.Type().(*types.Signature).Results()
	for i := 0; i < results.Len(); i++ {
		t := results.At(i).Type()
		if types.IsInterface(t) && !types.Identical(t, types.Universe.Lookup("error").Type()) {
			return true
		}
	}
	return false
}

// isDefineMethod reports whether fn is a circuit's Define(frontend.API)
// error method, the frontend.Circuit entry point.
func isDefineMethod(info *types.Info, fn *ast.FuncDecl) bool {
	if fn.Recv == nil || len(fn.Recv.List) == 0 || fn.Name.Name != "Define" {
		return false
	}
	obj, ok := info.Defs[fn.Name].(*types.Func)
	if !ok {
		return false
	}
	sig := obj.Type().(*types.Signature)
	if sig.Params().Len() != 1 || sig.Results().Len() != 1 || !types.Identical(sig.Results().At(0).Type(), types.Universe.Lookup("error").Type()) {
		return false
	}
	named, ok := types.Unalias(sig.Params().At(0).Type()).(*types.Named)
	return ok && named.Obj().Pkg() != nil && named.Obj().Pkg().Path() == gnarkapi.FrontendPath && named.Obj().Name() == "API"
}

// referencedElsewhere reports whether package code outside fn's own body
// refers to fn, as when one circuit's Define calls another's to compose it
// as a sub-circuit.
func (c *ruleContext) referencedElsewhere(fn *ast.FuncDecl) bool {
	obj, ok := c.info.Defs[fn.Name].(*types.Func)
	if !ok {
		return false
	}
	for id, used := range c.info.Uses {
		if f, ok := used.(*types.Func); ok && f.Origin() == obj && (id.Pos() < fn.Pos() || id.Pos() >= fn.End()) {
			return true
		}
	}
	return false
}

// isWitnessPublicField reports whether obj is the Public field declared by
// the Witness type of std/recursion/groth16 or std/recursion/plonk, however
// it is reached: directly, promoted through embedding, or through a type
// defined over Witness.
func isWitnessPublicField(obj types.Object) bool {
	v, ok := obj.(*types.Var)
	if !ok || !v.IsField() || v.Name() != "Public" {
		return false
	}
	origin := v.Origin()
	pkg := origin.Pkg()
	if pkg == nil || (pkg.Path() != recursionGroth16 && pkg.Path() != recursionPlonk) {
		return false
	}
	name, ok := pkg.Scope().Lookup("Witness").(*types.TypeName)
	if !ok {
		return false
	}
	st, ok := name.Type().Underlying().(*types.Struct)
	if !ok {
		return false
	}
	for i := 0; i < st.NumFields(); i++ {
		if st.Field(i) == origin {
			return true
		}
	}
	return false
}

func isWitnessPublic(sel *types.Selection) bool {
	return sel != nil && sel.Kind() == types.FieldVal && isWitnessPublicField(sel.Obj())
}

// isWitnessType reports whether t is, or points to, a struct declaring the
// recursion witness's Public field: Witness itself or a type defined over it.
func isWitnessType(t types.Type) bool {
	if pointer, ok := types.Unalias(t).Underlying().(*types.Pointer); ok {
		t = pointer.Elem()
	}
	st, ok := types.Unalias(t).Underlying().(*types.Struct)
	if !ok {
		return false
	}
	for i := 0; i < st.NumFields(); i++ {
		if isWitnessPublicField(st.Field(i)) {
			return true
		}
	}
	return false
}

// containsWitness reports whether a value of type t carries a recursion
// witness at any depth: through pointers, slices, arrays, maps, channels,
// or struct fields.
func containsWitness(t types.Type, seen map[types.Type]bool) bool {
	if seen[t] {
		return false
	}
	seen[t] = true
	switch u := types.Unalias(t).Underlying().(type) {
	case *types.Pointer:
		return containsWitness(u.Elem(), seen)
	case *types.Slice:
		return containsWitness(u.Elem(), seen)
	case *types.Array:
		return containsWitness(u.Elem(), seen)
	case *types.Map:
		return containsWitness(u.Key(), seen) || containsWitness(u.Elem(), seen)
	case *types.Chan:
		return containsWitness(u.Elem(), seen)
	case *types.Struct:
		for i := 0; i < u.NumFields(); i++ {
			if isWitnessPublicField(u.Field(i)) || containsWitness(u.Field(i).Type(), seen) {
				return true
			}
		}
	}
	return false
}

// holdsWitness reports whether e's value carries a recursion witness.
func (c *ruleContext) holdsWitness(e ast.Expr) bool {
	t := c.info.TypeOf(e)
	return t != nil && containsWitness(t, map[types.Type]bool{})
}

// publicExpr reports whether e is a witness's public inputs: its Public
// slice, part of it, an element, a pointer to any of them, or a local
// assigned one of those.
func (c *ruleContext) publicExpr(e ast.Expr, public map[types.Object]bool) bool {
	for {
		switch x := e.(type) {
		case *ast.ParenExpr:
			e = x.X
			continue
		case *ast.SliceExpr:
			e = x.X
			continue
		case *ast.IndexExpr:
			e = x.X
			continue
		case *ast.UnaryExpr:
			if x.Op == token.AND {
				e = x.X
				continue
			}
		case *ast.StarExpr:
			e = x.X
			continue
		}
		break
	}
	switch x := e.(type) {
	case *ast.SelectorExpr:
		return isWitnessPublic(c.info.Selections[x])
	case *ast.Ident:
		return public[objectOf(c.info, x)]
	}
	return false
}

// escapesToInterface reports whether n stores a value holding a recursion
// witness into an interface: an assignment or declaration of an
// interface-typed variable, a conversion to an interface type, or an
// interface-typed element of a composite literal.
func (c *ruleContext) escapesToInterface(n ast.Node) bool {
	isInterface := func(t types.Type) bool {
		return t != nil && types.IsInterface(t)
	}
	switch x := n.(type) {
	case *ast.AssignStmt:
		if len(x.Lhs) == len(x.Rhs) {
			for i, lhs := range x.Lhs {
				if !isBlank(lhs) && isInterface(c.info.TypeOf(lhs)) && c.holdsWitness(x.Rhs[i]) {
					return true
				}
			}
		}
	case *ast.ValueSpec:
		// var _ I = (*T)(nil) asserts an implementation and stores nothing.
		if x.Type != nil && isInterface(c.info.TypeOf(x.Type)) && len(x.Names) == len(x.Values) {
			for i, value := range x.Values {
				if x.Names[i].Name != "_" && c.holdsWitness(value) {
					return true
				}
			}
		}
	case *ast.SendStmt:
		if t := c.info.TypeOf(x.Chan); t != nil {
			if ch, ok := types.Unalias(t).Underlying().(*types.Chan); ok && isInterface(ch.Elem()) && c.holdsWitness(x.Value) {
				return true
			}
		}
	case *ast.CallExpr:
		if tv := c.info.Types[x.Fun]; tv.IsType() && isInterface(tv.Type) && len(x.Args) == 1 && c.holdsWitness(x.Args[0]) {
			return true
		}
		if id, ok := unparen(x.Fun).(*ast.Ident); ok && len(x.Args) > 1 {
			if builtin, ok := c.info.Uses[id].(*types.Builtin); ok && builtin.Name() == "append" {
				if t := c.info.TypeOf(x.Args[0]); t != nil {
					if slice, ok := types.Unalias(t).Underlying().(*types.Slice); ok && isInterface(slice.Elem()) {
						for _, arg := range x.Args[1:] {
							if c.holdsWitness(arg) {
								return true
							}
						}
					}
				}
			}
		}
	case *ast.CompositeLit:
		t := c.info.TypeOf(x)
		if t == nil {
			return false
		}
		for i, elt := range x.Elts {
			value := elt
			if kv, ok := elt.(*ast.KeyValueExpr); ok {
				value = kv.Value
			}
			var slot types.Type
			switch u := types.Unalias(t).Underlying().(type) {
			case *types.Slice:
				slot = u.Elem()
			case *types.Array:
				slot = u.Elem()
			case *types.Map:
				slot = u.Elem()
			case *types.Struct:
				if kv, ok := elt.(*ast.KeyValueExpr); ok {
					if key, ok := kv.Key.(*ast.Ident); ok {
						if field, ok := c.info.Uses[key].(*types.Var); ok {
							slot = field.Type()
						}
					}
				} else if i < u.NumFields() {
					slot = u.Field(i).Type()
				}
			}
			if isInterface(slot) && c.holdsWitness(value) {
				return true
			}
		}
	}
	return false
}

// witnessRead names the witness whose Public field x selects, by its field
// path from Define's receiver when it has one.
func (c *ruleContext) witnessRead(x *ast.SelectorExpr, sel *types.Selection, scope *witnessScope) witnessRead {
	key, resolved := c.witnessPath(x.X, scope, 0)
	display := types.ExprString(unparen(x.X))
	// A promoted Public goes through embedded fields; name them.
	t := sel.Recv()
	index := sel.Index()
	for _, i := range index[:len(index)-1] {
		if pointer, ok := types.Unalias(t).Underlying().(*types.Pointer); ok {
			t = pointer.Elem()
		}
		st, ok := types.Unalias(t).Underlying().(*types.Struct)
		if !ok {
			break
		}
		field := st.Field(i)
		key += "." + strconv.Itoa(i)
		display += "." + field.Name()
		t = field.Type()
	}
	if !resolved {
		key = display
	}
	return witnessRead{expr: x, witness: display, key: key, resolved: resolved}
}

// isShapeRead reports whether the Public selector on top of stack is read
// only for its shape: under len or cap, or ranged over without taking
// values, possibly after slicing, indexing, or selecting a field such as
// an element's Limbs.
func isShapeRead(info *types.Info, stack []ast.Node) bool {
	child := stack[len(stack)-1]
	i := len(stack) - 2
	for ; i >= 0; i-- {
		switch parent := stack[i].(type) {
		case *ast.ParenExpr:
			child = parent
			continue
		case *ast.SliceExpr:
			if parent.X == child {
				child = parent
				continue
			}
		case *ast.IndexExpr:
			if parent.X == child {
				child = parent
				continue
			}
		case *ast.SelectorExpr:
			if sel := info.Selections[parent]; parent.X == child && sel != nil && sel.Kind() == types.FieldVal {
				child = parent
				continue
			}
		}
		break
	}
	if i < 0 {
		return false
	}
	switch parent := stack[i].(type) {
	case *ast.RangeStmt:
		return parent.X == child && (parent.Value == nil || isBlank(parent.Value))
	case *ast.CallExpr:
		id, ok := unparen(parent.Fun).(*ast.Ident)
		if !ok {
			return false
		}
		builtin, ok := info.Uses[id].(*types.Builtin)
		return ok && (builtin.Name() == "len" || builtin.Name() == "cap")
	}
	return false
}

func isBlank(e ast.Expr) bool {
	if e == nil {
		return false
	}
	id, ok := unparen(e).(*ast.Ident)
	return ok && id.Name == "_"
}

// isCalled reports whether the selector on top of stack is the function of
// a call rather than a method value.
func isCalled(x *ast.SelectorExpr, stack []ast.Node) bool {
	var child ast.Node = x
	for i := len(stack) - 2; i >= 0; i-- {
		switch parent := stack[i].(type) {
		case *ast.ParenExpr:
			child = parent
			continue
		case *ast.CallExpr:
			return parent.Fun == child
		}
		return false
	}
	return false
}

func isVerifying(fn *types.Func) bool {
	if fn == nil || fn.Pkg() == nil || receiverName(fn) != "Verifier" {
		return false
	}
	path := fn.Pkg().Path()
	return (path == recursionGroth16 || path == recursionPlonk) && verifyingMethods[fn.Name()]
}

// resultDiscarded reports whether the value of the call on top of stack is
// thrown away: used as a statement, deferred, run as a goroutine, or bound
// only to _ by an assignment or a var declaration.
func resultDiscarded(stack []ast.Node) bool {
	child := stack[len(stack)-1]
	i := len(stack) - 2
	for ; i >= 0; i-- {
		if paren, ok := stack[i].(*ast.ParenExpr); ok {
			child = paren
			continue
		}
		break
	}
	if i < 0 {
		return false
	}
	switch parent := stack[i].(type) {
	case *ast.ExprStmt, *ast.DeferStmt, *ast.GoStmt:
		return true
	case *ast.AssignStmt:
		return isBlank(boundTarget(parent.Lhs, parent.Rhs, child))
	case *ast.ValueSpec:
		names := make([]ast.Expr, len(parent.Names))
		for j, name := range parent.Names {
			names[j] = name
		}
		return isBlank(boundTarget(names, parent.Values, child))
	}
	return false
}

// boundTarget returns the target value is bound to: its own position when
// targets and values pair up, or the first target when one call returns
// several values, the first of which is a predicate's result.
func boundTarget(targets, values []ast.Expr, value ast.Node) ast.Expr {
	for i, v := range values {
		if v != value {
			continue
		}
		switch {
		case len(targets) == len(values):
			return targets[i]
		case len(values) == 1 && len(targets) > 0:
			return targets[0]
		}
	}
	return nil
}

// witnessArgument returns the argument of a verifying call that holds the
// witness or witnesses, or nil.
func witnessArgument(info *types.Info, call *ast.CallExpr) ast.Expr {
	for _, arg := range call.Args {
		t := info.TypeOf(arg)
		if t == nil {
			continue
		}
		if slice, ok := types.Unalias(t).Underlying().(*types.Slice); ok {
			t = slice.Elem()
		}
		if isWitnessType(t) {
			return arg
		}
	}
	return nil
}

// resolveVerified records in verified the witnesses a verifying call's
// witness argument names: each element of a slice or array literal, also
// through a local holding one; a witness rebuilt as a literal from another
// witness's public inputs; or the argument's own field path. It reports
// false when one of them cannot be named.
func (c *ruleContext) resolveVerified(e ast.Expr, scope *witnessScope, depth int, verified map[string]string) bool {
	if depth > 8 {
		return false
	}
	e = unparen(e)
	if id, ok := e.(*ast.Ident); ok {
		if value, ok := scope.aliases[c.info.Uses[id]]; ok {
			if _, literal := unparen(value).(*ast.CompositeLit); literal {
				return c.resolveVerified(value, scope, depth+1, verified)
			}
		}
	}
	lit, ok := e.(*ast.CompositeLit)
	if !ok {
		key, ok := c.witnessPath(e, scope, 0)
		if ok {
			verified[key] = types.ExprString(e)
		}
		return ok
	}
	t := c.info.TypeOf(lit)
	if t == nil {
		return false
	}
	switch u := types.Unalias(t).Underlying().(type) {
	case *types.Slice, *types.Array:
		for _, elt := range lit.Elts {
			if kv, ok := elt.(*ast.KeyValueExpr); ok {
				elt = kv.Value
			}
			if !c.resolveVerified(elt, scope, depth+1, verified) {
				return false
			}
		}
		return true
	case *types.Struct:
		// A witness rebuilt from another witness's public inputs.
		for i, elt := range lit.Elts {
			value := elt
			field := -1
			if kv, ok := elt.(*ast.KeyValueExpr); ok {
				value = kv.Value
				if key, ok := kv.Key.(*ast.Ident); ok {
					for j := 0; j < u.NumFields(); j++ {
						if u.Field(j).Name() == key.Name {
							field = j
						}
					}
				}
			} else {
				field = i
			}
			if field < 0 || field >= u.NumFields() || !isWitnessPublicField(u.Field(field)) {
				continue
			}
			if source := c.publicSource(value, scope, depth+1); source != nil {
				if key, ok := c.witnessPath(source, scope, 0); ok {
					verified[key] = types.ExprString(source)
					return true
				}
			}
			return false
		}
	}
	return false
}

// publicSource returns the witness whose Public field e selects, through
// slicing, dereferences, and locals standing for one, or nil.
func (c *ruleContext) publicSource(e ast.Expr, scope *witnessScope, depth int) ast.Expr {
	for depth <= 8 {
		switch x := unparen(e).(type) {
		case *ast.SliceExpr:
			e = x.X
		case *ast.StarExpr:
			e = x.X
		case *ast.SelectorExpr:
			if isWitnessPublic(c.info.Selections[x]) {
				return x.X
			}
			return nil
		case *ast.Ident:
			value, ok := scope.aliases[c.info.Uses[x]]
			if !ok {
				return nil
			}
			e = value
		default:
			return nil
		}
		depth++
	}
	return nil
}

// witnessPath names a witness by its field path from Define's receiver,
// ignoring indexes, slicing, and type conversions, so c.Witnesses[i] and
// c.Witnesses match, and following locals that stand for one expression.
// It fails for anything else, such as a call result or a local copy that
// is later modified.
func (c *ruleContext) witnessPath(e ast.Expr, scope *witnessScope, depth int) (string, bool) {
	if depth > 8 {
		return "", false
	}
	switch x := unparen(e).(type) {
	case *ast.Ident:
		obj := c.info.Uses[x]
		if scope.receiver != nil && obj == scope.receiver {
			return "receiver", true
		}
		if value, ok := scope.aliases[obj]; ok {
			return c.witnessPath(value, scope, depth+1)
		}
		return "", false
	case *ast.SelectorExpr:
		sel := c.info.Selections[x]
		if sel == nil || sel.Kind() != types.FieldVal {
			return "", false
		}
		path, ok := c.witnessPath(x.X, scope, depth+1)
		for _, index := range sel.Index() {
			path += "." + strconv.Itoa(index)
		}
		return path, ok
	case *ast.IndexExpr:
		return c.witnessPath(x.X, scope, depth+1)
	case *ast.SliceExpr:
		return c.witnessPath(x.X, scope, depth+1)
	case *ast.StarExpr:
		return c.witnessPath(x.X, scope, depth+1)
	case *ast.UnaryExpr:
		if x.Op == token.AND {
			return c.witnessPath(x.X, scope, depth+1)
		}
	case *ast.CallExpr:
		if len(x.Args) == 1 && c.info.Types[x.Fun].IsType() {
			return c.witnessPath(x.Args[0], scope, depth+1)
		}
	}
	return "", false
}

// handOffKind says what a call passes to code other than the recursion
// verifier, gnark's frontend API, a builtin, or a type conversion.
type handOffKind int

const (
	handsNothing handOffKind = iota
	// handsPublic: a witness's public inputs, but no witness.
	handsPublic
	// handsWitness: a recursion witness, or a value holding one such as the
	// circuit receiver.
	handsWitness
)

func (c *ruleContext) handOff(call *ast.CallExpr, callee *types.Func, scope *witnessScope) handOffKind {
	if id, ok := unparen(call.Fun).(*ast.Ident); ok {
		if _, builtin := c.info.Uses[id].(*types.Builtin); builtin {
			return handsNothing
		}
	}
	if c.info.Types[call.Fun].IsType() {
		return handsNothing
	}
	if callee != nil && callee.Pkg() != nil {
		switch callee.Pkg().Path() {
		case recursionGroth16, recursionPlonk, gnarkapi.FrontendPath:
			return handsNothing
		}
	}
	operands := append([]ast.Expr(nil), call.Args...)
	if sel, ok := unparen(call.Fun).(*ast.SelectorExpr); ok {
		if selection := c.info.Selections[sel]; selection != nil && selection.Kind() == types.MethodVal {
			operands = append(operands, sel.X)
		}
	}
	kind := handsNothing
	for _, operand := range operands {
		switch {
		case c.holdsWitness(operand):
			return handsWitness
		case c.publicExpr(operand, scope.public):
			kind = handsPublic
		}
	}
	return kind
}

// containsVerification reports whether body calls a verifying method,
// counting IsValidProof only when its result is kept.
func (c *ruleContext) containsVerification(body *ast.BlockStmt) bool {
	found := false
	var stack []ast.Node
	ast.Inspect(body, func(n ast.Node) bool {
		if n == nil {
			stack = stack[:len(stack)-1]
			return true
		}
		stack = append(stack, n)
		if call, ok := n.(*ast.CallExpr); ok {
			if callee := calledFunc(c.info, call); isVerifying(callee) && !(callee.Name() == "IsValidProof" && resultDiscarded(stack)) {
				found = true
			}
		}
		return true
	})
	return found
}

func verifiedList(verified map[string]string) string {
	names := make([]string, 0, len(verified))
	for _, name := range verified {
		names = append(names, name)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}
