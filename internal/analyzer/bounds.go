package analyzer

import (
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"math/big"

	"github.com/auditinfra-io/gnark-safety/internal/gnarkapi"
)

// A remainder can be proved canonical without a comparison: when its
// range-checked value, or the value of the range-checked limbs it is rebuilt
// from, cannot reach a divisor whose value is known at compile time. This is
// how emulated-field code (KoalaBear, BabyBear, Goldilocks) bounds r < p.

// maximumReconstructionBits caps value-based evidence below the smallest
// pairing-friendly scalar field gnark compiles to (BN254's is about 2^254), so
// a limb reconstruction cannot wrap around the field modulus.
const maximumReconstructionBits = 240

// evaluator computes integer values fixed at compile time.
type evaluator struct {
	info    *types.Info
	helpers map[*types.Func]*ast.FuncDecl
	stable  map[*types.Var]bool
}

func newEvaluator(info *types.Info, helpers map[*types.Func]*ast.FuncDecl) *evaluator {
	return &evaluator{info: info, helpers: helpers, stable: map[*types.Var]bool{}}
}

// value returns the integer value of e when it is fixed at compile time: a
// Go constant, a conversion of one, math.Pow(2, k), integer arithmetic over
// such values, or an unexported package-level variable initialized to one
// that no code in the package can change. It returns nil otherwise.
func (ev *evaluator) value(e ast.Expr) *big.Int {
	e = unparen(e)
	if tv := ev.info.Types[e]; tv.Value != nil {
		return constantInteger(tv.Value)
	}
	switch x := e.(type) {
	case *ast.CallExpr:
		if tv := ev.info.Types[x.Fun]; tv.IsType() && len(x.Args) == 1 {
			v := ev.value(x.Args[0])
			if v == nil || !fitsConversion(v, tv.Type) {
				return nil
			}
			return v
		}
		fn := calledFunc(ev.info, x)
		if fn == nil {
			return nil
		}
		switch {
		case isPackageFunc(fn, "math", "Pow") && len(x.Args) == 2:
			base, exponent := ev.value(x.Args[0]), ev.value(x.Args[1])
			if base != nil && exponent != nil && base.Cmp(big.NewInt(2)) == 0 && exponent.Sign() >= 0 && exponent.Cmp(big.NewInt(1023)) <= 0 {
				return new(big.Int).Lsh(big.NewInt(1), uint(exponent.Int64()))
			}
		case isPackageFunc(fn, "math/big", "NewInt") && len(x.Args) == 1:
			return ev.value(x.Args[0])
		case isBigIntMethod(fn, "SetUint64", "SetInt64") && len(x.Args) == 1 && ev.freshBigInt(x.Fun):
			return ev.value(x.Args[0])
		}
	case *ast.BinaryExpr:
		a, b := ev.value(x.X), ev.value(x.Y)
		if a == nil || b == nil {
			return nil
		}
		var result *big.Int
		switch x.Op {
		case token.ADD:
			result = new(big.Int).Add(a, b)
		case token.SUB:
			result = new(big.Int).Sub(a, b)
		case token.MUL:
			result = new(big.Int).Mul(a, b)
		case token.SHL:
			if b.Sign() >= 0 && b.Cmp(big.NewInt(1023)) <= 0 {
				result = new(big.Int).Lsh(a, uint(b.Int64()))
			}
		}
		// Arithmetic on variables runs in the expression's Go type, which
		// wraps or rounds; only an exact result is the program's value.
		if result == nil || !exact(result, ev.info.TypeOf(x)) {
			return nil
		}
		return result
	case *ast.Ident:
		if v, ok := ev.info.Uses[x].(*types.Var); ok {
			return ev.packageValue(v)
		}
	}
	return nil
}

func constantInteger(v constant.Value) *big.Int {
	v = constant.ToInt(v)
	if v.Kind() != constant.Int {
		return nil
	}
	result, ok := new(big.Int).SetString(v.ExactString(), 10)
	if !ok {
		return nil
	}
	return result
}

// fitsConversion reports whether converting v to t preserves it: integer
// types must hold it, and interface (frontend.Variable) and float targets
// pass it through. math.Pow results are powers of two, exact in a float64.
func fitsConversion(v *big.Int, t types.Type) bool {
	switch u := t.Underlying().(type) {
	case *types.Interface:
		return true
	case *types.Basic:
		info := u.Info()
		switch {
		case info&types.IsFloat != 0:
			return true
		case info&types.IsInteger == 0:
			return false
		}
		bits := map[types.BasicKind]uint{types.Int8: 8, types.Int16: 16, types.Int32: 32, types.Int64: 64, types.Int: 64, types.Uint8: 8, types.Uint16: 16, types.Uint32: 32, types.Uint64: 64, types.Uint: 64, types.Uintptr: 64}[u.Kind()]
		if bits == 0 {
			return false
		}
		if info&types.IsUnsigned != 0 {
			return v.Sign() >= 0 && v.BitLen() <= int(bits)
		}
		return v.BitLen() < int(bits)
	}
	return false
}

// exact reports whether Go computes v without loss in type t: an integer
// type must hold it rather than wrap around, and a float must represent it
// without rounding.
func exact(v *big.Int, t types.Type) bool {
	if t == nil {
		return false
	}
	if basic, ok := t.Underlying().(*types.Basic); ok && basic.Info()&types.IsFloat != 0 {
		precision := uint(53)
		if basic.Kind() == types.Float32 {
			precision = 24
		}
		return new(big.Float).SetPrec(precision).SetInt(v).Acc() == big.Exact
	}
	return fitsConversion(v, t)
}

// fieldConstant returns the value of e when it is fixed at compile time and
// the circuit sees that same number: non-negative and below the field
// modulus. With no field configured, it must be below 2^240, which every
// pairing-friendly field gnark compiles to exceeds. A larger constant wraps
// around the field, so its integer value says nothing about the circuit's.
func fieldConstant(ev *evaluator, e ast.Expr, field *big.Int) *big.Int {
	v := ev.value(e)
	if v == nil || v.Sign() < 0 {
		return nil
	}
	limit := field
	if limit == nil {
		limit = new(big.Int).Lsh(big.NewInt(1), maximumReconstructionBits)
	}
	if v.Cmp(limit) >= 0 {
		return nil
	}
	return v
}

func isBigIntMethod(fn *types.Func, names ...string) bool {
	if fn.Pkg() == nil || fn.Pkg().Path() != "math/big" || receiverName(fn) != "Int" {
		return false
	}
	for _, name := range names {
		if fn.Name() == name {
			return true
		}
	}
	return false
}

// freshBigInt reports whether a method call's receiver is a new big.Int, as
// in new(big.Int).SetUint64(c).
func (ev *evaluator) freshBigInt(fun ast.Expr) bool {
	sel, ok := unparen(fun).(*ast.SelectorExpr)
	if !ok {
		return false
	}
	call, ok := unparen(sel.X).(*ast.CallExpr)
	if !ok || len(call.Args) != 1 {
		return false
	}
	id, ok := unparen(call.Fun).(*ast.Ident)
	if !ok {
		return false
	}
	builtin, ok := ev.info.Uses[id].(*types.Builtin)
	return ok && builtin.Name() == "new"
}

// packageValue returns the value of an unexported package-level variable
// whose initializer is fixed at compile time and which no code in the package
// reassigns, takes the address of, or passes where it could be changed.
func (ev *evaluator) packageValue(v *types.Var) *big.Int {
	if v.Pkg() == nil || v.Parent() != v.Pkg().Scope() || v.Exported() {
		return nil
	}
	var initializer ast.Expr
	for _, init := range ev.info.InitOrder {
		if len(init.Lhs) == 1 && init.Lhs[0] == v {
			initializer = init.Rhs
		}
	}
	if initializer == nil || !ev.unchanged(v) {
		return nil
	}
	return ev.value(initializer)
}

// readOnlyBigIntMethods are the *big.Int methods that do not modify their
// receiver.
var readOnlyBigIntMethods = map[string]bool{"Cmp": true, "CmpAbs": true, "BitLen": true, "Sign": true, "String": true, "Text": true, "Uint64": true, "Int64": true, "IsUint64": true, "IsInt64": true, "Bit": true, "TrailingZeroBits": true, "ProbablyPrime": true, "Format": true, "Append": true, "MarshalText": true, "MarshalJSON": true, "Float64": true}

// unchanged reports whether every use of the package variable v in the
// package's functions and initializers only reads it: as an operand, as an
// argument to a math/big method or a frontend API call, or as the receiver of
// a read-only *big.Int method.
func (ev *evaluator) unchanged(v *types.Var) bool {
	if stable, ok := ev.stable[v]; ok {
		return stable
	}
	stable := true
	check := func(root ast.Node) {
		var stack []ast.Node
		ast.Inspect(root, func(n ast.Node) bool {
			if n == nil {
				stack = stack[:len(stack)-1]
				return true
			}
			stack = append(stack, n)
			if id, ok := n.(*ast.Ident); ok && stable && ev.info.Uses[id] == v {
				stable = ev.readOnly(stack)
			}
			return true
		})
	}
	for _, decl := range ev.helpers {
		check(decl.Body)
	}
	for _, init := range ev.info.InitOrder {
		check(init.Rhs)
	}
	ev.stable[v] = stable
	return stable
}

func (ev *evaluator) readOnly(stack []ast.Node) bool {
	node, ancestors := stack[len(stack)-1], stack[:len(stack)-1]
	for len(ancestors) > 0 {
		paren, ok := ancestors[len(ancestors)-1].(*ast.ParenExpr)
		if !ok {
			break
		}
		node, ancestors = paren, ancestors[:len(ancestors)-1]
	}
	if len(ancestors) == 0 {
		return false
	}
	switch parent := ancestors[len(ancestors)-1].(type) {
	case *ast.BinaryExpr:
		return true
	case *ast.SelectorExpr:
		if parent.X != node || len(ancestors) < 2 {
			return false
		}
		call, ok := ancestors[len(ancestors)-2].(*ast.CallExpr)
		if !ok || call.Fun != parent {
			return false
		}
		fn := calledFunc(ev.info, call)
		return fn != nil && fn.Pkg() != nil && fn.Pkg().Path() == "math/big" && receiverName(fn) == "Int" && readOnlyBigIntMethods[fn.Name()]
	case *ast.CallExpr:
		if parent.Fun == node {
			return false
		}
		fn := calledFunc(ev.info, parent)
		if fn == nil || fn.Pkg() == nil {
			return false
		}
		// math/big methods change only their receiver; frontend API calls
		// read constants.
		return (fn.Pkg().Path() == "math/big" && receiverName(fn) == "Int") || fn.Pkg().Path() == gnarkapi.FrontendPath
	}
	return false
}

// rangeBits returns the tightest bit width that scope proves for a value
// matched by matches: api.ToBinary(v, k) or a range checker's Check(v, k),
// either unconditional, in every branch of an if/else, or unconditional in
// one local helper called unconditionally.
func rangeBits(scope *ast.BlockStmt, ev *evaluator, helpers map[*types.Func]*ast.FuncDecl, matches func(ast.Expr) bool) (int, bool) {
	best, found := 0, false
	record := func(bits int) {
		if bits > 0 && (!found || bits < best) {
			best, found = bits, true
		}
	}
	ast.Inspect(scope, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.FuncLit:
			return false
		case *ast.IfStmt:
			if x.Else != nil && !conditionallyExecuted(scope, x) {
				if bits, ok := branchBits(x, ev, helpers, matches); ok {
					record(bits)
				}
			}
		case *ast.CallExpr:
			if conditionallyExecuted(scope, x) {
				return true
			}
			if bits, ok := checkedWidth(x, ev, matches); ok {
				record(bits)
			} else if decl := localHelper(ev.info, x, helpers); decl != nil {
				params := parameterIndexes(decl, ev.info)
				inner := func(e ast.Expr) bool {
					index, ok := params[objectOf(ev.info, e)]
					return ok && index < len(x.Args) && matches(x.Args[index])
				}
				if bits, ok := rangeBits(decl.Body, ev, nil, inner); ok {
					record(bits)
				}
			}
		}
		return true
	})
	return best, found
}

// branchBits returns the width that every branch of an if/else chain proves,
// which is the widest of them, or false when a branch proves none.
func branchBits(stmt *ast.IfStmt, ev *evaluator, helpers map[*types.Func]*ast.FuncDecl, matches func(ast.Expr) bool) (int, bool) {
	width, ok := rangeBits(stmt.Body, ev, helpers, matches)
	if !ok {
		return 0, false
	}
	var other int
	switch e := stmt.Else.(type) {
	case *ast.BlockStmt:
		other, ok = rangeBits(e, ev, helpers, matches)
	case *ast.IfStmt:
		if e.Else == nil {
			return 0, false
		}
		other, ok = branchBits(e, ev, helpers, matches)
	default:
		return 0, false
	}
	if !ok {
		return 0, false
	}
	return max(width, other), true
}

// checkedWidth recognizes api.ToBinary(v, k) and Check(v, k) on a gnark range
// checker (frontend.Rangechecker, or std/rangecheck) with a constant width.
func checkedWidth(call *ast.CallExpr, ev *evaluator, matches func(ast.Expr) bool) (int, bool) {
	fn := calledFunc(ev.info, call)
	if fn == nil || fn.Pkg() == nil || len(call.Args) < 2 || !matches(call.Args[0]) {
		return 0, false
	}
	path := fn.Pkg().Path()
	isToBinary := path == gnarkapi.FrontendPath && fn.Name() == "ToBinary" && receiverName(fn) != ""
	isCheck := (path == gnarkapi.FrontendPath || path == rangecheckPath) && fn.Name() == "Check" && receiverName(fn) != ""
	if !isToBinary && !isCheck {
		return 0, false
	}
	width := ev.value(call.Args[1])
	if width == nil || width.Sign() <= 0 || width.BitLen() > 16 {
		return 0, false
	}
	return int(width.Int64()), true
}

const rangecheckPath = "github.com/consensys/gnark/std/rangecheck"

// remainderMaximum returns the largest value scope allows for the remainder:
// 2^k-1 when it is range-checked to k bits, or the largest value of the
// range-checked limbs it is rebuilt from, as in r = hi*2^b + lo. A constraint
// that forces lo to zero when hi is all ones, the usual check that r stays
// below a modulus 2^(k+b) - 2^b + 1, lowers that maximum to (2^k-1)*2^b.
func remainderMaximum(scope *ast.BlockStmt, ev *evaluator, helpers map[*types.Func]*ast.FuncDecl, outputs types.Object, aliases map[types.Object]int) (*big.Int, string) {
	info := ev.info
	isRemainder := func(e ast.Expr) bool { return outputIndex(info, e, outputs, aliases) == 1 }
	var best *big.Int
	how := ""
	consider := func(v *big.Int, evidence string) {
		if v.BitLen() <= maximumReconstructionBits && (best == nil || v.Cmp(best) < 0) {
			best, how = v, evidence
		}
	}
	if bits, ok := rangeBits(scope, ev, helpers, isRemainder); ok {
		consider(new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), uint(bits)), big.NewInt(1)), "range check of r")
	}
	ast.Inspect(scope, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || !isFrontendCall(info, call, "AssertIsEqual") || len(call.Args) != 2 || conditionallyExecuted(scope, call) {
			return true
		}
		for i := 0; i < 2; i++ {
			if !isRemainder(call.Args[i]) {
				continue
			}
			hi, lo, shift, ok := limbSum(ev, call.Args[1-i])
			if !ok {
				continue
			}
			hiBits, hiOK := rangeBits(scope, ev, helpers, func(e ast.Expr) bool { return sameExpr(info, e, hi) })
			loBits, loOK := rangeBits(scope, ev, helpers, func(e ast.Expr) bool { return sameExpr(info, e, lo) })
			if !hiOK || !loOK || new(big.Int).Lsh(big.NewInt(1), uint(loBits)).Cmp(shift) > 0 {
				continue
			}
			hiMax := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), uint(hiBits)), big.NewInt(1))
			maximum := new(big.Int).Mul(hiMax, shift)
			evidence := "range-checked limbs of r"
			if topLimbForcesZero(scope, ev, hi, lo, hiMax) {
				evidence = "range-checked limbs of r, with the low limb forced to zero when the high limb is all ones"
			} else {
				maximum.Add(maximum, new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), uint(loBits)), big.NewInt(1)))
			}
			consider(maximum, evidence)
		}
		return true
	})
	return best, how
}

// limbSum recognizes Add(Mul(hi, 2^b), lo), with the operands of Add and Mul
// in either order and 2^b a compile-time power of two.
func limbSum(ev *evaluator, e ast.Expr) (hi, lo ast.Expr, shift *big.Int, ok bool) {
	add, ok := apiCallArgs(ev.info, e, "Add")
	if !ok || len(add) != 2 {
		return nil, nil, nil, false
	}
	for i := 0; i < 2; i++ {
		mul, ok := apiCallArgs(ev.info, add[i], "Mul")
		if !ok || len(mul) != 2 || objectOf(ev.info, add[1-i]) == nil {
			continue
		}
		for j := 0; j < 2; j++ {
			factor := ev.value(mul[j])
			if factor == nil || factor.Sign() <= 0 || new(big.Int).And(factor, new(big.Int).Sub(factor, big.NewInt(1))).Sign() != 0 {
				continue
			}
			if objectOf(ev.info, mul[1-j]) != nil {
				return mul[1-j], add[1-i], factor, true
			}
		}
	}
	return nil, nil, nil, false
}

// topLimbForcesZero looks for an unconditional constraint that lo is zero
// whenever hi equals hiMax: AssertIsEqual(Mul(s, lo), 0) or
// AssertIsEqual(Select(s, lo, 0), 0), where s is IsZero(Sub(hi, hiMax)),
// directly or through a variable assigned once.
func topLimbForcesZero(scope *ast.BlockStmt, ev *evaluator, hi, lo ast.Expr, hiMax *big.Int) bool {
	info := ev.info
	isSelector := func(e ast.Expr) bool {
		e = singleDefinition(scope, info, e)
		args, ok := apiCallArgs(info, e, "IsZero")
		if !ok || len(args) != 1 {
			return false
		}
		sub, ok := apiCallArgs(info, args[0], "Sub")
		if !ok || len(sub) != 2 {
			return false
		}
		for i := 0; i < 2; i++ {
			if v := ev.value(sub[1-i]); v != nil && v.Cmp(hiMax) == 0 && sameExpr(info, sub[i], hi) {
				return true
			}
		}
		return false
	}
	isZero := func(e ast.Expr) bool {
		v := ev.value(e)
		return v != nil && v.Sign() == 0
	}
	forces := func(e ast.Expr) bool {
		if mul, ok := apiCallArgs(info, e, "Mul"); ok && len(mul) == 2 {
			return (isSelector(mul[0]) && sameExpr(info, mul[1], lo)) || (isSelector(mul[1]) && sameExpr(info, mul[0], lo))
		}
		if sel, ok := apiCallArgs(info, e, "Select"); ok && len(sel) == 3 {
			return isSelector(sel[0]) && sameExpr(info, sel[1], lo) && isZero(sel[2])
		}
		return false
	}
	found := false
	ast.Inspect(scope, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || found || !isFrontendCall(info, call, "AssertIsEqual") || len(call.Args) != 2 || conditionallyExecuted(scope, call) {
			return !found
		}
		found = (forces(call.Args[0]) && isZero(call.Args[1])) || (forces(call.Args[1]) && isZero(call.Args[0]))
		return !found
	})
	return found
}

// singleDefinition returns the expression a local variable is defined with,
// when e names a variable declared in scope and assigned exactly once there;
// otherwise it returns e.
func singleDefinition(scope *ast.BlockStmt, info *types.Info, e ast.Expr) ast.Expr {
	id, ok := unparen(e).(*ast.Ident)
	if !ok {
		return e
	}
	v, ok := info.Uses[id].(*types.Var)
	if !ok || v.Pos() < scope.Pos() || v.Pos() >= scope.End() {
		return e
	}
	var definition ast.Expr
	assignments := 0
	ast.Inspect(scope, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.AssignStmt:
			for i, lhs := range x.Lhs {
				lid, ok := lhs.(*ast.Ident)
				if !ok || (info.Defs[lid] != v && info.Uses[lid] != v) {
					continue
				}
				assignments++
				if len(x.Lhs) == len(x.Rhs) {
					definition = x.Rhs[i]
				}
			}
		case *ast.UnaryExpr:
			if x.Op == token.AND && objectOf(info, x.X) == v {
				assignments += 2
			}
		}
		return true
	})
	if assignments != 1 || definition == nil {
		return e
	}
	return definition
}

// successGuards returns the bodies of if E == nil { ... } statements in scope
// that run on every successful path: E has type error, there is no else, and
// the statement right after the if returns E, explicitly as the last result
// or through a bare return of a named result. When the body does not run, the
// function fails, and a Define that fails yields no constraint system.
func successGuards(scope *ast.BlockStmt, info *types.Info, helpers map[*types.Func]*ast.FuncDecl) []*ast.BlockStmt {
	var guarded []*ast.BlockStmt
	errorType := types.Universe.Lookup("error").Type()
	for i, stmt := range scope.List {
		ifStmt, ok := stmt.(*ast.IfStmt)
		if !ok || ifStmt.Init != nil || ifStmt.Else != nil || i+1 >= len(scope.List) || conditionallyExecuted(scope, ifStmt) {
			continue
		}
		cond, ok := unparen(ifStmt.Cond).(*ast.BinaryExpr)
		if !ok || cond.Op != token.EQL {
			continue
		}
		checked := cond.X
		if info.Types[cond.X].IsNil() {
			checked = cond.Y
		} else if !info.Types[cond.Y].IsNil() {
			continue
		}
		id, ok := unparen(checked).(*ast.Ident)
		if !ok {
			continue
		}
		v, ok := info.Uses[id].(*types.Var)
		if !ok || !types.Identical(v.Type(), errorType) {
			continue
		}
		ret, ok := scope.List[i+1].(*ast.ReturnStmt)
		if !ok {
			continue
		}
		switch {
		case len(ret.Results) > 0:
			last, ok := unparen(ret.Results[len(ret.Results)-1]).(*ast.Ident)
			if ok && info.Uses[last] == v {
				guarded = append(guarded, ifStmt.Body)
			}
		case namedResult(scope, info, helpers, v):
			guarded = append(guarded, ifStmt.Body)
		}
	}
	return guarded
}

// namedResult reports whether v is a named result of the function whose body
// is scope, so that a bare return in it returns v.
func namedResult(scope *ast.BlockStmt, info *types.Info, helpers map[*types.Func]*ast.FuncDecl, v *types.Var) bool {
	for _, decl := range helpers {
		if decl.Body != scope || decl.Type.Results == nil {
			continue
		}
		for _, field := range decl.Type.Results.List {
			for _, name := range field.Names {
				if info.Defs[name] == v {
					return true
				}
			}
		}
	}
	return false
}
