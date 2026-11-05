package analyzer

import (
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	goversion "go/version"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/auditinfra-io/gnark-safety/internal/gnarkapi"
	"github.com/auditinfra-io/gnark-safety/internal/rules"
	"github.com/auditinfra-io/gnark-safety/internal/version"
	"github.com/auditinfra-io/gnark-safety/pkg/report"
	"golang.org/x/tools/go/packages"
)

const (
	relationRule     = rules.HintRelationIncomplete
	unusedOutputRule = rules.HintOutputUnused
)

const maximumAnalyzedBitWidth = 4096

var limitations = []string{
	"No findings means that no pattern these rules recognize matched; it is not evidence that the circuits are sound.",
	"A finding is a lead for review, not a confirmed vulnerability; its confidence, its evidence, and the rule's documented limitations say how far the rule can tell.",
	"Analysis follows one level of unconditional direct local helper calls; deeper or recursive call graphs are not modeled.",
	"Reflection, generated code, external helpers, complex aliasing, and dynamic hint selection are not modeled.",
}

type Options struct {
	MaxHints int
	FieldModulus *big.Int
	FieldName string
	IncludeTests bool
	IncludeExamples bool
	IncludeTestSupport bool
	SkipUnloadable bool
	PathBase string
	Env []string
	Tags []string
	BuildFlags []string
	CGO bool
	GOOS string
	GOARCH string
}

func Scan(dir string, patterns []string) (report.Report, error) {
	return ScanContext(context.Background(), dir, patterns, Options{})
}

func buildEnv(env []string, opts Options) []string {
	base := append([]string{}, env...)
	if len(base) == 0 {
		base = append(base, os.Environ()...)
	}
	filtered := base[:0]
	for _, entry := range base {
		if strings.HasPrefix(entry, "GOFLAGS=") || strings.HasPrefix(entry, "CGO_ENABLED=") || strings.HasPrefix(entry, "GOOS=") || strings.HasPrefix(entry, "GOARCH=") {
			continue
		}
		filtered = append(filtered, entry)
	}
	filtered = append(filtered, "GOFLAGS=")
	if opts.CGO {
		filtered = append(filtered, "CGO_ENABLED=1")
	} else {
		filtered = append(filtered, "CGO_ENABLED=0")
	}
	if opts.GOOS != "" {
		filtered = append(filtered, "GOOS="+opts.GOOS)
	}
	if opts.GOARCH != "" {
		filtered = append(filtered, "GOARCH="+opts.GOARCH)
	}
	return filtered
}

func goCommandVersion(ctx context.Context, dir string, env []string) string {
	cmd := exec.CommandContext(ctx, "go", "env", "GOVERSION")
	cmd.Dir = dir
	cmd.Env = env
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func toolchainSkewHint(built, goCommand string) string {
	if !goversion.IsValid(built) || !goversion.IsValid(goCommand) {
		return ""
	}
	if goversion.Compare(goversion.Lang(goCommand), goversion.Lang(built)) <= 0 {
		return ""
	}
	return fmt.Sprintf("gnark-safety was built with %s, but the go command is %s: a type checker older than the go command cannot load its standard library. Rebuild gnark-safety with %s or newer, or run it with a matching GOTOOLCHAIN.\n", built, goCommand, goCommand)
}

func ScanContext(ctx context.Context, dir string, patterns []string, opts Options) (report.Report, error) {
	r := newReport()
	maxHints := opts.MaxHints
	if maxHints == 0 {
		maxHints = defaultMaxHints
	}
	if maxHints < 0 {
		return r, errors.New("max hints must be positive")
	}
	pkgEnv := buildEnv(opts.Env, opts)
	buildFlags := append([]string{}, opts.BuildFlags...)
	if len(opts.Tags) > 0 {
		buildFlags = append(buildFlags, "-tags="+strings.Join(opts.Tags, ","))
	}
	fset := token.NewFileSet()
	pkgs, err := packages.Load(&packages.Config{Context: ctx, Dir: dir, Env: pkgEnv, Fset: fset, Tests: opts.IncludeTests, BuildFlags: buildFlags, Mode: packages.NeedName | packages.NeedModule | packages.NeedFiles | packages.NeedCompiledGoFiles | packages.NeedImports | packages.NeedTypes | packages.NeedTypesInfo | packages.NeedSyntax | packages.NeedDeps}, patterns...)
	if err != nil {
		return r, err
	}
	if len(pkgs) == 0 {
		return r, errors.New("package patterns matched no packages")
	}
	var loadErrs []string
	seenErrs := map[string]bool{}
	var usable []*packages.Package
	analyzable := 0
	for _, p := range pkgs {
		errs := packageErrors(p)
		for _, e := range errs {
			if !seenErrs[e] {
				seenErrs[e] = true
				loadErrs = append(loadErrs, e)
			}
		}
		if len(errs) == 0 {
			usable = append(usable, p)
			if !strings.HasSuffix(p.ID, ".test") {
				analyzable++
			}
		} else if !strings.HasSuffix(p.ID, ".test") {
			r.Coverage.Skipped = append(r.Coverage.Skipped, report.SkippedPackage{Package: p.ID, Errors: errs})
		}
	}
	if len(loadErrs) > 0 {
		hint := toolchainSkewHint(runtime.Version(), goCommandVersion(ctx, dir, pkgEnv))
		if !opts.SkipUnloadable || analyzable == 0 {
			sort.Strings(loadErrs)
			msg := "package loading/type checking failed:\n" + strings.Join(loadErrs, "\n")
			if hint != "" {
				msg += "\n" + hint
			}
			return r, errors.New(msg)
		}
		for _, skipped := range r.Coverage.Skipped {
			r.Diagnostics = append(r.Diagnostics, fmt.Sprintf("package %s was not analyzed because it failed to load: %s", skipped.Package, skipped.Errors[0]))
		}
		r.Limitations = append(r.Limitations, fmt.Sprintf("Partial scan: %d requested package(s) failed to load and were not analyzed (see coverage.skipped), so findings in them are not reported.", len(r.Coverage.Skipped)))
		if hint != "" {
			r.Diagnostics = append(r.Diagnostics, hint)
		}
	}
	pkgs = usable
	base := dir
	if opts.PathBase != "" {
		base = opts.PathBase
	}
	absDir, err := filepath.Abs(base)
	if err != nil {
		return r, fmt.Errorf("resolve path base: %w", err)
	}
	r.Coverage.TestsIncluded = opts.IncludeTests
	seenFiles := map[string]bool{}
	seenPackages := map[string]bool{}
	var directives []*directive
	gnarkPackages := map[string]bool{}
	for _, p := range pkgs {
		if err := ctx.Err(); err != nil {
			return r, fmt.Errorf("analysis canceled: %w", err)
		}
		if strings.HasSuffix(p.ID, ".test") {
			continue
		}
		if r.Module == "" && p.Module != nil {
			r.Module = p.Module.Path
		}
		seenPackages[p.PkgPath] = true
		if importsGnark(p) {
			gnarkPackages[p.PkgPath] = true
		}
		var files []*ast.File
		for _, file := range p.Syntax {
			name := fset.Position(file.Package).Filename
			if !seenFiles[name] {
				seenFiles[name] = true
				files = append(files, file)
			}
		}
		found, err := analyzeFiles(ctx, &r, p, files, fset, absDir, maxHints, opts)
		if err != nil {
			return r, err
		}
		directives = append(directives, found...)
	}
	r.Coverage.Packages, r.Coverage.GnarkPackages, r.Coverage.Files = len(seenPackages), len(gnarkPackages), len(seenFiles)
	finish(&r, directives, opts)
	return r, nil
}

