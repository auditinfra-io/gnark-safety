// Package vet adapts gnark-safety to the golang.org/x/tools/go/analysis
// framework, so drivers such as `go vet -vettool` can run it. It reuses the
// analyzer core on each package the driver has already type-checked.
package vet

import (
	"fmt"
	"go/token"
	"regexp"
	"strconv"

	"github.com/auditinfra-io/gnark-safety/internal/analyzer"
	"github.com/auditinfra-io/gnark-safety/internal/rules"
	"golang.org/x/tools/go/analysis"
)

// Analyzer reports gnark-safety findings as analysis diagnostics. Messages
// carry the severity and rule ID; the diagnostic URL links to the rule.
var Analyzer = &analysis.Analyzer{
	Name: "gnarksafety",
	Doc:  "report soundness findings in gnark circuits\n\nRuns every gnark-safety rule; see `gnark-safety explain` for the rule list.",
	URL:  "https://github.com/auditinfra-io/gnark-safety",
	Run:  run,
}

func run(pass *analysis.Pass) (any, error) {
	r, err := analyzer.AnalyzePackage(pass.Fset, pass.Pkg, pass.TypesInfo, pass.Files)
	if err != nil {
		return nil, err
	}
	for _, f := range r.Findings {
		pos, ok := position(pass, f.File, f.Line, f.Column)
		if !ok {
			return nil, fmt.Errorf("gnark-safety: cannot map %s:%d:%d to a file of %s", f.File, f.Line, f.Column, pass.Pkg.Path())
		}
		diagnostic := analysis.Diagnostic{Pos: pos, Category: f.RuleID, Message: fmt.Sprintf("%s [%s] %s", f.Severity, f.RuleID, f.Message)}
		if spec, ok := rules.Lookup(f.RuleID); ok {
			diagnostic.URL = spec.HelpURI()
		}
		pass.Report(diagnostic)
	}
	// Suppression warnings name "file:line: message"; report them where the
	// directive is so a malformed or stale suppression is visible in vet too.
	for _, text := range r.Diagnostics {
		m := diagnosticLocation.FindStringSubmatch(text)
		if m == nil {
			continue
		}
		line, _ := strconv.Atoi(m[2])
		if pos, ok := position(pass, m[1], line, 1); ok {
			pass.Report(analysis.Diagnostic{Pos: pos, Category: "suppression", Message: m[3]})
		}
	}
	return nil, nil
}

var diagnosticLocation = regexp.MustCompile(`^(.+\.go):(\d+): (.+)$`)

// position maps a reported file, line, and column back to a token.Pos in
// one of the package's files.
func position(pass *analysis.Pass, file string, line, column int) (token.Pos, bool) {
	for _, syntax := range pass.Files {
		tf := pass.Fset.File(syntax.Pos())
		if tf == nil || tf.Name() != file || line < 1 || line > tf.LineCount() {
			continue
		}
		start := tf.LineStart(line)
		offset := tf.Offset(start) + column - 1
		if column < 1 || offset > tf.Size() {
			return start, true
		}
		return tf.Pos(offset), true
	}
	return token.NoPos, false
}
