package analyzer

import (
	"fmt"
	"go/ast"
	"go/token"
	"sort"
	"strings"

	"github.com/auditinfra-io/gnark-safety/internal/rules"
	"github.com/auditinfra-io/gnark-safety/pkg/report"
)

// directivePrefix follows Go's directive convention: no space after //.
const directivePrefix = "//gnark-safety:ignore"

// directive is one parsed //gnark-safety:ignore comment. It applies to
// findings on its own line (a trailing comment) and on the following line (a
// comment above the flagged statement).
type directive struct {
	file   string
	line   int
	ids    []string
	reason string
	used   map[string]bool
}

// collectDirectives parses the suppression comments in one file. Malformed
// directives are reported as diagnostics and never suppress anything, so a
// typo cannot silently hide a finding.
func collectDirectives(file *ast.File, fset *token.FileSet, path string) ([]*directive, []string) {
	var directives []*directive
	var diagnostics []string
	for _, group := range file.Comments {
		for _, comment := range group.List {
			pos := fset.Position(comment.Slash)
			where := fmt.Sprintf("%s:%d", path, pos.Line)
			text := comment.Text
			if strings.HasPrefix(text, "// gnark-safety:ignore") {
				diagnostics = append(diagnostics, where+": suppression ignored: write //gnark-safety:ignore with no space after //")
				continue
			}
			if !strings.HasPrefix(text, directivePrefix) {
				continue
			}
			rest := strings.TrimPrefix(text, directivePrefix)
			if rest != "" && rest[0] != ' ' && rest[0] != '\t' {
				continue // a different directive that shares the prefix
			}
			fields := strings.Fields(rest)
			if len(fields) < 2 {
				diagnostics = append(diagnostics, where+": suppression ignored: //gnark-safety:ignore needs a rule ID and a reason")
				continue
			}
			ids := strings.Split(fields[0], ",")
			valid := true
			for _, id := range ids {
				if _, ok := rules.Lookup(id); !ok {
					diagnostics = append(diagnostics, fmt.Sprintf("%s: suppression ignored: unknown rule %q", where, id))
					valid = false
				}
			}
			if valid {
				directives = append(directives, &directive{file: path, line: pos.Line, ids: ids, reason: strings.Join(fields[1:], " "), used: map[string]bool{}})
			}
		}
	}
	return directives, diagnostics
}

// applySuppressions moves findings matched by a directive into
// r.Suppressed and reports directives that matched nothing, so stale
// suppressions surface instead of accumulating.
func applySuppressions(r *report.Report, directives []*directive) {
	byFile := map[string][]*directive{}
	for _, d := range directives {
		byFile[d.file] = append(byFile[d.file], d)
	}
	kept := r.Findings[:0]
	for _, f := range r.Findings {
		if d := matchDirective(byFile[f.File], f); d != nil {
			d.used[f.RuleID] = true
			f.Suppression = &report.Suppression{Kind: "inSource", Justification: d.reason, Line: d.line}
			r.Suppressed = append(r.Suppressed, f)
			continue
		}
		kept = append(kept, f)
	}
	r.Findings = kept
	var unused []string
	for _, d := range directives {
		for _, id := range d.ids {
			if !d.used[id] {
				unused = append(unused, fmt.Sprintf("%s:%d: suppression of %s matched no finding on this or the next line", d.file, d.line, id))
			}
		}
	}
	sort.Strings(unused)
	r.Diagnostics = append(r.Diagnostics, unused...)
}

func matchDirective(candidates []*directive, f report.Finding) *directive {
	for _, d := range candidates {
		if d.line != f.Line && d.line != f.Line-1 {
			continue
		}
		for _, id := range d.ids {
			if id == f.RuleID {
				return d
			}
		}
	}
	return nil
}
