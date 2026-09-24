package rules

import (
	"bytes"
	"fmt"
	"strings"
)

// Explain renders the plain-text help for `gnark-safety explain`.
func Explain(id string) (string, bool) {
	spec, ok := Lookup(id)
	if !ok {
		return "", false
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s: %s\n", spec.ID, spec.Title)
	fmt.Fprintf(&b, "Severity: %s. Confidence: %s. Class: %s.\n\n", spec.SeverityLabel(), spec.Confidence, spec.Class)
	fmt.Fprintf(&b, "%s\n\n%s\n", spec.Summary, spec.Description)
	if spec.Limitations != "" {
		fmt.Fprintf(&b, "\nWhere it stops: %s\n", spec.Limitations)
	}
	fmt.Fprintf(&b, "\nReference: %s\n", spec.HelpURI())
	return b.String(), true
}

// Table renders the Markdown summary table used by README.md and
// docs/rules.md.
func Table() string {
	var b strings.Builder
	b.WriteString("| Rule | Severity | Class | What it means |\n")
	b.WriteString("|---|---|---|---|\n")
	for _, spec := range specs {
		fmt.Fprintf(&b, "| [`%s`](%s) | %s | %s | %s |\n", spec.ID, spec.HelpURI(), spec.SeverityLabel(), spec.Class, tableCell(spec.Summary))
	}
	return b.String()
}

// Reference renders one Markdown section per rule for docs/rules.md. The
// headings are the anchors SARIF helpUri values link to.
func Reference() string {
	var b strings.Builder
	for i, spec := range specs {
		if i > 0 {
			b.WriteString("\n")
		}
		fmt.Fprintf(&b, "### %s\n\n", spec.ID)
		fmt.Fprintf(&b, "**%s**: severity %s; confidence %s; class %s.\n\n", spec.Title, spec.SeverityLabel(), spec.Confidence, spec.Class)
		fmt.Fprintf(&b, "%s\n\n%s\n", spec.Summary, spec.Description)
		if spec.Limitations != "" {
			fmt.Fprintf(&b, "\n*Where it stops:* %s\n", spec.Limitations)
		}
	}
	return b.String()
}

func tableCell(text string) string { return strings.ReplaceAll(text, "|", `\|`) }

// Section names a generated block delimited by BEGIN/END marker comments.
type Section struct {
	Name   string
	Render func() string
}

// Document lists the generated sections a repository file must contain.
type Document struct {
	Path     string
	Sections []Section
}

// Documents is every file with generated rule content, relative to the
// repository root.
var Documents = []Document{
	{Path: "README.md", Sections: []Section{{Name: "RULE TABLE", Render: Table}}},
	{Path: "docs/rules.md", Sections: []Section{{Name: "RULE TABLE", Render: Table}, {Name: "RULE REFERENCE", Render: Reference}}},
}

// Regenerate replaces each section's body between its markers. It fails if
// a marker is missing or duplicated rather than silently skipping a file.
func (d Document) Regenerate(content []byte) ([]byte, error) {
	for _, section := range d.Sections {
		begin := []byte("<!-- BEGIN GENERATED " + section.Name + " -->\n")
		end := []byte("<!-- END GENERATED " + section.Name + " -->")
		if bytes.Count(content, begin) != 1 || bytes.Count(content, end) != 1 {
			return nil, fmt.Errorf("%s: want exactly one %q/%q marker pair", d.Path, strings.TrimSpace(string(begin)), end)
		}
		start := bytes.Index(content, begin) + len(begin)
		stop := bytes.Index(content, end)
		if stop < start {
			return nil, fmt.Errorf("%s: %s markers are out of order", d.Path, section.Name)
		}
		var updated bytes.Buffer
		updated.Write(content[:start])
		updated.WriteString(section.Render())
		updated.Write(content[stop:])
		content = updated.Bytes()
	}
	return content, nil
}
