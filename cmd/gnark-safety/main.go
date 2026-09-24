package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/auditinfra-io/gnark-safety/internal/analyzer"
	"github.com/auditinfra-io/gnark-safety/internal/output"
	"github.com/auditinfra-io/gnark-safety/internal/rules"
	"github.com/auditinfra-io/gnark-safety/internal/version"
	"github.com/auditinfra-io/gnark-safety/pkg/report"
	"github.com/consensys/gnark-crypto/ecc"
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, ".")) }

func run(args []string, stdout, stderr io.Writer, dir string) int {
	if len(args) == 1 && (args[0] == "version" || args[0] == "--version" || args[0] == "-version") {
		fmt.Fprintf(stdout, "gnark-safety %s\n", version.String())
		return 0
	}
	if len(args) == 1 && args[0] == "explain" {
		width := 0
		for _, spec := range rules.All() {
			width = max(width, len(spec.ID))
		}
		for _, spec := range rules.All() {
			fmt.Fprintf(stdout, "%-*s  %-15s %s\n", width, spec.ID, spec.SeverityLabel(), spec.Title)
		}
		return 0
	}
	if len(args) == 2 && args[0] == "explain" {
		if text, ok := rules.Explain(args[1]); ok {
			fmt.Fprint(stdout, text)
			return 0
		}
		fmt.Fprintf(stderr, "unknown rule: %s (run `gnark-safety explain` to list rules)\n", args[1])
		return 2
	}
	if len(args) > 0 && args[0] == "inventory" {
		return inventory(args[1:], stdout, stderr, dir)
	}
	if len(args) == 0 || args[0] != "scan" {
		usage(stderr)
		return 2
	}
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	format := fs.String("format", "text", "text, json, or sarif")
	destination := fs.String("output", "", "write output to a file")
	sarifDestination := fs.String("sarif-output", "", "also write SARIF 2.1.0 to this file, in the same pass")
	relativeTo := fs.String("relative-to", "", "report paths relative to this directory (default: the current directory)")
	failOn := fs.String("fail-on", "high", "lowest severity that fails the scan: critical, high, medium, low, info, or none")
	allowEmpty := fs.Bool("allow-empty", false, "succeed even when no scanned package imports gnark")
	includeTests := fs.Bool("include-tests", false, "also analyze _test.go files")
	includeExamples := fs.Bool("include-examples", false, "keep the original severity of findings in example directories")
	timeout := fs.Duration("timeout", 2*time.Minute, "package loading and analysis timeout")
	maxHints := fs.Int("max-hints", 10000, "maximum hint call sites")
	maxOutput := fs.Int64("max-output-bytes", 16<<20, "maximum rendered output size")
	field := fs.String("field", "unknown", "unknown, bn254, or bls12-381")
	if fs.Parse(args[1:]) != nil {
		usage(stderr)
		return 2
	}
	threshold, gated := report.ParseSeverity(*failOn)
	if fs.NArg() == 0 || (*format != "text" && *format != "json" && *format != "sarif") || (!gated && *failOn != "none") || *timeout <= 0 || *maxHints <= 0 || *maxOutput <= 0 || (*field != "unknown" && *field != "bn254" && *field != "bls12-381") {
		usage(stderr)
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	pathBase := *relativeTo
	if pathBase != "" && !filepath.IsAbs(pathBase) {
		pathBase = filepath.Join(dir, pathBase)
	}
	opts := analyzer.Options{MaxHints: *maxHints, IncludeTests: *includeTests, IncludeExamples: *includeExamples, PathBase: pathBase}
	if *field == "bn254" {
		opts.FieldModulus, opts.FieldName = ecc.BN254.ScalarField(), "BN254 scalar field"
	} else if *field == "bls12-381" {
		opts.FieldModulus, opts.FieldName = ecc.BLS12_381.ScalarField(), "BLS12-381 scalar field"
	}
	r, err := analyzer.ScanContext(ctx, dir, fs.Args(), opts)
	if err != nil {
		fmt.Fprintf(stderr, "gnark-safety: %v\n", err)
		return 2
	}
	// A scan that examined no gnark code must not read as a clean pass: a
	// mistyped pattern or a moved package would otherwise turn CI green.
	if r.Coverage.GnarkPackages == 0 && !*allowEmpty {
		fmt.Fprintf(stderr, "gnark-safety: none of the %d scanned package(s) import gnark, so no circuit code was analyzed. Check the package patterns, or pass --allow-empty if no circuits are expected.\n", r.Coverage.Packages)
		return 2
	}
	var rendered bytes.Buffer
	w := &limitedWriter{writer: &rendered, remaining: *maxOutput}
	switch *format {
	case "text":
		err = output.Text(w, r)
	case "json":
		err = output.JSON(w, r)
	case "sarif":
		err = output.SARIF(w, r)
	}
	if err != nil {
		fmt.Fprintf(stderr, "gnark-safety: %v\n", err)
		return 2
	}
	// Render everything before writing anything, so an output-limit or
	// rendering error never leaves one file written and the other missing.
	var sarifRendered bytes.Buffer
	if *sarifDestination != "" {
		if err := output.SARIF(&limitedWriter{writer: &sarifRendered, remaining: *maxOutput}, r); err != nil {
			fmt.Fprintf(stderr, "gnark-safety: %v\n", err)
			return 2
		}
		if err := os.WriteFile(*sarifDestination, sarifRendered.Bytes(), 0o644); err != nil {
			fmt.Fprintf(stderr, "gnark-safety: %v\n", err)
			return 2
		}
	}
	if *destination != "" {
		if err := os.WriteFile(*destination, rendered.Bytes(), 0o644); err != nil {
			fmt.Fprintf(stderr, "gnark-safety: %v\n", err)
			return 2
		}
	} else if _, err := stdout.Write(rendered.Bytes()); err != nil {
		fmt.Fprintf(stderr, "gnark-safety: %v\n", err)
		return 2
	}
	for _, diagnostic := range r.Diagnostics {
		fmt.Fprintf(stderr, "gnark-safety: warning: %s\n", diagnostic)
	}
	fails := gated && hasFindingAtOrAbove(r, threshold)
	fmt.Fprintln(stderr, summary(r, *failOn, fails))
	if fails {
		return 1
	}
	return 0
}

// inventory lists every gnark hint call site without applying rules. It
// replaces the deprecated gnark-hint-scan command.
func inventory(args []string, stdout, stderr io.Writer, dir string) int {
	fs := flag.NewFlagSet("inventory", flag.ContinueOnError)
	fs.SetOutput(stderr)
	format := fs.String("format", "text", "text or json")
	includeTests := fs.Bool("include-tests", false, "also inventory _test.go files")
	timeout := fs.Duration("timeout", 2*time.Minute, "package loading and analysis timeout")
	maxHints := fs.Int("max-hints", 10000, "maximum hint call sites")
	maxOutput := fs.Int64("max-output-bytes", 16<<20, "maximum rendered output size")
	if fs.Parse(args) != nil || fs.NArg() == 0 || (*format != "text" && *format != "json") || *timeout <= 0 || *maxHints <= 0 || *maxOutput <= 0 {
		usage(stderr)
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	r, err := analyzer.ScanContext(ctx, dir, fs.Args(), analyzer.Options{MaxHints: *maxHints, IncludeTests: *includeTests, IncludeExamples: true})
	if err != nil {
		fmt.Fprintf(stderr, "gnark-safety: %v\n", err)
		return 2
	}
	var rendered bytes.Buffer
	w := &limitedWriter{writer: &rendered, remaining: *maxOutput}
	if *format == "json" {
		err = output.InventoryJSON(w, r)
	} else {
		err = output.InventoryText(w, r)
	}
	if err == nil {
		_, err = stdout.Write(rendered.Bytes())
	}
	if err != nil {
		fmt.Fprintf(stderr, "gnark-safety: %v\n", err)
		return 2
	}
	fmt.Fprintf(stderr, "gnark-safety: %d hint call site(s); scanned %d package(s), %d importing gnark\n", len(r.Hints), r.Coverage.Packages, r.Coverage.GnarkPackages)
	return 0
}

// hasFindingAtOrAbove reports whether any finding meets the gate threshold.
func hasFindingAtOrAbove(r report.Report, threshold report.Severity) bool {
	for _, finding := range r.Findings {
		if finding.Severity.Rank() >= threshold.Rank() {
			return true
		}
	}
	return false
}

// summary is the one-line stderr verdict. It always states coverage so a
// quiet scan is never silently quiet.
func summary(r report.Report, failOn string, fails bool) string {
	verdict := "passes"
	if fails {
		verdict = "fails"
	}
	c := r.Coverage
	notes := []string{fmt.Sprintf("scanned %d package(s), %d importing gnark", c.Packages, c.GnarkPackages)}
	if c.ExamplesDowngraded > 0 {
		notes = append(notes, fmt.Sprintf("%d downgraded as example code", c.ExamplesDowngraded))
	}
	if len(r.Suppressed) > 0 {
		notes = append(notes, fmt.Sprintf("%d suppressed", len(r.Suppressed)))
	}
	if !c.TestsIncluded {
		notes = append(notes, "_test.go files excluded")
	}
	head := "no findings"
	if len(r.Findings) > 0 {
		counts := map[report.Severity]int{}
		files := map[string]bool{}
		for _, f := range r.Findings {
			counts[f.Severity]++
			files[f.File] = true
		}
		var parts []string
		for _, severity := range report.Severities {
			if counts[severity] > 0 {
				parts = append(parts, fmt.Sprintf("%d %s", counts[severity], severity))
			}
		}
		head = fmt.Sprintf("%d finding(s) [%s] in %d file(s)", len(r.Findings), strings.Join(parts, ", "), len(files))
	}
	return fmt.Sprintf("gnark-safety: %s; %s — %s (--fail-on %s)", head, strings.Join(notes, "; "), verdict, failOn)
}

func usage(w io.Writer) {
	fmt.Fprintln(w, `usage: gnark-safety scan [flags] <package patterns...>
       gnark-safety inventory [--format text|json] [--include-tests] <package patterns...>
       gnark-safety explain [rule-id]
       gnark-safety --version

scan flags:
  --format text|json|sarif     output format (default text)
  --output file                write output to a file instead of stdout
  --sarif-output file          also write SARIF 2.1.0 to a file in the same pass
  --relative-to dir            report paths relative to dir (default: current
                               directory); use the repository root for SARIF
  --fail-on severity|none      lowest severity that exits 1: critical, high,
                               medium, low, info, or none (default high)
  --allow-empty                exit 0 even if no scanned package imports gnark
  --include-tests              also analyze _test.go files
  --include-examples           keep original severity in example directories
  --field unknown|bn254|bls12-381
  --timeout duration           default 2m
  --max-hints n                default 10000
  --max-output-bytes n         default 16777216

Exit codes: 0 pass, 1 a finding at or above --fail-on, 2 usage, loading, or
empty-scan error.`)
}

type limitedWriter struct {
	writer    io.Writer
	remaining int64
}

func (w *limitedWriter) Write(p []byte) (int, error) {
	if int64(len(p)) > w.remaining {
		return 0, fmt.Errorf("output limit exceeded")
	}
	n, err := w.writer.Write(p)
	w.remaining -= int64(n)
	return n, err
}
