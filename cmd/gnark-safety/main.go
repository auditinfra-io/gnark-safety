package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/auditinfra-io/gnark-safety/internal/analyzer"
	"github.com/auditinfra-io/gnark-safety/internal/output"
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, ".")) }

func run(args []string, stdout, stderr io.Writer, dir string) int {
	if len(args) == 2 && args[0] == "explain" {
		if text, ok := analyzer.RuleHelp(args[1]); ok {
			fmt.Fprintf(stdout, "%s\n\n%s\n", args[1], text)
			return 0
		}
		fmt.Fprintf(stderr, "unknown rule: %s\n", args[1])
		return 2
	}
	if len(args) == 0 || args[0] != "scan" {
		usage(stderr)
		return 2
	}
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	format := fs.String("format", "text", "text, json, or sarif")
	destination := fs.String("output", "", "write output to a file")
	failOn := fs.String("fail-on", "high", "high or none")
	timeout := fs.Duration("timeout", 2*time.Minute, "package loading and analysis timeout")
	maxHints := fs.Int("max-hints", 10000, "maximum hint call sites")
	maxOutput := fs.Int64("max-output-bytes", 16<<20, "maximum rendered output size")
	if fs.Parse(args[1:]) != nil || fs.NArg() == 0 || (*format != "text" && *format != "json" && *format != "sarif") || (*failOn != "high" && *failOn != "none") || *timeout <= 0 || *maxHints <= 0 || *maxOutput <= 0 {
		usage(stderr)
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	r, err := analyzer.ScanContext(ctx, dir, fs.Args(), analyzer.Options{MaxHints: *maxHints})
	if err != nil {
		fmt.Fprintf(stderr, "gnark-safety: %v\n", err)
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
	if *destination != "" {
		if err := os.WriteFile(*destination, rendered.Bytes(), 0o644); err != nil {
			fmt.Fprintf(stderr, "gnark-safety: %v\n", err)
			return 2
		}
	} else if _, err := stdout.Write(rendered.Bytes()); err != nil {
		fmt.Fprintf(stderr, "gnark-safety: %v\n", err)
		return 2
	}
	if *failOn == "high" && len(r.Findings) > 0 {
		return 1
	}
	return 0
}
func usage(w io.Writer) {
	fmt.Fprintln(w, "usage: gnark-safety scan [--format text|json|sarif] [--output file] [--fail-on high|none] [--timeout duration] [--max-hints n] [--max-output-bytes n] <package patterns...>\n       gnark-safety explain <rule-id>")
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
