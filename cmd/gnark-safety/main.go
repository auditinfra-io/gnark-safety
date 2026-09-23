package main

import (
	"flag"
	"fmt"
	"io"
	"os"

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
	if fs.Parse(args[1:]) != nil || fs.NArg() == 0 || (*format != "text" && *format != "json" && *format != "sarif") || (*failOn != "high" && *failOn != "none") {
		usage(stderr)
		return 2
	}
	r, err := analyzer.Scan(dir, fs.Args())
	if err != nil {
		fmt.Fprintf(stderr, "gnark-safety: %v\n", err)
		return 2
	}
	w := stdout
	var file *os.File
	if *destination != "" {
		file, err = os.Create(*destination)
		if err != nil {
			fmt.Fprintf(stderr, "gnark-safety: %v\n", err)
			return 2
		}
		defer file.Close()
		w = file
	}
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
	if *failOn == "high" && len(r.Findings) > 0 {
		return 1
	}
	return 0
}
func usage(w io.Writer) {
	fmt.Fprintln(w, "usage: gnark-safety scan [--format text|json|sarif] [--output file] [--fail-on high|none] <package patterns...>\n       gnark-safety explain <rule-id>")
}
