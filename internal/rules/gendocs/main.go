// gendocs rewrites the generated rule sections of the repository docs from
// the registry in internal/rules. Run it through `go generate
// ./internal/rules`; pass -check to verify without writing.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/auditinfra-io/gnark-safety/internal/rules"
)

func main() {
	root := flag.String("root", ".", "repository root")
	check := flag.Bool("check", false, "report stale files instead of rewriting them")
	flag.Parse()
	stale := false
	for _, doc := range rules.Documents {
		path := filepath.Join(*root, doc.Path)
		current, err := os.ReadFile(path)
		if err != nil {
			fail(err)
		}
		updated, err := doc.Regenerate(current)
		if err != nil {
			fail(err)
		}
		if bytes.Equal(current, updated) {
			continue
		}
		if *check {
			fmt.Fprintf(os.Stderr, "%s is out of date; run go generate ./internal/rules\n", doc.Path)
			stale = true
			continue
		}
		if err := os.WriteFile(path, updated, 0o644); err != nil {
			fail(err)
		}
	}
	if stale {
		os.Exit(1)
	}
}

func fail(err error) {
	fmt.Fprintf(os.Stderr, "gendocs: %v\n", err)
	os.Exit(2)
}
