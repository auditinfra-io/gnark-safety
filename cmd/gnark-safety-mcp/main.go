// Command gnark-safety-mcp serves gnark-safety's scan, inventory, and rule
// reference to AI coding assistants over the Model Context Protocol. It
// speaks only stdio: it runs locally, started by the assistant's client, and
// sends nothing anywhere else.
//
//	gnark-safety-mcp [--root DIR] [--timeout 2m] [--max-hints 10000] [--max-output-bytes 16777216]
//
// Every package load runs with a fixed environment (see env.go): the local Go
// toolchain only, no GOFLAGS, no go.work, no cgo.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/auditinfra-io/gnark-safety/internal/version"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("gnark-safety-mcp", flag.ContinueOnError)
	fs.SetOutput(stderr)
	root := fs.String("root", ".", "directory whose packages may be scanned; patterns must stay below it")
	timeout := fs.Duration("timeout", 2*time.Minute, "package loading and analysis timeout per call")
	maxHints := fs.Int("max-hints", 10000, "maximum hint call sites per call")
	maxOutput := fs.Int("max-output-bytes", 16<<20, "maximum size of one tool result")
	showVersion := fs.Bool("version", false, "print the version and exit")
	if fs.Parse(args) != nil || fs.NArg() != 0 || *timeout <= 0 || *maxHints <= 0 || *maxOutput <= 0 {
		fmt.Fprintln(stderr, "usage: gnark-safety-mcp [--root DIR] [--timeout 2m] [--max-hints 10000] [--max-output-bytes 16777216]")
		return 2
	}
	if *showVersion {
		fmt.Fprintf(stdout, "gnark-safety-mcp %s\n", version.String())
		return 0
	}
	resolved, err := resolveRoot(*root)
	if err != nil {
		fmt.Fprintf(stderr, "gnark-safety-mcp: root: %v\n", err)
		return 2
	}
	ctx := context.Background()
	env, err := loadEnv(ctx)
	if err != nil {
		fmt.Fprintf(stderr, "gnark-safety-mcp: %v\n", err)
		return 2
	}
	srv := newMCPServer(config{root: resolved, env: env, timeout: *timeout, maxHints: *maxHints, maxOutputBytes: *maxOutput})
	if err := srv.Run(ctx, &mcp.StdioTransport{}); err != nil {
		fmt.Fprintf(stderr, "gnark-safety-mcp: %v\n", err)
		return 1
	}
	return 0
}
