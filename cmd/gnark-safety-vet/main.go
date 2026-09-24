// gnark-safety-vet runs gnark-safety as a go vet tool:
//
//	go install github.com/auditinfra-io/gnark-safety/cmd/gnark-safety-vet@latest
//	go vet -vettool="$(command -v gnark-safety-vet)" ./...
//
// go vet type-checks each package (including its tests) and this tool
// reports findings as vet diagnostics. Use the gnark-safety command for
// severity gating, SARIF, example downgrading, and scan coverage.
package main

import (
	"github.com/auditinfra-io/gnark-safety/internal/vet"
	"golang.org/x/tools/go/analysis/unitchecker"
)

func main() { unitchecker.Main(vet.Analyzer) }
