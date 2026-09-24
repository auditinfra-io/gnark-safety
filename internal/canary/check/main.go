// check compares a canary scan with its classified snapshot:
//
//	go run ./internal/canary/check -snapshot canary/gnark-std-v0.16.3.json -report scan.json
//
// It exits 1 when the scan has a finding the snapshot does not classify, or
// the snapshot lists a finding the scan no longer produces. With
// -ignore-lines it compares by rule, severity, file, and function only, for
// scans of unreleased gnark code whose lines move.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/auditinfra-io/gnark-safety/internal/canary"
	"github.com/auditinfra-io/gnark-safety/pkg/report"
)

func main() {
	snapshotPath := flag.String("snapshot", "", "classified snapshot (JSON)")
	reportPath := flag.String("report", "", "gnark-safety JSON report of the same target")
	ignoreLines := flag.Bool("ignore-lines", false, "match findings without line numbers")
	flag.Parse()
	if *snapshotPath == "" || *reportPath == "" {
		flag.Usage()
		os.Exit(2)
	}
	snapshot, err := canary.Load(*snapshotPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "canary: %v\n", err)
		os.Exit(2)
	}
	content, err := os.ReadFile(*reportPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "canary: %v\n", err)
		os.Exit(2)
	}
	var r report.Report
	if err := json.Unmarshal(content, &r); err != nil {
		fmt.Fprintf(os.Stderr, "canary: %s: %v\n", *reportPath, err)
		os.Exit(2)
	}
	unexpected, missing := canary.Diff(snapshot, r, *ignoreLines)
	for _, key := range unexpected {
		fmt.Printf("unclassified: %s\n", key)
	}
	for _, key := range missing {
		fmt.Printf("no longer reported: %s\n", key)
	}
	fmt.Printf("canary: %d finding(s), %d classified in %s; %d unclassified, %d no longer reported\n", len(r.Findings), len(snapshot.Findings), *snapshotPath, len(unexpected), len(missing))
	if len(unexpected) > 0 || len(missing) > 0 {
		fmt.Println("canary: read each change, then classify it in the snapshot or fix the rule")
		os.Exit(1)
	}
}
