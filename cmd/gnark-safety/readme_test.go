package main

import (
	"bufio"
	"bytes"
	"os"
	"strconv"
	"strings"
	"testing"
)

// TestREADMETranscripts runs every `$ gnark-safety ...` command in the
// README's console blocks and compares the real output, and the exit status
// shown by a following `$ echo $?`, with the transcript. Documentation that
// claims an output the tool no longer produces fails here instead of
// misleading readers.
func TestREADMETranscripts(t *testing.T) {
	if n := checkTranscripts(t, "../../README.md", true); n == 0 {
		t.Fatal("README contains no gnark-safety transcripts")
	}
}

// TestWalkthroughTranscripts does the same for docs/walkthrough.md. Its
// setup commands (git clone, go install, go test, --version) record one run
// on one machine and are skipped, with the exit status that follows them.
func TestWalkthroughTranscripts(t *testing.T) {
	if n := checkTranscripts(t, "../../docs/walkthrough.md", false); n < 3 {
		t.Fatalf("walkthrough has %d checked transcripts, want its two scans and its explain", n)
	}
}

// checkTranscripts verifies the console blocks in path and returns how many
// gnark-safety commands it ran. strict rejects any other command.
func checkTranscripts(t *testing.T, path string, strict bool) int {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	transcripts := 0
	for _, block := range consoleBlocks(string(content)) {
		lines := strings.Split(strings.TrimSuffix(block, "\n"), "\n")
		lastExit, skipped := -1, false
		for i := 0; i < len(lines); i++ {
			command, ok := strings.CutPrefix(lines[i], "$ ")
			if !ok {
				t.Fatalf("%s: console block line %q is not preceded by a command", path, lines[i])
			}
			var expected []string
			for i+1 < len(lines) && !strings.HasPrefix(lines[i+1], "$ ") {
				i++
				expected = append(expected, lines[i])
			}
			want := strings.Join(expected, "\n")
			if command == "echo $?" {
				if skipped {
					continue
				}
				if lastExit < 0 || want != strconv.Itoa(lastExit) {
					t.Errorf("%s claims exit %q, last command exited %d", path, want, lastExit)
				}
				continue
			}
			args, ok := strings.CutPrefix(command, "gnark-safety ")
			if !ok || args == "--version" {
				if strict {
					t.Fatalf("%s: unsupported transcript command %q", path, command)
				}
				skipped = true
				continue
			}
			skipped = false
			var out, stderr bytes.Buffer
			lastExit = run(strings.Fields(args), &out, &stderr, "../..")
			// A terminal shows the report (stdout) and then the summary
			// (stderr), which the CLI writes last.
			got := strings.TrimSuffix(out.String()+stderr.String(), "\n")
			if got != want {
				t.Errorf("%s transcript for %q is stale\n got:\n%s\nwant:\n%s", path, command, got, want)
			}
			transcripts++
		}
	}
	return transcripts
}

func consoleBlocks(markdown string) []string {
	var blocks []string
	var current strings.Builder
	inside := false
	scanner := bufio.NewScanner(strings.NewReader(markdown))
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case !inside && line == "```console":
			inside = true
			current.Reset()
		case inside && line == "```":
			inside = false
			blocks = append(blocks, current.String())
		case inside:
			current.WriteString(line + "\n")
		}
	}
	return blocks
}
