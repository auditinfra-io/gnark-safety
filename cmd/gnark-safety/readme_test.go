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
	content, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatal(err)
	}
	transcripts := 0
	for _, block := range consoleBlocks(string(content)) {
		lines := strings.Split(strings.TrimSuffix(block, "\n"), "\n")
		lastExit := -1
		for i := 0; i < len(lines); i++ {
			command, ok := strings.CutPrefix(lines[i], "$ ")
			if !ok {
				t.Fatalf("console block line %q is not preceded by a command", lines[i])
			}
			var expected []string
			for i+1 < len(lines) && !strings.HasPrefix(lines[i+1], "$ ") {
				i++
				expected = append(expected, lines[i])
			}
			want := strings.Join(expected, "\n")
			if command == "echo $?" {
				if lastExit < 0 || want != strconv.Itoa(lastExit) {
					t.Errorf("README claims exit %q, last command exited %d", want, lastExit)
				}
				continue
			}
			args, ok := strings.CutPrefix(command, "gnark-safety ")
			if !ok {
				t.Fatalf("unsupported transcript command %q", command)
			}
			var out, stderr bytes.Buffer
			lastExit = run(strings.Fields(args), &out, &stderr, "../..")
			// A terminal shows the report (stdout) and then the summary
			// (stderr), which the CLI writes last.
			got := strings.TrimSuffix(out.String()+stderr.String(), "\n")
			if got != want {
				t.Errorf("README transcript for %q is stale\n got:\n%s\nwant:\n%s", command, got, want)
			}
			transcripts++
		}
	}
	if transcripts == 0 {
		t.Fatal("README contains no gnark-safety transcripts")
	}
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
