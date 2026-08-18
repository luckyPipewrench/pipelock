// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"io"
	"regexp"
	"strings"
	"testing"
)

// quickstart is the first command a new user runs, and both of its defects were
// the same shape: text nobody executed. These tests execute what it prints, or
// assert on the exact thing that made it wrong.

// repoOnlyPath matches directories that exist only in a source clone. A reader
// who installed from Homebrew, a container, or a release binary has none of
// them, so naming one hands them a command that cannot run.
var repoOnlyPath = regexp.MustCompile(`(^|[\s"'./])(configs|examples|testdata|charts|scripts)/`)

func quickstartText(t *testing.T, goos string) string {
	t.Helper()
	var buf bytes.Buffer
	writeQuickstart(&buf, goos)
	if buf.Len() == 0 {
		t.Fatal("quickstart printed nothing")
	}
	return buf.String()
}

func TestQuickstartNamesNoRepoOnlyPath(t *testing.T) {
	// The original text said `--config configs/balanced.yaml` in five of six
	// steps. That file ships only in the repository, so step two exited 1 with
	// "no such file or directory" for anyone who installed the binary.
	for _, goos := range []string{"linux", "darwin", "windows"} {
		t.Run(goos, func(t *testing.T) {
			for i, line := range strings.Split(quickstartText(t, goos), "\n") {
				if m := repoOnlyPath.FindString(line); m != "" {
					t.Errorf("line %d names %q, which exists only in a source clone: %s",
						i+1, strings.TrimSpace(m), line)
				}
			}
		})
	}
}

func TestQuickstartCreatesTheConfigItThenUses(t *testing.T) {
	// Every config path the walkthrough passes to a later step must be one an
	// earlier step told the reader to create. This is the property the old text
	// violated, stated so it cannot regress quietly.
	text := quickstartText(t, "linux")
	if !strings.Contains(text, "pipelock init --output ./"+quickstartConfig) {
		t.Fatalf("no step creates the config.\n%s", text)
	}
	configFlag := regexp.MustCompile(`--config (\S+)`)
	found := 0
	for _, m := range configFlag.FindAllStringSubmatch(text, -1) {
		found++
		if want := "./" + quickstartConfig; m[1] != want {
			t.Errorf("step passes --config %s, which no earlier step creates; want %s", m[1], want)
		}
	}
	if found == 0 {
		t.Error("no step passes --config, so this test proves nothing")
	}
}

func TestQuickstartUsesThePlatformsOwnSyntax(t *testing.T) {
	// The original printed bash export lines and a sudo /usr/local/bin command
	// on every platform, including Windows, which this project publishes
	// binaries for. None of it is runnable there.
	unix := quickstartText(t, "linux")
	if !strings.Contains(unix, "export HTTPS_PROXY=") {
		t.Error("unix walkthrough lost its export lines")
	}
	if !strings.Contains(unix, "sudo pipelock install /usr/local/bin/pipelock") {
		t.Error("unix walkthrough lost the system-wide install line")
	}

	win := quickstartText(t, "windows")
	for _, unwanted := range []string{"export ", "sudo ", "/usr/local/bin"} {
		if strings.Contains(win, unwanted) {
			t.Errorf("windows walkthrough contains %q, which does not work there:\n%s", unwanted, win)
		}
	}
	for _, wanted := range []string{"set HTTPS_PROXY=", "$env:HTTPS_PROXY"} {
		if !strings.Contains(win, wanted) {
			t.Errorf("windows walkthrough is missing %q", wanted)
		}
	}
}

func TestQuickstartReachesTheRealCLI(t *testing.T) {
	// The checks above call the writer directly. This one drives the binary, so
	// a walkthrough that is correct in a unit test and unreachable in practice
	// still fails.
	stdout, stderr, code := runCLI(t, "quickstart")
	if code != 0 {
		t.Fatalf("quickstart exited %d\nstderr: %s", code, stderr)
	}
	if !strings.Contains(stdout, "pipelock init --output") {
		t.Errorf("walkthrough did not reach stdout.\nstdout: %q", stdout)
	}
	if repoOnlyPath.MatchString(stdout) {
		t.Errorf("shipped walkthrough names a repo-only path.\nstdout: %q", stdout)
	}
	// A successful walkthrough writes nothing to stderr. Duplicating the result
	// onto both streams would satisfy the stdout check above and quietly undo
	// the routing this change exists to establish.
	if stderr != "" {
		t.Errorf("successful quickstart wrote to stderr: %q", stderr)
	}
}

func TestQuickstartRejectsAnArgument(t *testing.T) {
	// quickstart takes no arguments. Without this, a reader who typed a stray
	// word would get the walkthrough and a success status, and never learn the
	// word did nothing.
	cmd := quickstartCmd()
	cmd.SetArgs([]string{"unexpected"})
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	if err := cmd.Execute(); err == nil {
		t.Error("quickstart accepted a positional argument instead of rejecting it")
	}
}

func TestQuickstartCommandLinesArePasteable(t *testing.T) {
	// The Windows lines once read `set HTTPS_PROXY=http://127.0.0.1:8888   (cmd)`.
	// cmd assigns everything after the equals sign, so that variable would have
	// held the URL, the padding, and the word (cmd), and the proxy address would
	// never have resolved. A label belongs on its own line, never appended to a
	// command someone is told to run.
	for _, goos := range []string{"linux", "darwin", "windows"} {
		t.Run(goos, func(t *testing.T) {
			for _, line := range strings.Split(quickstartText(t, goos), "\n") {
				trimmed := strings.TrimSpace(line)
				if !isCommandLine(trimmed) {
					continue
				}
				if i := strings.Index(trimmed, "("); i != -1 && strings.Contains(trimmed[i:], ")") {
					t.Errorf("%s: command line carries a parenthetical that would be run as part of it: %q",
						goos, trimmed)
				}
			}
		})
	}
}

// isCommandLine reports whether a walkthrough line is something the reader is
// meant to paste, as opposed to prose or a shell label.
func isCommandLine(trimmed string) bool {
	switch {
	case strings.HasPrefix(trimmed, "pipelock "),
		strings.HasPrefix(trimmed, "sudo pipelock "),
		strings.HasPrefix(trimmed, "export "),
		strings.HasPrefix(trimmed, "set "),
		strings.HasPrefix(trimmed, "$env:"):
		return true
	}
	return false
}

func TestQuickstartNamesNoUnixOnlyPathOnWindows(t *testing.T) {
	// The MCP example passed /tmp on every platform. A Windows reader cannot run
	// that, and the walkthrough claims to be written for their platform.
	win := quickstartText(t, "windows")
	for _, unixOnly := range []string{"/tmp", "/usr/", "/etc/", "/var/"} {
		if strings.Contains(win, unixOnly) {
			t.Errorf("windows walkthrough names %q, which does not exist there:\n%s", unixOnly, win)
		}
	}
}
