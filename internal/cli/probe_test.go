package cli

import (
	"os"
	"strings"
	"testing"
)

// Temporary probe: does the re-executed child inherit the isolated
// XDG_DATA_HOME that TestMain set in the parent, or does it read the
// developer's real one? Deleted once answered.
func TestProbeChildInheritsIsolation(t *testing.T) {
	parent := os.Getenv("XDG_DATA_HOME")
	t.Logf("parent XDG_DATA_HOME = %q", parent)
	if parent == "" || !strings.Contains(parent, "pipelock-cli-test-xdg") {
		t.Fatalf("parent isolation not set as expected: %q", parent)
	}
	// The child prints its own view of the variable through a command that
	// reads it. rules list resolves its directory from XDG_DATA_HOME.
	stdout, stderr, code := runCLI(t, "rules", "list", "--json")
	t.Logf("child rules list: code=%d stdout=%.200q stderr=%.200q", code, stdout, stderr)
}
