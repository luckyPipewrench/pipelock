package testwait

import (
	"testing"
	"time"
)

// TestScaleDeadline pins the four states the scaling can be in. Without this the
// factor is a number nobody checks: a typo that made it 1 would silently restore
// the flaky behavior, and one that made it enormous would turn a real hang into a
// package timeout with no useful failure.
func TestScaleDeadline(t *testing.T) {
	base := 10 * time.Second
	t.Setenv("CI", "")
	t.Setenv("PIPELOCK_TEST_DEADLINE_SCALE", "")
	if got := scaleDeadline(base); got != base {
		t.Errorf("local: got %v want %v", got, base)
	}
	t.Setenv("CI", "true")
	if got := scaleDeadline(base); got != 40*time.Second {
		t.Errorf("ci: got %v want 40s", got)
	}
	t.Setenv("PIPELOCK_TEST_DEADLINE_SCALE", "1")
	if got := scaleDeadline(base); got != base {
		t.Errorf("pinned to 1: got %v want %v", got, base)
	}
	// A pin must beat CI, so a bisect can reproduce the original timing on a
	// runner rather than only on a laptop.
	t.Setenv("PIPELOCK_TEST_DEADLINE_SCALE", "bogus")
	if got := scaleDeadline(base); got != 40*time.Second {
		t.Errorf("bad override should fall through to CI: got %v", got)
	}
}
