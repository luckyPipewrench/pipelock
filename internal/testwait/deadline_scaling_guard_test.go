// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package testwait

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestDeadlineScalingGuard(t *testing.T) {
	tests := []struct {
		name     string
		source   string
		mutate   func(t *testing.T, root string)
		wantPass bool
		wantText string
	}{
		{
			// The duration is concatenated rather than written inline: this file is
			// itself a tracked _test.go containing exec.CommandContext, so a
			// contiguous violating line would make the guard flag its own fixture.
			// Splitting it keeps the scan universal instead of needing a
			// file exclusion that real code could later hide behind.
			name: "rejects raw subprocess deadline",
			source: `package fixture

import (
	"context"
	"os/exec"
	"time"
)

func test() {
	ctx, cancel := context.WithTimeout(context.Background(), ` + "time.Second" + `)
	defer cancel()
	_ = exec.CommandContext(ctx, "true")
}
`,
			wantText: "Unscaled deadline",
		},
		{
			name: "allows scaled subprocess deadline",
			source: `package fixture

import (
	"context"
	"os/exec"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/testwait"
)

func test() {
	ctx, cancel := context.WithTimeout(context.Background(), testwait.Deadline(time.Second))
	defer cancel()
	_ = exec.CommandContext(ctx, "true")
}
`,
			wantPass: true,
		},
		{
			// The line filter this replaced dropped any line MENTIONING the
			// helper, so naming it in a trailing comment was enough to hide a
			// raw deadline. The helper call itself never matched the detector,
			// which is why the filter bought nothing and cost this.
			name: "rejects raw deadline carrying the helper name in a comment",
			source: `package fixture

import (
	"context"
	"os/exec"
	"time"
)

func test() {
	ctx, cancel := context.WithTimeout(context.Background(), ` + "time.Second" + `) // testwait.Deadline
	defer cancel()
	_ = exec.CommandContext(ctx, "true")
}
`,
			wantText: "Unscaled deadline",
		},
		{
			name:     "rejects empty tracked test set",
			wantText: "no tracked internal test files",
		},
		{
			name: "rejects unreadable tracked path",
			source: `package fixture

import "os/exec"

func test() { _ = exec.CommandContext }
`,
			mutate: func(t *testing.T, root string) {
				t.Helper()
				if err := os.Remove(filepath.Join(root, "internal", "fixture", "fixture_test.go")); err != nil {
					t.Fatalf("remove tracked fixture: %v", err)
				}
			},
			wantText: "cannot read tracked test file",
		},
		{
			name: "rejects invalid git index",
			source: `package fixture

import "os/exec"

func test() { _ = exec.CommandContext }
`,
			mutate: func(t *testing.T, root string) {
				t.Helper()
				index := filepath.Join(root, "invalid-index")
				if err := os.WriteFile(index, []byte("not an index\n"), 0o600); err != nil {
					t.Fatalf("write invalid index: %v", err)
				}
				t.Setenv("GIT_INDEX_FILE", index)
			},
			wantText: "could not enumerate tracked test files",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := newDeadlineScalingGuardFixture(t, tt.source)
			if tt.mutate != nil {
				tt.mutate(t, root)
			}

			// #nosec G204 -- the path is built from t.TempDir() and a fixed name.
			cmd := exec.CommandContext(t.Context(), "bash", filepath.Join(root, "scripts", "check-test-deadline-scaling.sh"))
			cmd.Dir = root
			cmd.Env = os.Environ()
			var output bytes.Buffer
			cmd.Stdout = &output
			cmd.Stderr = &output
			err := cmd.Run()
			if (err == nil) != tt.wantPass {
				t.Fatalf("guard error = %v, want pass = %t\n%s", err, tt.wantPass, output.String())
			}
			if tt.wantText != "" && !strings.Contains(output.String(), tt.wantText) {
				t.Fatalf("guard output = %q, want %q", output.String(), tt.wantText)
			}
		})
	}
}

func newDeadlineScalingGuardFixture(t *testing.T, source string) string {
	t.Helper()
	root := t.TempDir()
	for _, dir := range []string{"internal", "internal/fixture", "scripts"} {
		if err := os.Mkdir(filepath.Join(root, dir), 0o750); err != nil {
			t.Fatalf("mkdir %s: %v", dir, err)
		}
	}

	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate deadline scaling guard test")
	}
	script, err := os.ReadFile(filepath.Join(filepath.Dir(thisFile), "..", "..", "scripts", "check-test-deadline-scaling.sh"))
	if err != nil {
		t.Fatalf("read deadline scaling guard: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "scripts", "check-test-deadline-scaling.sh"), script, 0o600); err != nil {
		t.Fatalf("write deadline scaling guard: %v", err)
	}
	if source != "" {
		if err := os.WriteFile(filepath.Join(root, "internal", "fixture", "fixture_test.go"), []byte(source), 0o600); err != nil {
			t.Fatalf("write fixture: %v", err)
		}
	}

	init := exec.CommandContext(t.Context(), "git", "init", "--quiet")
	init.Dir = root
	if output, err := init.CombinedOutput(); err != nil {
		t.Fatalf("init fixture repository: %v\n%s", err, output)
	}
	add := exec.CommandContext(t.Context(), "git", "add", "scripts/check-test-deadline-scaling.sh", "internal")
	add.Dir = root
	if output, err := add.CombinedOutput(); err != nil {
		t.Fatalf("track fixture files: %v\n%s", err, output)
	}
	return root
}
