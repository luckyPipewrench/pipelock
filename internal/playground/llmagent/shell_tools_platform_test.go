// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package llmagent

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunCommandConfiguration(t *testing.T) {
	t.Run("supported", func(t *testing.T) {
		result, event, ok := runCommandConfiguration(&exec.Cmd{}, func(*exec.Cmd) error { return nil })
		if !ok || result != "" || event != (Event{}) {
			t.Fatalf("result = %q, event = %+v, ok = %v", result, event, ok)
		}
	})

	t.Run("unsupported", func(t *testing.T) {
		result, event, ok := runCommandConfiguration(&exec.Cmd{}, func(*exec.Cmd) error {
			return errRunCommandUnsupported
		})
		if ok {
			t.Fatal("unsupported configuration reported success")
		}
		if !strings.Contains(result, errRunCommandUnsupported.Error()) {
			t.Fatalf("result = %q, want unsupported-platform error", result)
		}
		if event.Note != "unsupported platform" {
			t.Fatalf("event note = %q, want unsupported platform", event.Note)
		}
	})
}

func TestShellTools_RunCommandPlatformGate(t *testing.T) {
	tools := shellTools(t.TempDir(), true, 0)
	offered := false
	for _, tool := range tools {
		if tool.Name == ToolRunCommand {
			offered = true
			break
		}
	}
	if offered != runCommandSupported {
		t.Fatalf("run_command offered = %v, platform support = %v", offered, runCommandSupported)
	}
}

func TestRunCommandInvoke_UnsupportedPlatform(t *testing.T) {
	scratch := t.TempDir()
	witness := filepath.Join(scratch, "command-ran")
	command := fmt.Sprintf("printf ran > %q", witness)
	raw, err := json.Marshal(map[string]string{"command": command})
	if err != nil {
		t.Fatalf("marshal command: %v", err)
	}
	result, event := runCommandInvokeWithConfigure(
		context.Background(),
		scratch,
		0,
		raw,
		func(*exec.Cmd) error { return errRunCommandUnsupported },
	)
	if !strings.Contains(result, errRunCommandUnsupported.Error()) {
		t.Fatalf("result = %q, want unsupported-platform error", result)
	}
	if event.Note != "unsupported platform" {
		t.Fatalf("event note = %q, want unsupported platform", event.Note)
	}
	if _, err := os.Stat(witness); !os.IsNotExist(err) {
		t.Fatalf("unsupported command executed: stat error = %v", err)
	}
}
