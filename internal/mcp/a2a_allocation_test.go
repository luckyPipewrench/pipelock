//go:build !race

// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
)

// Race instrumentation changes regexp pool allocation; the byte budget is
// measured on the production build. Path limits are tested in both builds.
func TestA2AWalkBoundedPathAllocation(t *testing.T) {
	// TotalAlloc is process-wide; isolate the measurement from background
	// work started by other package tests without relaxing the allocation bound.
	const allocationCheckEnv = "PIPELOCK_TEST_A2A_PATH_ALLOCATION"
	if os.Getenv(allocationCheckEnv) != "1" {
		binary, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		cmd := exec.CommandContext(t.Context(), binary, "-test.run=^TestA2AWalkBoundedPathAllocation$", "-test.v", "-test.timeout=30s") // #nosec G204 -- re-executes this test binary with fixed arguments
		cmd.Env = append(os.Environ(), allocationCheckEnv+"=1")
		output, err := cmd.CombinedOutput()
		t.Logf("%s", output)
		if err != nil {
			t.Fatalf("isolated allocation check: %v", err)
		}
		return
	}
	key := strings.Repeat("k", 16000)
	body := `{"items":[` + strings.Repeat(`"hello",`, 3999) + `"hello"]}`
	for range 60 {
		body = fmt.Sprintf(`{%q:%s}`, key, body)
	}
	raw := json.RawMessage(body)
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	longest, leaves := 0, 0
	WalkA2AJSON(raw, func(path, _ string, class FieldClass) {
		longest = max(longest, len(path))
		if class == FieldOpaque {
			leaves++
		}
	})
	runtime.ReadMemStats(&after)
	allocated := after.TotalAlloc - before.TotalAlloc
	t.Logf("body=%d allocated=%d ratio=%.2f max_path=%d leaves=%d", len(raw), allocated, float64(allocated)/float64(len(raw)), longest, leaves)
	if allocated > uint64(len(raw))*16 || longest > 512 || leaves != 4000 {
		t.Fatalf("path allocation must be bounded: bytes=%d body=%d max_path=%d leaves=%d", allocated, len(raw), longest, leaves)
	}
}
