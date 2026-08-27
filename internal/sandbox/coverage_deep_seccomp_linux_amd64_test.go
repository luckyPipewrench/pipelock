// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux && amd64

// These tests exercise the seccomp filter builder and its syscall lists, which
// exist only in seccomp_linux.go under linux && amd64. They lived in
// coverage_deep_test.go, tagged plain linux, so the whole sandbox test package
// failed to COMPILE on linux/arm64 and that architecture had no sandbox test
// coverage at all. `go build ./...` cannot catch that, because it never builds
// test files, which is why a native arm64 lane found it and cross-compilation
// did not. Same shape as the internal/config Mkfifo break on Windows.

package sandbox

import "testing"

// ---------------------------------------------------------------------------
// buildSeccompFilter: verify filter properties.
// ---------------------------------------------------------------------------

func TestBuildSeccompFilter_BestEffortAndStrict(t *testing.T) {
	bestEffort := buildSeccompFilter(false)
	strict := buildSeccompFilter(true)

	const minInstructions = 4
	if len(bestEffort) < minInstructions {
		t.Errorf("best-effort filter too short: %d instructions", len(bestEffort))
	}
	if len(strict) < minInstructions {
		t.Errorf("strict filter too short: %d instructions", len(strict))
	}

	t.Logf("best-effort: %d instructions, strict: %d instructions", len(bestEffort), len(strict))
}

// ---------------------------------------------------------------------------
// seccomp conditionals: verify instruction counts.
// ---------------------------------------------------------------------------

func TestSeccompConditionals_InstructionCounts(t *testing.T) {
	cloneInsns := cloneConditional()
	clone3Strict := clone3Conditional(true)
	clone3BestEff := clone3Conditional(false)
	socketInsns := socketConditional()
	personalityInsns := personalityConditional()

	tests := []struct {
		name  string
		count int
		got   int
	}{
		{name: "clone", count: 5, got: len(cloneInsns)},
		{name: "clone3_strict", count: 2, got: len(clone3Strict)},
		{name: "clone3_besteff", count: 2, got: len(clone3BestEff)},
		{name: "socket", count: 5, got: len(socketInsns)},
		{name: "personality", count: 9, got: len(personalityInsns)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.count {
				t.Errorf("%s: got %d instructions, want %d", tt.name, tt.got, tt.count)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// allowedSyscalls / killSyscalls / denySyscalls: no dups, no overlap.
// ---------------------------------------------------------------------------

func TestSyscallLists_NoDuplicates(t *testing.T) {
	lists := map[string][]uint32{
		"allowed": allowedSyscalls(),
		"kill":    killSyscalls(),
		"deny":    denySyscalls(),
	}

	for name, list := range lists {
		t.Run(name, func(t *testing.T) {
			if len(list) == 0 {
				t.Errorf("%s syscall list is empty", name)
			}
			seen := make(map[uint32]bool, len(list))
			for _, nr := range list {
				if seen[nr] {
					t.Errorf("%s: duplicate syscall number %d", name, nr)
				}
				seen[nr] = true
			}
		})
	}
}

func TestSyscallLists_NoOverlap(t *testing.T) {
	allow := make(map[uint32]bool)
	for _, nr := range allowedSyscalls() {
		allow[nr] = true
	}
	kill := make(map[uint32]bool)

	for _, nr := range killSyscalls() {
		if allow[nr] {
			t.Errorf("syscall %d is in both allowed and kill lists", nr)
		}
		kill[nr] = true
	}
	for _, nr := range denySyscalls() {
		if allow[nr] {
			t.Errorf("syscall %d is in both allowed and deny lists", nr)
		}
		if kill[nr] {
			t.Errorf("syscall %d is in both kill and deny lists", nr)
		}
	}
}

// ---------------------------------------------------------------------------
// BPF helpers: verify instruction codes.
// ---------------------------------------------------------------------------

func TestBPFHelpers(t *testing.T) {
	t.Run("bpfLoad", func(t *testing.T) {
		insn := bpfLoad(42)
		if insn.K != 42 {
			t.Errorf("K = %d, want 42", insn.K)
		}
	})

	t.Run("bpfJumpEq", func(t *testing.T) {
		insn := bpfJumpEq(100, 2, 3)
		if insn.K != 100 {
			t.Errorf("K = %d, want 100", insn.K)
		}
		if insn.Jt != 2 {
			t.Errorf("Jt = %d, want 2", insn.Jt)
		}
		if insn.Jf != 3 {
			t.Errorf("Jf = %d, want 3", insn.Jf)
		}
	})

	t.Run("bpfRet", func(t *testing.T) {
		insn := bpfRet(0x7FFF0001)
		if insn.K != 0x7FFF0001 {
			t.Errorf("K = %d, want %d", insn.K, 0x7FFF0001)
		}
	})

	t.Run("bpfJumpSet", func(t *testing.T) {
		insn := bpfJumpSet(0xFF, 1, 0)
		if insn.K != 0xFF {
			t.Errorf("K = %d, want 255", insn.K)
		}
		if insn.Jt != 1 {
			t.Errorf("Jt = %d, want 1", insn.Jt)
		}
	})
}
