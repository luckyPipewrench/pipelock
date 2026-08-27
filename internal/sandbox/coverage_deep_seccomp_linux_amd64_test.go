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

import (
	"testing"

	"golang.org/x/sys/unix"
)

// ---------------------------------------------------------------------------
// buildSeccompFilter: verify filter properties.
// ---------------------------------------------------------------------------

func TestBuildSeccompFilter_ArchitectureGuardAndPrologue(t *testing.T) {
	// An instruction COUNT proves nothing about a filter. A regression that
	// removed the wrong-architecture kill, or turned it into an allow, would keep
	// the same length and pass. The architecture guard is what stops a 32-bit or
	// x32 syscall ABI from being interpreted against x86-64 syscall numbers, so a
	// silent change there re-opens every number-based rule below it.
	for _, strict := range []bool{false, true} {
		name := "best_effort"
		if strict {
			name = "strict"
		}
		t.Run(name, func(t *testing.T) {
			prog := buildSeccompFilter(strict)
			if len(prog) < 4 {
				t.Fatalf("filter has %d instructions, want at least the four-instruction prologue", len(prog))
			}
			want := []unix.SockFilter{
				bpfLoad(offsetArch),
				bpfJumpEq(unix.AUDIT_ARCH_X86_64, 1, 0),
				bpfRet(unix.SECCOMP_RET_KILL_PROCESS),
				bpfLoad(offsetNR),
			}
			for idx, expected := range want {
				if prog[idx] != expected {
					t.Errorf("instruction %d = %+v, want %+v", idx, prog[idx], expected)
				}
			}
			// Stated explicitly because it is the property that matters rather than
			// a consequence of the comparison above: a matching architecture skips
			// one instruction to reach the syscall load, and any other architecture
			// falls through to a kill rather than a permissive return.
			if prog[2].Code != unix.BPF_RET|unix.BPF_K || prog[2].K != unix.SECCOMP_RET_KILL_PROCESS {
				t.Errorf("wrong-architecture action = %+v, want a kill return", prog[2])
			}
		})
	}
}

// ---------------------------------------------------------------------------
// seccomp conditionals: verify the decision each branch encodes.
// ---------------------------------------------------------------------------

func TestSeccompConditionals_EncodeTheIntendedDecision(t *testing.T) {
	deny := bpfRet(unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM))
	allow := bpfRet(unix.SECCOMP_RET_ALLOW)

	// Lengths are still asserted, because the surrounding filter's jump offsets
	// are computed from them, but every case also pins the ACTION its branch
	// takes. The strict and best-effort clone3 pair is the clearest example of
	// why: both are two instructions, and the only difference between blocking
	// clone3 and permitting it is which return the second instruction is.
	t.Run("clone_denies_new_namespaces_and_allows_the_rest", func(t *testing.T) {
		insns := cloneConditional()
		if len(insns) != 5 {
			t.Fatalf("clone conditional = %d instructions, want 5", len(insns))
		}
		if insns[0] != bpfJumpEq(unix.SYS_CLONE, 0, 4) {
			t.Errorf("clone guard = %+v, want a jump that skips the block for other syscalls", insns[0])
		}
		if insns[1] != bpfLoad(offsetArgs0) {
			t.Errorf("clone flag load = %+v, want the first argument", insns[1])
		}
		if insns[2] != bpfJumpSet(cloneNewMask, 0, 1) {
			t.Errorf("namespace test = %+v, want a CLONE_NEW mask test falling through to deny", insns[2])
		}
		if insns[3] != deny {
			t.Errorf("namespace-creation action = %+v, want EPERM", insns[3])
		}
		if insns[4] != allow {
			t.Errorf("plain-clone action = %+v, want allow", insns[4])
		}
	})

	t.Run("clone3_strict_denies_and_best_effort_allows", func(t *testing.T) {
		strict := clone3Conditional(true)
		bestEffort := clone3Conditional(false)
		if len(strict) != 2 || len(bestEffort) != 2 {
			t.Fatalf("clone3 conditionals = %d and %d instructions, want 2 each", len(strict), len(bestEffort))
		}
		if strict[1] != deny {
			t.Errorf("strict clone3 action = %+v, want EPERM", strict[1])
		}
		if bestEffort[1] != allow {
			t.Errorf("best-effort clone3 action = %+v, want allow", bestEffort[1])
		}
		if strict[1] == bestEffort[1] {
			t.Error("strict and best-effort clone3 encode the same action, so strict mode is not stricter")
		}
	})

	t.Run("socket_and_personality_keep_their_deny_branch", func(t *testing.T) {
		for name, insns := range map[string][]unix.SockFilter{
			"socket":      socketConditional(),
			"personality": personalityConditional(),
		} {
			denies := 0
			for _, insn := range insns {
				if insn == deny {
					denies++
				}
			}
			if denies == 0 {
				t.Errorf("%s conditional encodes no EPERM branch, so its restriction is gone: %+v", name, insns)
			}
		}
		if got := len(socketConditional()); got != 5 {
			t.Errorf("socket conditional = %d instructions, want 5", got)
		}
		if got := len(personalityConditional()); got != 9 {
			t.Errorf("personality conditional = %d instructions, want 9", got)
		}
	})
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
	// Every field is asserted, not just K. An opcode or a false-branch offset is
	// as load-bearing as the constant: a helper emitting the wrong Code produces a
	// filter the kernel interprets differently, and a wrong Jf sends the
	// no-match case to the wrong instruction, which is how a deny becomes a
	// fall-through.
	tests := []struct {
		name string
		got  unix.SockFilter
		want unix.SockFilter
	}{
		{
			name: "bpfLoad",
			got:  bpfLoad(42),
			want: unix.SockFilter{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 42},
		},
		{
			name: "bpfJumpEq",
			got:  bpfJumpEq(100, 2, 3),
			want: unix.SockFilter{Code: unix.BPF_JMP | 0x10 | unix.BPF_K, K: 100, Jt: 2, Jf: 3},
		},
		{
			name: "bpfRet",
			got:  bpfRet(0x7FFF0001),
			want: unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K, K: 0x7FFF0001},
		},
		{
			name: "bpfJumpSet",
			got:  bpfJumpSet(0xFF, 1, 0),
			want: unix.SockFilter{Code: unix.BPF_JMP | 0x40 | unix.BPF_K, K: 0xFF, Jt: 1, Jf: 0},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Errorf("%s = %+v, want %+v", tt.name, tt.got, tt.want)
			}
		})
	}
}
