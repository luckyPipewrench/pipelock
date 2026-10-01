// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux && amd64

package sandbox

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/luckyPipewrench/pipelock/internal/testwait"
)

// These tests evaluate namespace-denial decisions without issuing privileged
// syscalls. The runtime tests below only start and join ordinary native threads.
func TestSeccomp_StrictCloneDecisions(t *testing.T) {
	strict := buildSeccompFilter(true)
	deny := uint32(unix.SECCOMP_RET_ERRNO | unix.EPERM)
	unavailable := uint32(unix.SECCOMP_RET_ERRNO | unix.ENOSYS)
	pthreadFlags := uint64(unix.CLONE_VM | unix.CLONE_FS | unix.CLONE_FILES |
		unix.CLONE_SIGHAND | unix.CLONE_THREAD | unix.CLONE_SYSVSEM |
		unix.CLONE_SETTLS | unix.CLONE_PARENT_SETTID | unix.CLONE_CHILD_CLEARTID)

	for _, args := range [][6]uint64{{}, {1, 64}, {^uint64(0), ^uint64(0)}} {
		if got := evaluateThreadFilter(t, strict, unix.SYS_CLONE3, args); got != unavailable {
			t.Fatalf("strict clone3(%v) = %#x, want ENOSYS (%#x)", args, got, unavailable)
		}
		if got := evaluateThreadFilter(t, buildSeccompFilter(false), unix.SYS_CLONE3, args); got != unix.SECCOMP_RET_ALLOW {
			t.Fatalf("non-strict clone3(%v) = %#x, want ALLOW", args, got)
		}
	}
	for _, flags := range []uint64{0, uint64(unix.SIGCHLD), pthreadFlags} {
		if got := evaluateThreadFilter(t, strict, unix.SYS_CLONE, [6]uint64{flags}); got != unix.SECCOMP_RET_ALLOW {
			t.Fatalf("ordinary clone flags %#x = %#x, want ALLOW", flags, got)
		}
	}
	for _, flag := range []uint64{
		unix.CLONE_NEWNS, unix.CLONE_NEWCGROUP, unix.CLONE_NEWUTS, unix.CLONE_NEWIPC,
		unix.CLONE_NEWUSER, unix.CLONE_NEWPID, unix.CLONE_NEWNET,
		unix.CLONE_NEWNS | unix.CLONE_NEWCGROUP | unix.CLONE_NEWUTS | unix.CLONE_NEWIPC |
			unix.CLONE_NEWUSER | unix.CLONE_NEWPID | unix.CLONE_NEWNET,
	} {
		for _, flags := range []uint64{flag, flag | pthreadFlags, flag | uint64(unix.SIGCHLD)} {
			if got := evaluateThreadFilter(t, strict, unix.SYS_CLONE, [6]uint64{flags}); got != deny {
				t.Fatalf("namespace clone flags %#x = %#x, want EPERM (%#x)", flags, got, deny)
			}
		}
	}
}

func TestSeccomp_ThreadCompatibilityOnlyChangesClone3Decision(t *testing.T) {
	strict, nonStrict := buildSeccompFilter(true), buildSeccompFilter(false)
	if len(strict) != len(nonStrict) {
		t.Fatalf("filter lengths differ: strict=%d non-strict=%d", len(strict), len(nonStrict))
	}
	differences := 0
	for i := range strict {
		if strict[i] == nonStrict[i] {
			continue
		}
		differences++
		if i == 0 || strict[i-1] != bpfJumpEq(unix.SYS_CLONE3, 0, 1) ||
			strict[i] != bpfRet(unix.SECCOMP_RET_ERRNO|uint32(unix.ENOSYS)) ||
			nonStrict[i] != bpfRet(unix.SECCOMP_RET_ALLOW) {
			t.Fatalf("unexpected strict/non-strict difference at instruction %d", i)
		}
	}
	if differences != 1 {
		t.Fatalf("filter differences = %d, want only clone3 action", differences)
	}

	// Exercise the whole filter, including default-denied and x32 syscall
	// numbers. This never issues any of these calls to the kernel.
	for nr := uint32(0); nr < 1024; nr++ {
		for _, number := range []uint32{nr, nr | 0x40000000} {
			if number == unix.SYS_CLONE3 {
				continue
			}
			for _, args := range [][6]uint64{{}, {^uint64(0), ^uint64(0)}} {
				got := evaluateThreadFilter(t, strict, number, args)
				want := evaluateThreadFilter(t, nonStrict, number, args)
				if got != want {
					t.Fatalf("syscall %d args %v differs: strict=%#x non-strict=%#x", number, args, got, want)
				}
			}
		}
	}
}

// evaluateThreadFilter supports exactly the forward-only instructions emitted
// by buildSeccompFilter. Invalid instructions and out-of-range jumps fail tests.
func evaluateThreadFilter(t *testing.T, prog []unix.SockFilter, nr uint32, args [6]uint64) uint32 {
	t.Helper()
	data := [16]uint32{nr, unix.AUDIT_ARCH_X86_64}
	for i, arg := range args {
		data[4+2*i], data[5+2*i] = uint32(arg&0xffffffff), uint32(arg>>32)
	}
	var accumulator uint32
	for pc := 0; pc < len(prog); pc++ {
		insn := prog[pc]
		switch insn.Code {
		case unix.BPF_LD | unix.BPF_W | unix.BPF_ABS:
			if insn.K%4 != 0 || insn.K/4 >= uint32(len(data)) {
				t.Fatalf("invalid filter load at instruction %d: %d", pc, insn.K)
			}
			accumulator = data[insn.K/4]
		case unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K:
			if accumulator == insn.K {
				pc += int(insn.Jt)
			} else {
				pc += int(insn.Jf)
			}
		case unix.BPF_JMP | unix.BPF_JSET | unix.BPF_K:
			if accumulator&insn.K != 0 {
				pc += int(insn.Jt)
			} else {
				pc += int(insn.Jf)
			}
		case unix.BPF_RET | unix.BPF_K:
			return insn.K
		default:
			t.Fatalf("unsupported filter instruction at %d: %#x", pc, insn.Code)
		}
	}
	t.Fatal("filter did not return a decision")
	return 0
}

const strictThreadHelperEnv = "__PIPELOCK_TEST_STRICT_THREAD_EXEC"

func TestSeccompStrictThreadHelper(t *testing.T) {
	if os.Getenv(strictThreadHelperEnv) != "1" {
		return
	}
	separator := slices.Index(os.Args, "--")
	if separator < 0 || separator+1 >= len(os.Args) {
		t.Fatal("missing native thread fixture")
	}
	// Keep an assertion failure in a native runtime from writing a core dump.
	if err := unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{}); err != nil {
		t.Fatalf("disable helper core dumps: %v", err)
	}
	// no_new_privs belongs to the calling OS thread. Keep this goroutine on
	// that thread through filter installation and exec; TSYNC cannot repair
	// migration before the installing thread's no_new_privs check. This
	// dedicated helper exits on failure, so never return the thread to Go.
	runtime.LockOSThread()
	if err := SetNoNewPrivs(); err != nil {
		t.Fatalf("no_new_privs: %v", err)
	}
	status, err := ApplySeccomp(true)
	if err != nil || !status.Active {
		t.Fatalf("strict seccomp: active=%v err=%v reason=%s", status.Active, err, status.Reason)
	}
	args := os.Args[separator+1:]
	if err := unix.Exec(args[0], args, []string{"PATH=/usr/bin:/bin", "LANG=C"}); err != nil {
		t.Fatalf("exec native thread fixture: %v", err)
	}
}

func TestSeccomp_StrictNativePthread(t *testing.T) {
	compiler, err := exec.LookPath("cc")
	if err != nil {
		t.Skip("cc is required for the native pthread regression")
	}
	binary := filepath.Join(t.TempDir(), "native-thread")
	ctx, cancel := context.WithTimeout(t.Context(), testwait.Deadline(seccompChildTimeout))
	defer cancel()
	cmd := exec.CommandContext(ctx, compiler, "-pthread", "-Wall", "-Wextra", "-Werror", "-o", binary, "testdata/native_thread.c")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("compile native pthread fixture: %v\n%s", err, out)
	}
	checkStrictNativeThread(t, binary, nil)
}

type nativeThreadNodeIdentity struct {
	ExecPath string `json:"execPath"`
	Version  string `json:"version"`
	Release  string `json:"release"`
}

const nativeThreadNodeQuery = "JSON.stringify({execPath:process.execPath,version:process.versions.node,release:process.release.name})"

// Discover using Node's own identity, then query the resolved native executable
// directly. A PATH entry can be a version-manager launcher, not Node itself.
// This is an identity check, not the browser harness's Node-version policy.
func resolveNativeThreadNode(ctx context.Context, candidate string, env []string, dir string) (nativeThreadNodeIdentity, error) {
	identity, err := queryNativeThreadNode(ctx, candidate, env, dir)
	if err != nil {
		return nativeThreadNodeIdentity{}, err
	}
	if identity.Release != "node" || identity.Version == "" || !filepath.IsAbs(identity.ExecPath) {
		return nativeThreadNodeIdentity{}, fmt.Errorf("Node reported an invalid native identity")
	}
	resolved, err := filepath.EvalSymlinks(identity.ExecPath)
	if err != nil {
		return nativeThreadNodeIdentity{}, fmt.Errorf("resolve Node execPath: %w", err)
	}
	file, err := os.Open(filepath.Clean(resolved))
	if err != nil {
		return nativeThreadNodeIdentity{}, fmt.Errorf("open Node execPath: %w", err)
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		return nativeThreadNodeIdentity{}, fmt.Errorf("Node execPath is not a regular executable")
	}
	var magic [4]byte
	if _, err := io.ReadFull(file, magic[:]); err != nil || string(magic[:]) != "\x7fELF" {
		return nativeThreadNodeIdentity{}, fmt.Errorf("Node execPath is not a native Linux executable")
	}
	identity.ExecPath = resolved
	confirmed, err := queryNativeThreadNode(ctx, resolved, env, dir)
	if err != nil {
		return nativeThreadNodeIdentity{}, fmt.Errorf("confirm native Node identity: %w", err)
	}
	if confirmed != identity {
		return nativeThreadNodeIdentity{}, fmt.Errorf("native Node identity differs from launcher report")
	}
	return identity, nil
}

// Bound output as well as execution time. A broken launcher must not fill the
// test process's memory or leave pipe-copy goroutines waiting indefinitely.
type nativeThreadIdentityOutput struct {
	buffer   bytes.Buffer
	overflow bool
}

func (out *nativeThreadIdentityOutput) Write(p []byte) (int, error) {
	const limit = 4096
	size := len(p)
	if remaining := limit - out.buffer.Len(); len(p) > remaining {
		out.overflow = true
		p = p[:remaining]
	}
	_, _ = out.buffer.Write(p)
	return size, nil
}

func queryNativeThreadNode(ctx context.Context, candidate string, env []string, dir string) (nativeThreadNodeIdentity, error) {
	ctx, cancel := context.WithTimeout(ctx, testwait.Deadline(5*time.Second))
	defer cancel()
	cmd := exec.CommandContext(ctx, candidate, "-p", nativeThreadNodeQuery)
	cmd.Env, cmd.Dir, cmd.WaitDelay = env, dir, time.Second
	var out nativeThreadIdentityOutput
	cmd.Stdout, cmd.Stderr = &out, io.Discard
	if err := cmd.Run(); err != nil {
		return nativeThreadNodeIdentity{}, fmt.Errorf("Node identity query unavailable: %w", err)
	}
	if out.overflow {
		return nativeThreadNodeIdentity{}, fmt.Errorf("Node identity output exceeds 4096 bytes")
	}
	var identity nativeThreadNodeIdentity
	if err := json.Unmarshal(out.buffer.Bytes(), &identity); err != nil {
		return nativeThreadNodeIdentity{}, fmt.Errorf("Node identity output is not valid JSON: %w", err)
	}
	return identity, nil
}

func nativeThreadDiscoveryEnvironment(t *testing.T) ([]string, string) {
	t.Helper()
	dir := t.TempDir()
	env := []string{"PATH=/usr/bin:/bin", "LANG=C"}
	for _, key := range []string{"HOME", "TMPDIR", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME", "XDG_CACHE_HOME"} {
		env = append(env, key+"="+dir)
	}
	return env, dir
}

func requireNativeThreadNode(t *testing.T) nativeThreadNodeIdentity {
	t.Helper()
	candidate, err := exec.LookPath("node")
	if err != nil {
		t.Skip("native Node unavailable before seccomp: node is not on PATH")
	}
	env, dir := nativeThreadDiscoveryEnvironment(t)
	identity, err := resolveNativeThreadNode(t.Context(), candidate, env, dir)
	if err != nil {
		t.Skipf("native Node unavailable before seccomp: %v; put the native executable on PATH", err)
	}
	return identity
}

func TestSeccomp_StrictNodeWorker(t *testing.T) {
	checkStrictNodeWorker(t, requireNativeThreadNode(t))
}

func TestSeccomp_StrictNodeWorkerViaShim(t *testing.T) {
	native := requireNativeThreadNode(t)
	env, dir := nativeThreadDiscoveryEnvironment(t)
	calls := filepath.Join(dir, "shim-calls")
	shim := filepath.Join(dir, "node-shim")
	// Shell quoting makes this fixture independent of spaces or quotes in the
	// resolved runtime path. The shim records every invocation before exec.
	quote := func(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'" }
	script := "#!/bin/sh\nprintf 'called\\n' >> " + quote(calls) + "\nexec " + quote(native.ExecPath) + " \"$@\"\n"
	if err := os.WriteFile(shim, []byte(script), 0o750); err != nil {
		t.Fatalf("write Node launcher fixture: %v", err)
	}
	resolved, err := resolveNativeThreadNode(t.Context(), shim, env, dir)
	if err != nil {
		t.Fatalf("resolve Node through launcher: %v", err)
	}
	if resolved != native {
		t.Fatalf("launcher resolved %+v, want %+v", resolved, native)
	}
	checkStrictNodeWorker(t, resolved)
	out, err := os.ReadFile(filepath.Clean(calls))
	if err != nil || string(out) != "called\n" {
		t.Fatalf("launcher must run only for discovery: calls=%q err=%v", out, err)
	}
}

func TestSeccomp_NodeResolutionUnavailable(t *testing.T) {
	for _, tc := range []struct{ name, want string }{
		{"missing", "Node identity query unavailable"},
		{"invalid_json", "not valid JSON"},
		{"non_native", "not a native Linux executable"},
		{"oversized", "exceeds 4096 bytes"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env, dir := nativeThreadDiscoveryEnvironment(t)
			candidate := filepath.Join(dir, "node-fixture")
			var script string
			switch tc.name {
			case "invalid_json":
				script = "#!/bin/sh\nprintf 'invalid\\n'\n"
			case "non_native":
				identity, err := json.Marshal(nativeThreadNodeIdentity{ExecPath: candidate, Version: "1.0.0", Release: "node"})
				if err != nil {
					t.Fatal(err)
				}
				script = "#!/bin/sh\ncat <<'IDENTITY'\n" + string(identity) + "\nIDENTITY\n"
			case "oversized":
				script = "#!/bin/sh\nprintf '%5000s' x\n"
			}
			if script != "" {
				if err := os.WriteFile(candidate, []byte(script), 0o750); err != nil {
					t.Fatalf("write unavailable Node fixture: %v", err)
				}
			}
			if _, err := resolveNativeThreadNode(t.Context(), candidate, env, dir); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("native Node unavailability = %v, want %q before filter installation", err, tc.want)
			}
		})
	}
}

func checkStrictNodeWorker(t *testing.T, identity nativeThreadNodeIdentity) {
	t.Helper()
	encoded, err := json.Marshal(identity)
	if err != nil {
		t.Fatal(err)
	}
	// Both baseline and filtered processes must report the same native runtime
	// identity before their thread result can count as a successful regression.
	// Startup alone needs native threads; Worker proves creation after startup.
	const script = `const expected = JSON.parse(process.argv[1]);
if (process.execPath !== expected.execPath || process.versions.node !== expected.version || process.release.name !== expected.release) {
  console.error('native Node identity mismatch');
  process.exit(1);
}
const { Worker } = require('node:worker_threads');
const worker = new Worker("require('node:worker_threads').parentPort.postMessage(42)", { eval: true });
let received = false;
worker.on('message', value => { received = value === 42; });
worker.on('error', () => { process.exitCode = 1; });
worker.on('exit', code => {
  if (code === 0 && received) console.log('thread-ok');
  else process.exitCode = 1;
});`
	checkStrictNativeThread(t, identity.ExecPath, []string{"-e", script, string(encoded)})
}

func checkStrictNativeThread(t *testing.T, binary string, args []string) {
	t.Helper()
	for _, strict := range []bool{false, true} {
		name := "native_baseline"
		if strict {
			name = "strict_seccomp"
		}
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), testwait.Deadline(seccompChildTimeout))
			defer cancel()
			cmd := exec.CommandContext(ctx, binary, args...)
			cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C"}
			if strict {
				helperArgs := append([]string{"-test.run=^TestSeccompStrictThreadHelper$", "--", binary}, args...)
				cmd = exec.CommandContext(ctx, "/proc/self/exe", helperArgs...)
				cmd.Env = []string{strictThreadHelperEnv + "=1"}
			}
			out, err := cmd.CombinedOutput()
			if err != nil || strings.TrimSpace(string(out)) != "thread-ok" {
				t.Fatalf("native thread fixture: %v (deadline: %v)\n%s", err, ctx.Err(), out)
			}
		})
	}
}
