// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux && amd64

package sandbox

import (
	"bytes"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

func TestTargetUnixSocketFilter(t *testing.T) {
	deny := uint32(unix.SECCOMP_RET_ERRNO | unix.EPERM)
	for _, tc := range []struct {
		name string
		nr   uint32
		arg  uint64
		typ  uint64
		want uint32
	}{
		{"pathname or abstract socket", unix.SYS_SOCKET, unix.AF_UNIX, unix.SOCK_STREAM, deny},
		{"redirectable pair", unix.SYS_SOCKETPAIR, unix.AF_UNIX, unix.SOCK_DGRAM, deny},
		{"stream pair", unix.SYS_SOCKETPAIR, unix.AF_UNIX, unix.SOCK_STREAM, unix.SECCOMP_RET_ALLOW},
		{"sequenced pair", unix.SYS_SOCKETPAIR, unix.AF_UNIX, unix.SOCK_SEQPACKET, unix.SECCOMP_RET_ALLOW},
		{"flagged stream pair", unix.SYS_SOCKETPAIR, unix.AF_UNIX, unix.SOCK_STREAM | unix.SOCK_CLOEXEC | unix.SOCK_NONBLOCK, unix.SECCOMP_RET_ALLOW},
		{"flagged datagram pair", unix.SYS_SOCKETPAIR, unix.AF_UNIX, unix.SOCK_DGRAM | unix.SOCK_CLOEXEC, deny},
		{"unknown pair type", unix.SYS_SOCKETPAIR, unix.AF_UNIX, 15, deny},
		{"ancillary descriptors", unix.SYS_RECVMSG, 0, 0, deny},
		{"batched ancillary descriptors", unix.SYS_RECVMMSG, 0, 0, deny},
		{"x32 socket", 0x40000000 | unix.SYS_SOCKET, unix.AF_UNIX, 0, deny},
		{"TCP bridge", unix.SYS_SOCKET, unix.AF_INET, 0, unix.SECCOMP_RET_ALLOW},
		{"IPv6", unix.SYS_SOCKET, unix.AF_INET6, 0, unix.SECCOMP_RET_ALLOW},
		{"pipe", unix.SYS_PIPE2, 0, 0, unix.SECCOMP_RET_ALLOW},
		{"read", unix.SYS_READ, 0, 0, unix.SECCOMP_RET_ALLOW},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := evaluateThreadFilter(t, targetUnixSocketFilter(), tc.nr, [6]uint64{tc.arg, tc.typ}); got != tc.want {
				t.Fatalf("action %#x, want %#x", got, tc.want)
			}
		})
	}
}

func TestTargetUnixSocketFallbackNodeSpawn(t *testing.T) {
	if !Detect().Seccomp {
		t.Skip("kernel lacks seccomp support")
	}
	// A version-manager shim may try installing into the empty discovery
	// home. Prefer a verified system runtime when present, then use the
	// existing native-identity discovery for CI-managed PATH installations.
	env, dir := nativeThreadDiscoveryEnvironment(t)
	env = append(env, "MISE_OFFLINE=true", "MISE_NO_HOOKS=true")
	node, err := resolveNativeThreadNode(t.Context(), "/usr/bin/node", env, dir)
	if err != nil {
		candidate, lookupErr := exec.LookPath("node")
		if lookupErr != nil {
			t.Skip("native Node unavailable for subprocess stdio probe")
		}
		node, err = resolveNativeThreadNode(t.Context(), candidate, env, dir)
		if err != nil {
			t.Skipf("native Node unavailable before seccomp without installing tools: %v", err)
		}
	}
	const probe = `const assert = require('node:assert/strict');
const {spawnSync} = require('node:child_process');
const child = spawnSync(process.execPath, ['-e', 'process.stdout.write("spawned")']);
assert.equal(child.error, undefined);
assert.equal(child.status, 0);
assert.equal(child.stdout.toString(), 'spawned');
console.log('Node spawn with piped stdio works');`
	cmd := exec.CommandContext(t.Context(), node.ExecPath, "-e", probe) // #nosec G204 -- native Node identity is verified before launch; fixed probe.
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := startSandboxTarget(cmd, LayerStatus{Active: true, Version: 8}); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("Node spawn under fallback: %v: %s", err, out.String())
	}
	t.Logf("native Node %s: %s", node.Version, out.String())
}

// mise's native Rust runtime uses Tokio's UnixStream signal self-pipe. This
// exercises that real runtime without adding Rust dependencies to the project.
func TestTargetUnixSocketFallbackTokioRuntime(t *testing.T) {
	if !Detect().Seccomp {
		t.Skip("kernel lacks seccomp support")
	}
	mise, err := exec.LookPath("mise")
	if err != nil {
		t.Skip("mise unavailable for the native Rust/Tokio signal runtime probe")
	}
	cmd := exec.CommandContext(t.Context(), mise, "--no-config", "exec", "--", "/usr/bin/true") // #nosec G204 -- installed runtime and fixed harmless command.
	cmd.Env, cmd.Dir = nativeThreadDiscoveryEnvironment(t)
	cmd.Env = append(cmd.Env, "MISE_OFFLINE=true")
	baseline := exec.CommandContext(t.Context(), mise, "--no-config", "exec", "--", "/usr/bin/true") // #nosec G204 -- same fixed runtime probe before installing a filter.
	baseline.Env, baseline.Dir = cmd.Env, cmd.Dir
	if out, err := baseline.CombinedOutput(); err != nil {
		t.Skipf("configuration-free Rust/Tokio runtime unavailable before seccomp: %v: %s", err, out)
	}
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := startSandboxTarget(cmd, LayerStatus{Active: true, Version: 8}); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("Rust/Tokio signal runtime under fallback: %v: %s", err, out.String())
	}
	t.Log("native Rust/Tokio command completed under fallback")
}

func TestTargetUnixSocketInstallationFailure(t *testing.T) {
	if !Detect().Seccomp {
		t.Skip("kernel lacks seccomp support")
	}
	const helperEnv = "__PIPELOCK_TEST_IPC_FILTER_FAILURE"
	if denied := os.Getenv(helperEnv); denied != "" {
		runtime.LockOSThread()
		if err := SetNoNewPrivs(); err != nil {
			t.Fatal(err)
		}
		number, err := strconv.ParseUint(denied, 10, 32)
		if err != nil {
			t.Fatal(err)
		}
		filter := []unix.SockFilter{
			bpfLoad(offsetNR), bpfJumpEq(uint32(number), 0, 1), // #nosec G115 -- ParseUint above is limited to 32 bits.
			bpfRet(unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)), bpfRet(unix.SECCOMP_RET_ALLOW),
		}
		prog := unix.SockFprog{Len: 4, Filter: &filter[0]}
		// #nosec G103 -- fixed test filter copied synchronously by the kernel.
		_, _, errno := unix.RawSyscall(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER, unix.SECCOMP_FILTER_FLAG_TSYNC, uintptr(unsafe.Pointer(&prog)))
		if errno != 0 {
			t.Fatal(errno)
		}
		if err := restrictTargetUnixSockets(); !errors.Is(err, unix.EPERM) {
			t.Fatalf("filter installation did not fail closed: %v", err)
		}
		cmd := exec.CommandContext(t.Context(), "/usr/bin/true")
		if err := startSandboxTarget(cmd, LayerStatus{Active: true, Version: 8}); !errors.Is(err, unix.EPERM) || cmd.Process != nil {
			t.Fatalf("target started without IPC filter: %v", err)
		}
		return // this helper process exits with its restrictive test filter
	}
	for _, nr := range []int{unix.SYS_PRCTL, unix.SYS_SECCOMP} {
		cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestTargetUnixSocketInstallationFailure$") // #nosec G204 G702 -- reexec this test binary with a fixed test selector, no external command input.
		for _, arg := range os.Args[1:] {
			if strings.HasPrefix(arg, "-test.gocoverdir=") {
				cmd.Args = append(cmd.Args, arg)
			}
		}
		cmd.Env = append(os.Environ(), helperEnv+"="+strconv.Itoa(nr), "PIPELOCK_MCP_ENVIRON_PROOF_HELPER=1")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("denied syscall %d: %v: %s", nr, err, out)
		}
	}
}

func TestTargetUnixSocketFallback(t *testing.T) {
	if !Detect().Seccomp {
		t.Skip("kernel lacks seccomp support")
	}
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 unavailable for kernel seccomp integration")
	}
	probe := `import socket,errno
for make in (lambda: socket.socket(socket.AF_UNIX), lambda: socket.socketpair(type=socket.SOCK_DGRAM)):
 try:
  make()
 except OSError as e:
  assert e.errno == errno.EPERM, e
 else:
  raise AssertionError("Unix socket creation allowed")
socket.socket(socket.AF_INET).close()
for typ in (socket.SOCK_STREAM,socket.SOCK_SEQPACKET):
 a,b=socket.socketpair(type=typ|socket.SOCK_CLOEXEC)
 a.send(b"pair"); assert b.recv(4)==b"pair"
 target=sys.argv[1] if typ==socket.SOCK_STREAM else sys.argv[2]
 for attempt in (lambda: a.connect(target),lambda: a.sendto(b"blocked",target)):
  try: sent=attempt()
  except OSError as e: assert e.errno==errno.EISCONN,e
  else:
   assert typ==socket.SOCK_SEQPACKET and sent==7,"pair reconnected"
   assert b.recv(7)==b"blocked","sequenced packet left its paired receiver"
 a.send(b"message")
 try: b.recvmsg(7)
 except OSError as e: assert e.errno==errno.EPERM,e
 else: raise AssertionError("recvmsg allowed")
 a.close(); b.close()
print("isolated")
`
	probe = strings.Replace(probe, "import socket,errno", "import socket,errno,sys", 1)
	path := filepath.Join(shortTempDir(t), "host.sock")
	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	seqPath := filepath.Join(filepath.Dir(path), "host-seq.sock")
	seqFD, err := unix.Socket(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(seqFD) }()
	if err := unix.Bind(seqFD, &unix.SockaddrUnix{Name: seqPath}); err != nil {
		t.Fatal(err)
	}
	if err := unix.Listen(seqFD, 8); err != nil {
		t.Fatal(err)
	}
	for _, version := range []int{0, 5, 6, 8} {
		var out bytes.Buffer
		cmd := exec.CommandContext(t.Context(), python, "-c", probe, path, seqPath) // #nosec G204 -- fixed Python executable and in-process isolation probe
		cmd.Stdout, cmd.Stderr = &out, &out
		if err := startSandboxTarget(cmd, LayerStatus{Active: version > 0, Version: version}); err != nil {
			if errors.Is(err, unix.ENOSYS) {
				t.Skip("kernel has no seccomp syscall")
			}
			t.Fatal(err)
		}
		if err := cmd.Wait(); err != nil {
			t.Fatalf("ABI %d: %v: %s", version, err, out.String())
		}
		if out.String() != "isolated\n" {
			t.Fatalf("unexpected probe output: %s", out.String())
		}
		// Installing on the spawning thread must not restrict the bridge's
		// Go runtime or any future goroutine using its worker pool.
		fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM, 0)
		if err != nil {
			t.Fatalf("bridge lost Unix access: %v", err)
		}
		_ = unix.Close(fd)
	}
	modern := exec.CommandContext(t.Context(), "/usr/bin/true")
	if err := startSandboxTarget(modern, LayerStatus{Active: true, Version: 9}); err != nil {
		t.Fatal(err)
	}
	if err := modern.Wait(); err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(t.Context(), "/nonexistent/pipelock-test-command")
	if err := startSandboxTarget(cmd, LayerStatus{Active: true, Version: 8}); err == nil {
		t.Fatal("missing executable accepted")
	}
}
