// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package localservice

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/luckyPipewrench/pipelock/internal/testwait"
)

const (
	envHelper   = "LOCALSERVICE_TEST_HELPER"
	envListen   = "LOCALSERVICE_TEST_LISTEN"
	envHold     = "LOCALSERVICE_TEST_HOLD"
	envHoldMmap = "LOCALSERVICE_TEST_HOLD_MMAP"
	envUpstream = "LOCALSERVICE_TEST_UPSTREAM"

	modeServe   = "serve"
	modeForward = "forward"

	helperReady    = "ready "
	helperAccepted = "accepted"

	loopbackAny   = "127.0.0.1:0"
	pinnedContent = "pinned bundle contents"

	holdFD   = "fd"
	holdMmap = "mmap"
)

// TestMain turns this test binary into the process under verification when the
// helper variable is set. The helper is a real native process with its own pid,
// socket table entry and descriptor table, which is what the verifier reads.
func TestMain(m *testing.M) {
	if mode := os.Getenv(envHelper); mode != "" {
		os.Exit(runHelper(mode))
	}
	os.Exit(m.Run())
}

func helperf(format string, args ...any) {
	_, _ = fmt.Fprintf(os.Stdout, format+"\n", args...)
}

func runHelper(mode string) int {
	ctx := context.Background()
	go func() {
		_, _ = io.Copy(io.Discard, os.Stdin)
		os.Exit(0)
	}()
	if hold := os.Getenv(envHold); hold != "" {
		release, err := holdFile(hold, os.Getenv(envHoldMmap) != "")
		if err != nil {
			_, _ = fmt.Fprintln(os.Stderr, "hold:", err)
			return 1
		}
		defer release()
	}
	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", os.Getenv(envListen))
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "listen:", err)
		return 1
	}
	helperf("%s%s", helperReady, ln.Addr())
	conn, err := ln.Accept()
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "accept:", err)
		return 1
	}
	if mode == modeForward {
		up, err := (&net.Dialer{}).DialContext(ctx, "tcp", os.Getenv(envUpstream))
		if err != nil {
			_, _ = fmt.Fprintln(os.Stderr, "upstream:", err)
			return 1
		}
		go func() { _, _ = io.Copy(up, conn) }()
		go func() { _, _ = io.Copy(conn, up) }()
	}
	helperf("%s", helperAccepted)
	select {}
}

// holdFile keeps path open, or mapped with the descriptor closed, for the life
// of the helper.
func holdFile(path string, mapped bool) (func(), error) {
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	if !mapped {
		return func() { _ = f.Close() }, nil
	}
	fi, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	data, err := unix.Mmap(int(f.Fd()), 0, int(fi.Size()), unix.PROT_READ, unix.MAP_SHARED)
	_ = f.Close()
	if err != nil {
		return nil, err
	}
	return func() { _ = unix.Munmap(data) }, nil
}

type helper struct {
	cmd   *exec.Cmd
	lines chan string
	addr  string
}

// startHelper re-executes this test binary with a minimal environment, so no
// stray interpreter variable in the developer's shell reaches the child.
func startHelper(t *testing.T, mode string, env ...string) *helper {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), testwait.Deadline(2*time.Minute))
	cmd := exec.CommandContext(ctx, "/proc/self/exe")
	cmd.Env = append([]string{envHelper + "=" + mode, "PATH=/usr/bin:/bin"}, env...)
	cmd.Stderr = os.Stderr
	stdin, err := cmd.StdinPipe()
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatalf("start helper: %v", err)
	}
	h := &helper{cmd: cmd, lines: make(chan string, 16)}
	done := make(chan struct{})
	go func() {
		sc := bufio.NewScanner(stdout)
		for sc.Scan() {
			h.lines <- sc.Text()
		}
		close(h.lines)
		_ = cmd.Wait()
		close(done)
	}()
	t.Cleanup(func() {
		_ = stdin.Close()
		select {
		case <-done:
		case <-time.After(testwait.Deadline(10 * time.Second)):
			cancel()
			<-done
		}
		cancel()
	})
	return h
}

func (h *helper) expect(t *testing.T, prefix string) string {
	t.Helper()
	select {
	case line, ok := <-h.lines:
		if !ok {
			t.Fatalf("helper exited before reporting %q", prefix)
		}
		if !strings.HasPrefix(line, prefix) {
			t.Fatalf("helper said %q, want prefix %q", line, prefix)
		}
		return strings.TrimPrefix(line, prefix)
	case <-time.After(testwait.Deadline(30 * time.Second)):
		t.Fatalf("timed out waiting for helper to report %q", prefix)
	}
	return ""
}

func startServer(t *testing.T, mode, listen string, env ...string) *helper {
	t.Helper()
	h := startHelper(t, mode, append([]string{envListen + "=" + listen}, env...)...)
	h.addr = h.expect(t, helperReady)
	return h
}

// dialAccepted connects to the helper and waits until it has accepted, because
// a connection still in the accept queue has no socket inode to look up.
func dialAccepted(t *testing.T, h *helper, addr string) net.Conn {
	t.Helper()
	if addr == "" {
		addr = h.addr
	}
	ctx, cancel := context.WithTimeout(context.Background(), testwait.Deadline(30*time.Second))
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	if err != nil {
		t.Fatalf("dial %s: %v", addr, err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	h.expect(t, helperAccepted)
	return conn
}

var selfExeSum = sync.OnceValues(func() (string, error) {
	f, err := os.Open("/proc/self/exe")
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	return hashFile(f)
})

func basePin(t *testing.T) Pin {
	t.Helper()
	sum, err := selfExeSum()
	if err != nil {
		t.Fatalf("hash own executable: %v", err)
	}
	// A directory this process just created is owned by its effective uid.
	var st unix.Stat_t
	if err := unix.Stat(t.TempDir(), &st); err != nil {
		t.Fatalf("stat temp dir: %v", err)
	}
	return Pin{PrincipalUID: st.Uid, ExecutableSHA256: sum}
}

func writePinnedFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "bundle.bin")
	if err := os.WriteFile(path, []byte(pinnedContent), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func replaceByRename(t *testing.T, path string) {
	t.Helper()
	next := path + ".next"
	if err := os.WriteFile(next, []byte("replacement contents"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(next, path); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyConnRealProcess(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		env     []string
		hold    string
		pinFile bool
		prepare func(t *testing.T, path string)
		pin     func(p *Pin)
		wantErr error
		wantMsg string
	}{
		{name: "native process verifies"},
		{name: "executable digest differs", pin: func(p *Pin) { p.ExecutableSHA256 = testHashA }, wantErr: ErrApplicationMismatch, wantMsg: "verified_local_service.executable_sha256"},
		{name: "principal differs", pin: func(p *Pin) { p.PrincipalUID++ }, wantErr: ErrPrincipalMismatch, wantMsg: "verified_local_service.principal_uid"},
		{name: "pinned file held as a descriptor", hold: holdFD, pinFile: true},
		{name: "pinned file held as a mapping", hold: holdMmap, pinFile: true},
		{name: "pinned file not held", pinFile: true, wantErr: ErrApplicationMismatch, wantMsg: "not open or mapped"},
		{
			name: "pinned file digest differs", hold: holdFD, pinFile: true,
			pin:     func(p *Pin) { p.MappedFiles[0].SHA256 = testHashA },
			wantErr: ErrApplicationMismatch, wantMsg: "verified_local_service.mapped_files[0].sha256",
		},
		{name: "pinned file replaced by rename, held descriptor", hold: holdFD, pinFile: true, prepare: replaceByRename, wantErr: ErrApplicationMismatch, wantMsg: "stale"},
		{name: "pinned file replaced by rename, held mapping", hold: holdMmap, pinFile: true, prepare: replaceByRename, wantErr: ErrApplicationMismatch, wantMsg: "stale"},
		{name: "interpreter option present", env: []string{"NODE_OPTIONS=x"}, wantErr: ErrControlEnvironment, wantMsg: "NODE_OPTIONS"},
		{name: "loader preload present", env: []string{"LD_PRELOAD=/nonexistent/lib.so"}, wantErr: ErrControlEnvironment, wantMsg: "LD_PRELOAD"},
		{
			name: "interpreter option registered", env: []string{"NODE_OPTIONS=x"},
			pin: func(p *Pin) { p.ControlEnvironment = map[string]string{"NODE_OPTIONS": "x"} },
		},
		{
			name: "interpreter option registered with another value", env: []string{"NODE_OPTIONS=x"},
			pin:     func(p *Pin) { p.ControlEnvironment = map[string]string{"NODE_OPTIONS": "y"} },
			wantErr: ErrControlEnvironment,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			path := writePinnedFile(t)
			env := append([]string(nil), tt.env...)
			switch tt.hold {
			case holdFD:
				env = append(env, envHold+"="+path)
			case holdMmap:
				env = append(env, envHold+"="+path, envHoldMmap+"=1")
			}
			h := startServer(t, modeServe, loopbackAny, env...)
			pin := basePin(t)
			if tt.pinFile {
				pin.MappedFiles = []FilePin{{Path: path, SHA256: sha256Hex([]byte(pinnedContent))}}
			}
			if tt.pin != nil {
				tt.pin(&pin)
			}
			conn := dialAccepted(t, h, "")
			if tt.prepare != nil {
				tt.prepare(t, path)
			}

			ev, err := NewVerifier().VerifyConn(conn, pin)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("VerifyConn = %v, want %v", err, tt.wantErr)
				}
				if tt.wantMsg != "" && !strings.Contains(err.Error(), tt.wantMsg) {
					t.Fatalf("error %q does not contain %q", err, tt.wantMsg)
				}
				if strings.Contains(err.Error(), "--server-name") || strings.Contains(err.Error(), pinnedContent) {
					t.Fatalf("error leaks or misnames: %q", err)
				}
				if ev.PID != 0 {
					t.Fatalf("failure returned evidence %+v", ev)
				}
				return
			}
			if err != nil {
				t.Fatalf("VerifyConn = %v", err)
			}
			if ev.PID != h.cmd.Process.Pid {
				t.Fatalf("evidence pid = %d, want the helper's %d", ev.PID, h.cmd.Process.Pid)
			}
			if ev.UID != pin.PrincipalUID || ev.ExecutableSHA256 != pin.ExecutableSHA256 {
				t.Fatalf("evidence = %+v", ev)
			}
			if ev.StartTime == 0 || ev.BootID == "" || ev.ExecutableIno == 0 {
				t.Fatalf("evidence is missing incarnation or file identity: %+v", ev)
			}
			if tt.pinFile && (len(ev.MappedFiles) != 1 || ev.MappedFiles[0].SHA256 != pin.MappedFiles[0].SHA256) {
				t.Fatalf("mapped evidence = %+v", ev.MappedFiles)
			}
		})
	}
}

func TestVerifyConnRealProcessNetworkFamilies(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	probe := func(t *testing.T, addr string) {
		t.Helper()
		ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", addr)
		if err != nil {
			t.Skipf("cannot listen on %s: %v", addr, err)
		}
		_ = ln.Close()
	}
	t.Run("IPv6 loopback", func(t *testing.T) {
		t.Parallel()
		probe(t, "[::1]:0")
		h := startServer(t, modeServe, "[::1]:0")
		ev, err := NewVerifier().VerifyConn(dialAccepted(t, h, ""), basePin(t))
		if err != nil {
			t.Fatalf("VerifyConn = %v", err)
		}
		if ev.PID != h.cmd.Process.Pid {
			t.Fatalf("evidence pid = %d, want %d", ev.PID, h.cmd.Process.Pid)
		}
	})
	t.Run("dual-stack listener reached over IPv4", func(t *testing.T) {
		t.Parallel()
		probe(t, "[::]:0")
		h := startServer(t, modeServe, "[::]:0")
		_, port, err := net.SplitHostPort(h.addr)
		if err != nil {
			t.Fatal(err)
		}
		conn := dialAccepted(t, h, net.JoinHostPort("127.0.0.1", port))
		ev, err := NewVerifier().VerifyConn(conn, basePin(t))
		if err != nil {
			t.Fatalf("VerifyConn = %v", err)
		}
		if ev.PID != h.cmd.Process.Pid {
			t.Fatalf("evidence pid = %d, want %d", ev.PID, h.cmd.Process.Pid)
		}
	})
}

func TestVerifyConnRefusesForwarder(t *testing.T) {
	t.Parallel()
	path := writePinnedFile(t)
	upstream := startServer(t, modeServe, loopbackAny, envHold+"="+path)
	fwd := startServer(t, modeForward, loopbackAny, envUpstream+"="+upstream.addr)
	conn := dialAccepted(t, fwd, "")

	// The forwarder runs the same executable, so the executable pin alone cannot
	// tell it from the service. The kernel does identify it as the owner of the
	// connection, and that is not the process holding the pinned file.
	pin := basePin(t)
	ev, err := NewVerifier().VerifyConn(conn, pin)
	if err != nil {
		t.Fatalf("executable-only VerifyConn = %v", err)
	}
	if ev.PID != fwd.cmd.Process.Pid || ev.PID == upstream.cmd.Process.Pid {
		t.Fatalf("owner pid = %d, forwarder %d, upstream %d", ev.PID, fwd.cmd.Process.Pid, upstream.cmd.Process.Pid)
	}

	pin.MappedFiles = []FilePin{{Path: path, SHA256: sha256Hex([]byte(pinnedContent))}}
	_, err = NewVerifier().VerifyConn(conn, pin)
	if !errors.Is(err, ErrApplicationMismatch) || !strings.Contains(err.Error(), "not open or mapped by the owner") {
		t.Fatalf("VerifyConn through a forwarder = %v, want ErrApplicationMismatch", err)
	}
}

func TestVerifierConcurrentUse(t *testing.T) {
	t.Parallel()
	h := startServer(t, modeServe, loopbackAny)
	conn := dialAccepted(t, h, "")
	pin := basePin(t)
	v := NewVerifier()
	const workers = 8
	errs := make(chan error, workers)
	for i := 0; i < workers; i++ {
		go func() {
			_, err := v.VerifyConn(conn, pin)
			errs <- err
		}()
	}
	for i := 0; i < workers; i++ {
		select {
		case err := <-errs:
			if err != nil {
				t.Errorf("concurrent VerifyConn = %v", err)
			}
		case <-time.After(testwait.Deadline(30 * time.Second)):
			t.Fatal("timed out waiting for concurrent verifications")
		}
	}
}

func TestVerifyingDialContextWithVerifier(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		pin     func(p *Pin)
		wantErr error
	}{
		{name: "matching registration returns the connection"},
		{name: "mismatching registration closes the connection", pin: func(p *Pin) { p.ExecutableSHA256 = testHashA }, wantErr: ErrApplicationMismatch},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			h := startServer(t, modeServe, loopbackAny)
			pin := basePin(t)
			if tt.pin != nil {
				tt.pin(&pin)
			}
			var dialed net.Conn
			dial := VerifyingDialContext((&net.Dialer{}).DialContext, func(c net.Conn) error {
				dialed = c
				h.expect(t, helperAccepted)
				_, err := NewVerifier().VerifyConn(c, pin)
				return err
			})
			ctx, cancel := context.WithTimeout(context.Background(), testwait.Deadline(30*time.Second))
			defer cancel()
			conn, err := dial(ctx, "tcp", h.addr)
			if tt.wantErr == nil {
				if err != nil || conn == nil {
					t.Fatalf("dial = (%v, %v)", conn, err)
				}
				t.Cleanup(func() { _ = conn.Close() })
				return
			}
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("dial error = %v, want %v", err, tt.wantErr)
			}
			if conn != nil {
				t.Fatalf("dial returned an unverified connection")
			}
			if _, werr := dialed.Write([]byte("x")); !errors.Is(werr, net.ErrClosed) {
				t.Fatalf("write on the rejected connection = %v, want net.ErrClosed", werr)
			}
		})
	}
}
