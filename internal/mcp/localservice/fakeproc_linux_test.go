// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package localservice

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/luckyPipewrench/pipelock/internal/testwait"
)

const (
	fakePID     = 4242
	fakeUID     = 31337
	fakeInode   = 90210
	fakeStart   = 1000
	fakeBootID  = "11111111-2222-3333-4444-555555555555"
	fakeExeBody = "fake executable image"
)

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// loopbackPair returns a connected client and server pair on addr.
func loopbackPair(t *testing.T, addr string) (client, server net.Conn) {
	t.Helper()
	ctx := context.Background()
	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", addr)
	if err != nil {
		t.Skipf("cannot listen on %s: %v", addr, err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			close(accepted)
			return
		}
		accepted <- c
	}()
	client, err = (&net.Dialer{}).DialContext(ctx, "tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial %s: %v", ln.Addr(), err)
	}
	t.Cleanup(func() { _ = client.Close() })
	select {
	case server = <-accepted:
		if server == nil {
			t.Fatal("accept failed")
		}
	case <-time.After(testwait.Deadline(10 * time.Second)):
		t.Fatal("timed out waiting for accept")
	}
	t.Cleanup(func() { _ = server.Close() })
	return client, server
}

func fileIdent(t *testing.T, path string) (dev, ino uint64) {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	dev, ino, _, ok := fileIdentity(fi)
	if !ok {
		t.Fatal("no stat identity")
	}
	return dev, ino
}

func mapsLine(dev, ino uint64, path string) string {
	return fmt.Sprintf("7f0000000000-7f0000001000 r--p 00000000 %02x:%02x %d %s\n",
		unix.Major(dev), unix.Minor(dev), ino, path)
}

func statText(comm string, start uint64) string {
	return fmt.Sprintf("%d (%s) S%s %d 0 0\n", fakePID, comm, strings.Repeat(" 0", 18), start)
}

// fakeProc is a /proc tree for one connection and one owning process.
type fakeProc struct {
	t      *testing.T
	root   string
	client net.Conn
	server net.Conn
	pin    Pin
	v      *Verifier
}

func newFakeProc(t *testing.T) *fakeProc {
	t.Helper()
	client, server := loopbackPair(t, "127.0.0.1:0")
	f := &fakeProc{t: t, root: t.TempDir(), client: client, server: server}
	f.v = &Verifier{procRoot: f.root}
	f.pin = Pin{PrincipalUID: fakeUID, ExecutableSHA256: sha256Hex([]byte(fakeExeBody))}
	f.writeTables("tcp", f.rows(fakeUID, fakeInode, 1))
	f.write("sys/kernel/random/boot_id", fakeBootID+"\n")
	f.addProcess(fakePID, fakeInode)
	// A numeric entry that is not a process directory, like a stray file.
	f.write("123", "not a process directory")
	return f
}

func (f *fakeProc) write(rel, content string) {
	f.t.Helper()
	p := filepath.Join(f.root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
		f.t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fakeProc) remove(rel string) {
	f.t.Helper()
	if err := os.RemoveAll(filepath.Join(f.root, filepath.FromSlash(rel))); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fakeProc) symlink(target, rel string) {
	f.t.Helper()
	p := filepath.Join(f.root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
		f.t.Fatal(err)
	}
	if err := os.Symlink(target, p); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fakeProc) addrs() (local, remote netip.AddrPort) {
	return netip.MustParseAddrPort(f.client.LocalAddr().String()), netip.MustParseAddrPort(f.client.RemoteAddr().String())
}

// rows renders the client row and the server row of the connection.
func (f *fakeProc) rows(uid, inode, state uint64) string {
	local, remote := f.addrs()
	return procNetHeader +
		procRow(0, local, remote, 1, uid, 1) + "\n" +
		procRow(1, remote, local, state, uid, inode) + "\n"
}

func (f *fakeProc) writeTables(name, content string) {
	f.t.Helper()
	f.write("thread-self/net/"+name, content)
}

func (f *fakeProc) addProcess(pid int, socketInode uint64) {
	f.t.Helper()
	dir := strconv.Itoa(pid)
	f.write(dir+"/stat", statText("svc", fakeStart))
	f.write(dir+"/status", fmt.Sprintf("Name:\tsvc\nUid:\t%d\t%d\t%d\t%d\nGid:\t0\t0\t0\t0\n", fakeUID, fakeUID, fakeUID, fakeUID))
	f.write(dir+"/environ", "PATH=/usr/bin\x00HOME=/nonexistent\x00")
	f.write(dir+"/maps", "")
	f.write(dir+"/exe", fakeExeBody)
	if socketInode != 0 {
		f.symlink("socket:["+strconv.FormatUint(socketInode, 10)+"]", dir+"/fd/3")
	} else {
		f.write(dir+"/fd/.keep", "")
	}
}

func (f *fakeProc) verify() (Evidence, error) {
	f.t.Helper()
	return f.v.VerifyConn(f.client, f.pin)
}

// pinnedFile creates a regular file outside the tree to pin.
func (f *fakeProc) pinnedFile(content string) (path string) {
	f.t.Helper()
	path = filepath.Join(f.t.TempDir(), "bundle.bin")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		f.t.Fatal(err)
	}
	return path
}

func TestVerifyConnFakeProc(t *testing.T) {
	t.Parallel()
	const secretValue = "super-secret-env-value"
	tests := []struct {
		name    string
		setup   func(t *testing.T, f *fakeProc)
		wantErr error
		wantMsg string
	}{
		{name: "baseline verifies", setup: func(*testing.T, *fakeProc) {}},
		{
			name: "tcp6 rows with IPv4-mapped addresses",
			setup: func(_ *testing.T, f *fakeProc) {
				local, remote := f.addrs()
				mapped := func(ap netip.AddrPort) netip.AddrPort {
					return netip.AddrPortFrom(netip.AddrFrom16(ap.Addr().As16()), ap.Port())
				}
				f.writeTables("tcp", procNetHeader)
				f.writeTables("tcp6", procNetHeader+
					procRow(0, mapped(local), mapped(remote), 1, fakeUID, 1)+"\n"+
					procRow(1, mapped(remote), mapped(local), 1, fakeUID, fakeInode)+"\n")
			},
		},
		{
			name: "malformed lines are ignored",
			setup: func(_ *testing.T, f *fakeProc) {
				f.writeTables("tcp", f.rows(fakeUID, fakeInode, 1)+"complete garbage\n\x00\x00\n   9: zz:zz zz:zz 01 a b c d e f g\n")
			},
		},
		{
			name: "one process holding the socket on two descriptors is one owner",
			setup: func(_ *testing.T, f *fakeProc) {
				f.symlink("socket:["+strconv.Itoa(fakeInode)+"]", strconv.Itoa(fakePID)+"/fd/9")
			},
		},
		{
			name: "falls back to self when thread-self is absent",
			setup: func(t *testing.T, f *fakeProc) {
				if err := os.Rename(filepath.Join(f.root, "thread-self"), filepath.Join(f.root, "self")); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "command name containing a parenthesis and spaces",
			setup: func(_ *testing.T, f *fakeProc) {
				f.write(strconv.Itoa(fakePID)+"/stat", statText("a) b (c", fakeStart))
			},
		},
		{
			name:    "no socket rows at all",
			setup:   func(_ *testing.T, f *fakeProc) { f.writeTables("tcp", procNetHeader) },
			wantErr: ErrSocketNotFound,
		},
		{
			name: "server row missing",
			setup: func(_ *testing.T, f *fakeProc) {
				local, remote := f.addrs()
				f.writeTables("tcp", procNetHeader+procRow(0, local, remote, 1, fakeUID, 1)+"\n")
			},
			wantErr: ErrSocketNotFound,
			wantMsg: "server end",
		},
		{
			name: "client row missing",
			setup: func(_ *testing.T, f *fakeProc) {
				local, remote := f.addrs()
				f.writeTables("tcp", procNetHeader+procRow(0, remote, local, 1, fakeUID, fakeInode)+"\n")
			},
			wantErr: ErrSocketNotFound,
			wantMsg: "client end",
		},
		{
			name:    "server row not established",
			setup:   func(_ *testing.T, f *fakeProc) { f.writeTables("tcp", f.rows(fakeUID, fakeInode, 6)) },
			wantErr: ErrSocketNotFound,
		},
		{
			name:    "server row without an inode",
			setup:   func(_ *testing.T, f *fakeProc) { f.writeTables("tcp", f.rows(fakeUID, 0, 1)) },
			wantErr: ErrSocketNotFound,
			wantMsg: "no socket inode",
		},
		{
			name: "two distinct server sockets for one tuple",
			setup: func(_ *testing.T, f *fakeProc) {
				local, remote := f.addrs()
				f.writeTables("tcp", f.rows(fakeUID, fakeInode, 1)+procRow(2, remote, local, 1, fakeUID, fakeInode+1)+"\n")
			},
			wantErr: ErrMultipleOwners,
		},
		{
			name:    "socket table unreadable",
			setup:   func(_ *testing.T, f *fakeProc) { f.remove("thread-self/net/tcp") },
			wantErr: ErrSocketNotFound,
		},
		{
			name: "tcp6 table present but unreadable",
			setup: func(t *testing.T, f *fakeProc) {
				if err := os.MkdirAll(filepath.Join(f.root, "thread-self/net/tcp6"), 0o750); err != nil {
					t.Fatal(err)
				}
			},
			wantErr: ErrSocketNotFound,
		},
		{
			name:    "no process holds the socket",
			setup:   func(_ *testing.T, f *fakeProc) { f.remove(strconv.Itoa(fakePID) + "/fd/3") },
			wantErr: ErrOwnerNotVisible,
			wantMsg: "visible",
		},
		{
			name: "two processes hold the socket",
			setup: func(_ *testing.T, f *fakeProc) {
				f.addProcess(fakePID+1, fakeInode)
			},
			wantErr: ErrMultipleOwners,
			wantMsg: strconv.Itoa(fakePID + 1),
		},
		{
			name: "owner vanishes before its start time is read",
			setup: func(_ *testing.T, f *fakeProc) {
				f.remove(strconv.Itoa(fakePID) + "/stat")
			},
			wantErr: ErrOwnerChanged,
		},
		{
			name: "stat unreadable for another reason",
			setup: func(_ *testing.T, f *fakeProc) {
				f.remove(strconv.Itoa(fakePID) + "/stat")
				f.write(strconv.Itoa(fakePID)+"/stat/keep", "")
			},
			wantErr: ErrOwnerNotVisible,
		},
		{
			name:    "stat without a command terminator",
			setup:   func(_ *testing.T, f *fakeProc) { f.write(strconv.Itoa(fakePID)+"/stat", "4242 svc S 0\n") },
			wantErr: ErrOwnerNotVisible,
		},
		{
			name:    "stat with too few fields",
			setup:   func(_ *testing.T, f *fakeProc) { f.write(strconv.Itoa(fakePID)+"/stat", "4242 (svc) S 0 0\n") },
			wantErr: ErrOwnerNotVisible,
		},
		{
			name: "stat with a malformed start time",
			setup: func(_ *testing.T, f *fakeProc) {
				f.write(strconv.Itoa(fakePID)+"/stat", strings.Replace(statText("svc", 1), " 1 0 0", " x 0 0", 1))
			},
			wantErr: ErrOwnerNotVisible,
		},
		{
			name:    "boot id unreadable",
			setup:   func(_ *testing.T, f *fakeProc) { f.remove("sys/kernel/random/boot_id") },
			wantErr: ErrOwnerNotVisible,
		},
		{
			name: "start time changes between the reads",
			setup: func(_ *testing.T, f *fakeProc) {
				f.v.beforeRecheck = func() { f.write(strconv.Itoa(fakePID)+"/stat", statText("svc", fakeStart+1)) }
			},
			wantErr: ErrOwnerChanged,
		},
		{
			name: "boot id changes between the reads",
			setup: func(_ *testing.T, f *fakeProc) {
				f.v.beforeRecheck = func() { f.write("sys/kernel/random/boot_id", "other-boot\n") }
			},
			wantErr: ErrOwnerChanged,
		},
		{
			name: "socket descriptor goes away between the reads",
			setup: func(_ *testing.T, f *fakeProc) {
				f.v.beforeRecheck = func() { f.remove(strconv.Itoa(fakePID) + "/fd/3") }
			},
			wantErr: ErrOwnerChanged,
		},
		{
			name: "descriptor now holds a different socket",
			setup: func(_ *testing.T, f *fakeProc) {
				f.v.beforeRecheck = func() {
					f.remove(strconv.Itoa(fakePID) + "/fd/3")
					f.symlink("socket:[1]", strconv.Itoa(fakePID)+"/fd/3")
				}
			},
			wantErr: ErrOwnerChanged,
		},
		{
			name: "process exits between the reads",
			setup: func(_ *testing.T, f *fakeProc) {
				f.v.beforeRecheck = func() { f.remove(strconv.Itoa(fakePID) + "/stat") }
			},
			wantErr: ErrOwnerChanged,
		},
		{
			name: "socket table uid differs from the process uid",
			setup: func(_ *testing.T, f *fakeProc) {
				f.writeTables("tcp", f.rows(fakeUID+1, fakeInode, 1))
			},
			wantErr: ErrPrincipalMismatch,
			wantMsg: "verified_local_service.principal_uid",
		},
		{
			name:    "registered principal differs",
			setup:   func(_ *testing.T, f *fakeProc) { f.pin.PrincipalUID = fakeUID + 1 },
			wantErr: ErrPrincipalMismatch,
		},
		{
			name: "effective uid differs while the real uid matches",
			setup: func(_ *testing.T, f *fakeProc) {
				f.write(strconv.Itoa(fakePID)+"/status", fmt.Sprintf("Uid:\t%d\t0\t0\t0\n", fakeUID))
			},
			wantErr: ErrPrincipalMismatch,
		},
		{
			name:    "status without a Uid line",
			setup:   func(_ *testing.T, f *fakeProc) { f.write(strconv.Itoa(fakePID)+"/status", "Name:\tsvc\n") },
			wantErr: ErrOwnerNotVisible,
		},
		{
			name:    "status Uid line with the wrong field count",
			setup:   func(_ *testing.T, f *fakeProc) { f.write(strconv.Itoa(fakePID)+"/status", "Uid:\t1\t2\n") },
			wantErr: ErrOwnerNotVisible,
		},
		{
			name:    "status Uid line with a non-numeric value",
			setup:   func(_ *testing.T, f *fakeProc) { f.write(strconv.Itoa(fakePID)+"/status", "Uid:\t1\tx\t3\t4\n") },
			wantErr: ErrOwnerNotVisible,
		},
		{
			name: "status missing",
			setup: func(_ *testing.T, f *fakeProc) {
				f.remove(strconv.Itoa(fakePID) + "/status")
			},
			wantErr: ErrOwnerChanged,
		},
		{
			name:    "executable digest differs",
			setup:   func(_ *testing.T, f *fakeProc) { f.pin.ExecutableSHA256 = testHashA },
			wantErr: ErrApplicationMismatch,
			wantMsg: "verified_local_service.executable_sha256",
		},
		{
			name:    "executable cannot be opened",
			setup:   func(_ *testing.T, f *fakeProc) { f.remove(strconv.Itoa(fakePID) + "/exe") },
			wantErr: ErrOwnerNotVisible,
		},
		{
			name: "executable cannot be read",
			setup: func(_ *testing.T, f *fakeProc) {
				f.remove(strconv.Itoa(fakePID) + "/exe")
				f.write(strconv.Itoa(fakePID)+"/exe/inner", "")
			},
			wantErr: ErrOwnerNotVisible,
		},
		{
			name: "control variable not registered",
			setup: func(_ *testing.T, f *fakeProc) {
				f.write(strconv.Itoa(fakePID)+"/environ", "PATH=/bin\x00NODE_OPTIONS="+secretValue+"\x00")
			},
			wantErr: ErrControlEnvironment,
			wantMsg: "NODE_OPTIONS",
		},
		{
			name: "control variable registered with the exact value",
			setup: func(_ *testing.T, f *fakeProc) {
				f.write(strconv.Itoa(fakePID)+"/environ", "NODE_OPTIONS="+secretValue+"\x00")
				f.pin.ControlEnvironment = map[string]string{"NODE_OPTIONS": secretValue}
			},
		},
		{
			name: "control variable registered with another value",
			setup: func(_ *testing.T, f *fakeProc) {
				f.write(strconv.Itoa(fakePID)+"/environ", "NODE_OPTIONS="+secretValue+"\x00")
				f.pin.ControlEnvironment = map[string]string{"NODE_OPTIONS": "other"}
			},
			wantErr: ErrControlEnvironment,
		},
		{
			name: "several control variables are all named",
			setup: func(_ *testing.T, f *fakeProc) {
				f.write(strconv.Itoa(fakePID)+"/environ", "PYTHONPATH=/x\x00LD_PRELOAD=/y\x00OK=1\x00noequals\x00")
				f.pin.ControlEnvironment = map[string]string{"PYTHONPATH": "/x"}
			},
			wantErr: ErrControlEnvironment,
			wantMsg: "LD_PRELOAD",
		},
		{
			name: "environment unreadable",
			setup: func(_ *testing.T, f *fakeProc) {
				f.remove(strconv.Itoa(fakePID) + "/environ")
			},
			wantErr: ErrOwnerNotVisible,
		},
		{
			name: "environment cannot be read",
			setup: func(_ *testing.T, f *fakeProc) {
				f.remove(strconv.Itoa(fakePID) + "/environ")
				f.write(strconv.Itoa(fakePID)+"/environ/inner", "")
			},
			wantErr: ErrOwnerNotVisible,
		},
		{
			name: "environment larger than the bound",
			setup: func(_ *testing.T, f *fakeProc) {
				f.write(strconv.Itoa(fakePID)+"/environ", strings.Repeat("A", environMaxBytes+1))
			},
			wantErr: ErrOwnerNotVisible,
			wantMsg: "cannot be fully checked",
		},
		{
			name:    "invalid registration is refused before any proc read",
			setup:   func(_ *testing.T, f *fakeProc) { f.pin.ExecutableSHA256 = "nope" },
			wantErr: ErrInvalidPin,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			f := newFakeProc(t)
			tt.setup(t, f)
			ev, err := f.verify()
			if tt.wantErr == nil {
				if err != nil {
					t.Fatalf("VerifyConn = %v, want success", err)
				}
				if ev.PID != fakePID || ev.StartTime != fakeStart || ev.BootID != fakeBootID || ev.UID != fakeUID {
					t.Fatalf("evidence = %+v", ev)
				}
				if ev.ExecutableSHA256 != f.pin.ExecutableSHA256 || ev.ExecutableIno == 0 {
					t.Fatalf("executable evidence = %+v", ev)
				}
				return
			}
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("VerifyConn = %v, want %v", err, tt.wantErr)
			}
			if ev.PID != 0 || ev.ExecutableSHA256 != "" || len(ev.MappedFiles) != 0 {
				t.Fatalf("failure returned partial evidence %+v", ev)
			}
			if tt.wantMsg != "" && !strings.Contains(err.Error(), tt.wantMsg) {
				t.Fatalf("error %q does not contain %q", err, tt.wantMsg)
			}
			if strings.Contains(err.Error(), secretValue) {
				t.Fatalf("error leaks an environment value: %q", err)
			}
			if strings.Contains(err.Error(), "--server-name") {
				t.Fatalf("error names --server-name: %q", err)
			}
		})
	}
}

func TestVerifyConnFakeProcMappedFiles(t *testing.T) {
	t.Parallel()
	const content = "bundle contents"
	contentHash := sha256Hex([]byte(content))

	heldByMaps := func(f *fakeProc, path string) {
		dev, ino := fileIdent(f.t, path)
		f.write(strconv.Itoa(fakePID)+"/maps", "00400000-00401000 r-xp 00000000 00:00 0\n"+mapsLine(dev, ino, path))
	}
	tests := []struct {
		name    string
		setup   func(f *fakeProc, path string)
		pinHash string
		wantErr error
		wantMsg string
	}{
		{
			name:    "held as a descriptor",
			pinHash: contentHash,
			setup: func(f *fakeProc, path string) {
				f.symlink(path, strconv.Itoa(fakePID)+"/fd/4")
			},
		},
		{
			name:    "held as a mapping",
			pinHash: contentHash,
			setup:   heldByMaps,
		},
		{
			name:    "descriptor noise does not matter",
			pinHash: contentHash,
			setup: func(f *fakeProc, path string) {
				f.symlink("anon_inode:[eventfd]", strconv.Itoa(fakePID)+"/fd/5")
				f.symlink("/nonexistent/dangling/target", strconv.Itoa(fakePID)+"/fd/6")
				heldByMaps(f, path)
			},
		},
		{
			name:    "not held by the owner",
			pinHash: contentHash,
			setup:   func(*fakeProc, string) {},
			wantErr: ErrApplicationMismatch,
			wantMsg: "not open or mapped by the owner",
		},
		{
			name:    "held under a different inode at the same path",
			pinHash: contentHash,
			setup: func(f *fakeProc, path string) {
				dev, ino := fileIdent(f.t, path)
				f.write(strconv.Itoa(fakePID)+"/maps", mapsLine(dev, ino+1, path+deletedSuffix))
			},
			wantErr: ErrApplicationMismatch,
			wantMsg: "stale",
		},
		{
			name:    "held but the digest differs",
			pinHash: testHashA,
			setup:   heldByMaps,
			wantErr: ErrApplicationMismatch,
			wantMsg: "verified_local_service.mapped_files[0].sha256",
		},
		{
			name:    "maps unreadable",
			pinHash: contentHash,
			setup: func(f *fakeProc, _ string) {
				f.remove(strconv.Itoa(fakePID) + "/maps")
				f.write(strconv.Itoa(fakePID)+"/maps/inner", "")
			},
			wantErr: ErrOwnerNotVisible,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			f := newFakeProc(t)
			path := f.pinnedFile(content)
			f.pin.MappedFiles = []FilePin{{Path: path, SHA256: tt.pinHash}}
			tt.setup(f, path)
			ev, err := f.verify()
			if tt.wantErr == nil {
				if err != nil {
					t.Fatalf("VerifyConn = %v", err)
				}
				if len(ev.MappedFiles) != 1 || ev.MappedFiles[0] != (FilePin{Path: path, SHA256: contentHash}) {
					t.Fatalf("mapped evidence = %+v", ev.MappedFiles)
				}
				return
			}
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("VerifyConn = %v, want %v", err, tt.wantErr)
			}
			if tt.wantMsg != "" && !strings.Contains(err.Error(), tt.wantMsg) {
				t.Fatalf("error %q does not contain %q", err, tt.wantMsg)
			}
			if strings.Contains(err.Error(), content) {
				t.Fatalf("error leaks file contents: %q", err)
			}
		})
	}

	t.Run("pinned path problems", func(t *testing.T) {
		t.Parallel()
		f := newFakeProc(t)
		dir := t.TempDir()
		for name, pf := range map[string]FilePin{
			"missing":   {Path: filepath.Join(dir, "absent"), SHA256: contentHash},
			"directory": {Path: dir, SHA256: contentHash},
		} {
			f.pin.MappedFiles = []FilePin{pf}
			if _, err := f.verify(); !errors.Is(err, ErrApplicationMismatch) {
				t.Errorf("%s: VerifyConn = %v, want ErrApplicationMismatch", name, err)
			}
		}
	})

	t.Run("second entry fails and names its index", func(t *testing.T) {
		t.Parallel()
		f := newFakeProc(t)
		held := f.pinnedFile(content)
		heldByMaps(f, held)
		other := f.pinnedFile("another")
		f.pin.MappedFiles = []FilePin{{Path: held, SHA256: contentHash}, {Path: other, SHA256: sha256Hex([]byte("another"))}}
		_, err := f.verify()
		if !errors.Is(err, ErrApplicationMismatch) || !strings.Contains(err.Error(), "mapped_files[1]") {
			t.Fatalf("VerifyConn = %v, want mapped_files[1] mismatch", err)
		}
	})
}

func TestVerifyConnFakeProcIPv6(t *testing.T) {
	t.Parallel()
	client, _ := loopbackPair(t, "[::1]:0")
	f := &fakeProc{t: t, root: t.TempDir(), client: client}
	f.v = &Verifier{procRoot: f.root}
	f.pin = Pin{PrincipalUID: fakeUID, ExecutableSHA256: sha256Hex([]byte(fakeExeBody))}
	f.writeTables("tcp", procNetHeader)
	f.writeTables("tcp6", f.rows(fakeUID, fakeInode, 1))
	f.write("sys/kernel/random/boot_id", fakeBootID+"\n")
	f.addProcess(fakePID, fakeInode)
	ev, err := f.verify()
	if err != nil {
		t.Fatalf("VerifyConn = %v", err)
	}
	if ev.PID != fakePID {
		t.Fatalf("evidence = %+v", ev)
	}
}

func TestVerifierExecutableCache(t *testing.T) {
	t.Parallel()
	f := newFakeProc(t)
	for i := 0; i < 2; i++ {
		if _, err := f.verify(); err != nil {
			t.Fatalf("verify %d: %v", i, err)
		}
	}
	if len(f.v.exeSums) != 1 || len(f.v.exeOrder) != 1 {
		t.Fatalf("cache holds %d entries, want 1", len(f.v.exeSums))
	}

	v := &Verifier{}
	first := exeKey{dev: 1, ino: 1}
	v.storeSum(first, "first")
	v.storeSum(first, "replaced?")
	if got, ok := v.cachedSum(first); !ok || got != "first" {
		t.Fatalf("duplicate store must keep the original, got %q %v", got, ok)
	}
	for i := 2; i < exeCacheMax+10; i++ {
		v.storeSum(exeKey{dev: 1, ino: uint64(i)}, "x")
	}
	if len(v.exeSums) != exeCacheMax || len(v.exeOrder) != exeCacheMax {
		t.Fatalf("cache grew to %d/%d, bound is %d", len(v.exeSums), len(v.exeOrder), exeCacheMax)
	}
	if _, ok := v.cachedSum(first); ok {
		t.Fatal("oldest entry was not evicted")
	}
	if _, ok := v.cachedSum(exeKey{dev: 1, ino: uint64(exeCacheMax + 9)}); !ok {
		t.Fatal("newest entry was evicted")
	}
}

func TestVerifierPathDefaults(t *testing.T) {
	t.Parallel()
	if got := NewVerifier().path("self", "net"); got != filepath.Join("/proc", "self", "net") {
		t.Fatalf("path = %q", got)
	}
	if got := (&Verifier{}).pidPath(7, "fd"); got != filepath.Join("/proc", "7", "fd") {
		t.Fatalf("pidPath = %q", got)
	}
}

func TestFindOwnerUnreadableRoot(t *testing.T) {
	t.Parallel()
	v := &Verifier{procRoot: filepath.Join(t.TempDir(), "absent")}
	if _, err := v.findOwner(1); !errors.Is(err, ErrOwnerNotVisible) {
		t.Fatalf("findOwner = %v, want ErrOwnerNotVisible", err)
	}
	if _, err := v.readSocketTables(); !errors.Is(err, ErrSocketNotFound) {
		t.Fatalf("readSocketTables = %v, want ErrSocketNotFound", err)
	}
}

func TestShortHash(t *testing.T) {
	t.Parallel()
	long := strings.Repeat("a", sha256HexLen)
	if got := shortHash(long); len(got) != shortHashLen {
		t.Fatalf("shortHash(long) = %q", got)
	}
	if got := shortHash("abc"); got != "abc" {
		t.Fatalf("shortHash(short) = %q", got)
	}
}

func TestParsePID(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in   string
		want int
		ok   bool
	}{
		{"1", 1, true},
		{"4242", 4242, true},
		{"", 0, false},
		{"0", 0, false},
		{"-1", 0, false},
		{"12a", 0, false},
		{"self", 0, false},
		{"thread-self", 0, false},
		{"99999999999999999999999", 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			t.Parallel()
			got, ok := parsePID(tt.in)
			if got != tt.want || ok != tt.ok {
				t.Fatalf("parsePID(%q) = %d, %v", tt.in, got, ok)
			}
		})
	}
}

func TestParseMapsLine(t *testing.T) {
	t.Parallel()
	dev := unix.Mkdev(8, 1)
	tests := []struct {
		name string
		line string
		want heldFile
		ok   bool
	}{
		{name: "file mapping", line: "7f00-7f01 r--p 00000000 08:01 1234 /usr/lib/libx.so", want: heldFile{dev: dev, ino: 1234, path: "/usr/lib/libx.so"}, ok: true},
		{name: "deleted suffix is trimmed", line: "7f00-7f01 r--p 00000000 08:01 1234 /tmp/x (deleted)", want: heldFile{dev: dev, ino: 1234, path: "/tmp/x"}, ok: true},
		{name: "path with spaces", line: "7f00-7f01 r--p 00000000 08:01 1234 /opt/my app/x.bin", want: heldFile{dev: dev, ino: 1234, path: "/opt/my app/x.bin"}, ok: true},
		{name: "anonymous", line: "7f00-7f01 rw-p 00000000 00:00 0"},
		{name: "heap", line: "7f00-7f01 rw-p 00000000 00:00 0 [heap]"},
		{name: "pseudo path with inode", line: "7f00-7f01 rw-p 00000000 00:05 55 anon_inode:x"},
		{name: "zero inode", line: "7f00-7f01 r--p 00000000 08:01 0 /x"},
		{name: "bad device", line: "7f00-7f01 r--p 00000000 0801 5 /x"},
		{name: "bad major", line: "7f00-7f01 r--p 00000000 zz:01 5 /x"},
		{name: "bad minor", line: "7f00-7f01 r--p 00000000 08:zz 5 /x"},
		{name: "bad inode", line: "7f00-7f01 r--p 00000000 08:01 x /x"},
		{name: "empty", line: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, ok := parseMapsLine(tt.line)
			if ok != tt.ok || (ok && got != tt.want) {
				t.Fatalf("parseMapsLine = %+v, %v; want %+v, %v", got, ok, tt.want, tt.ok)
			}
		})
	}
}

type addrConn struct {
	net.Conn
	l, r net.Addr
}

func (c addrConn) LocalAddr() net.Addr  { return c.l }
func (c addrConn) RemoteAddr() net.Addr { return c.r }

func TestLoopbackEndpoints(t *testing.T) {
	t.Parallel()
	pipeA, pipeB := net.Pipe()
	t.Cleanup(func() { _ = pipeA.Close(); _ = pipeB.Close() })
	tcp := func(ip string, port int) net.Addr {
		return &net.TCPAddr{IP: net.ParseIP(ip), Port: port}
	}
	tests := []struct {
		name    string
		conn    net.Conn
		want    string
		wantErr bool
	}{
		{name: "nil", conn: nil, wantErr: true},
		{name: "not TCP", conn: pipeA, wantErr: true},
		{name: "unix remote", conn: addrConn{l: tcp("127.0.0.1", 1), r: &net.UnixAddr{Name: "/s", Net: "unix"}}, wantErr: true},
		{name: "local not loopback", conn: addrConn{l: tcp("192.0.2.1", 1), r: tcp("127.0.0.1", 2)}, wantErr: true},
		{name: "remote not loopback", conn: addrConn{l: tcp("127.0.0.1", 1), r: tcp("192.0.2.1", 2)}, wantErr: true},
		{name: "v6 documentation address", conn: addrConn{l: tcp("2001:db8::1", 1), r: tcp("::1", 2)}, wantErr: true},
		{name: "v4 loopback block", conn: addrConn{l: tcp("127.5.5.5", 1), r: tcp("127.0.0.1", 2)}, want: "127.5.5.5:1"},
		{name: "v6 loopback", conn: addrConn{l: tcp("::1", 1), r: tcp("::1", 2)}, want: "[::1]:1"},
		{name: "mapped loopback is unmapped", conn: addrConn{l: tcp("::ffff:127.0.0.1", 1), r: tcp("::ffff:127.0.0.1", 2)}, want: "127.0.0.1:1"},
		{name: "zone is dropped", conn: addrConn{l: &net.TCPAddr{IP: net.ParseIP("::1"), Port: 1, Zone: "lo"}, r: tcp("::1", 2)}, want: "[::1]:1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			local, _, err := loopbackEndpoints(tt.conn)
			if tt.wantErr {
				if !errors.Is(err, ErrNotLoopback) {
					t.Fatalf("err = %v, want ErrNotLoopback", err)
				}
				return
			}
			if err != nil || local.String() != tt.want {
				t.Fatalf("local = %v, err = %v; want %s", local, err, tt.want)
			}
		})
	}

	// The same refusal surfaces through VerifyConn before any /proc access.
	_, err := (&Verifier{procRoot: filepath.Join(t.TempDir(), "absent")}).VerifyConn(
		addrConn{l: tcp("192.0.2.1", 1), r: tcp("192.0.2.2", 2)}, Pin{ExecutableSHA256: testHashA})
	if !errors.Is(err, ErrNotLoopback) {
		t.Fatalf("VerifyConn = %v, want ErrNotLoopback", err)
	}
}
