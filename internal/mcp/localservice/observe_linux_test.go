// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package localservice

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/luckyPipewrench/pipelock/internal/testwait"
)

const observeSecret = "observe-secret-env-value"

func (f *fakeProc) observe() (Observation, error) {
	f.t.Helper()
	return f.v.Observe(context.Background(), f.client)
}

func (f *fakeProc) setMaps(lines ...string) {
	f.t.Helper()
	f.write(strconv.Itoa(fakePID)+"/maps", strings.Join(lines, ""))
}

func TestObserveFakeProcFiles(t *testing.T) {
	t.Parallel()
	const content = "observed bundle"
	contentHash := sha256Hex([]byte(content))

	tests := []struct {
		name  string
		setup func(f *fakeProc, path string)
		want  func(path string) []ObservedFile
	}{
		{
			name:  "nothing held",
			setup: func(*fakeProc, string) {},
			want:  func(string) []ObservedFile { return nil },
		},
		{
			name: "held as a descriptor",
			setup: func(f *fakeProc, path string) {
				f.symlink(path, strconv.Itoa(fakePID)+"/fd/4")
			},
			want: func(path string) []ObservedFile { return []ObservedFile{{Path: path, SHA256: contentHash}} },
		},
		{
			name: "held as a mapping",
			setup: func(f *fakeProc, path string) {
				dev, ino := mapsIdent(f.t, path)
				f.setMaps(mapsLine(dev, ino, path))
			},
			want: func(path string) []ObservedFile { return []ObservedFile{{Path: path, SHA256: contentHash}} },
		},
		{
			name: "descriptor and mapping of one inode are one entry",
			setup: func(f *fakeProc, path string) {
				dev, ino := mapsIdent(f.t, path)
				f.symlink(path, strconv.Itoa(fakePID)+"/fd/4")
				f.setMaps(mapsLine(dev, ino, path), mapsLine(dev, ino, path))
			},
			want: func(path string) []ObservedFile { return []ObservedFile{{Path: path, SHA256: contentHash}} },
		},
		{
			name: "same path held under another inode is reported without a digest",
			setup: func(f *fakeProc, path string) {
				dev, ino := mapsIdent(f.t, path)
				f.setMaps(mapsLine(dev, ino+1, path+deletedSuffix))
			},
			want: func(path string) []ObservedFile { return []ObservedFile{{Path: path}} },
		},
		{
			name: "held path that no longer exists is reported without a digest",
			setup: func(f *fakeProc, path string) {
				dev, ino := mapsIdent(f.t, path)
				f.setMaps(mapsLine(dev, ino, path+".gone"))
			},
			want: func(path string) []ObservedFile { return []ObservedFile{{Path: path + ".gone"}} },
		},
		{
			name: "directory descriptors are not files",
			setup: func(f *fakeProc, _ string) {
				f.symlink(f.t.TempDir(), strconv.Itoa(fakePID)+"/fd/4")
			},
			want: func(string) []ObservedFile { return nil },
		},
		{
			name: "character device descriptors are not files",
			setup: func(f *fakeProc, _ string) {
				f.symlink("/dev/null", strconv.Itoa(fakePID)+"/fd/4")
			},
			want: func(string) []ObservedFile { return nil },
		},
		{
			name: "kernel and anonymous object paths are not files",
			setup: func(f *fakeProc, path string) {
				dev, ino := mapsIdent(f.t, path)
				f.setMaps(
					mapsLine(dev, ino, "/dev/shm/segment"),
					mapsLine(dev, ino+1, "/proc/self/exe"),
					mapsLine(dev, ino+2, "/sys/kernel/x"),
					mapsLine(dev, ino+3, "/memfd:jit (deleted)"),
					mapsLine(dev, ino+4, "/SYSV00000000"),
				)
			},
			want: func(string) []ObservedFile { return nil },
		},
		{
			name: "a fifo behind a held path is dropped without blocking",
			setup: func(f *fakeProc, _ string) {
				fifo := filepath.Join(f.t.TempDir(), "pipe")
				if err := unix.Mkfifo(fifo, 0o600); err != nil {
					f.t.Fatal(err)
				}
				dev, ino := fileIdent(f.t, fifo)
				f.setMaps(mapsLine(dev, ino, fifo))
			},
			want: func(string) []ObservedFile { return nil },
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			f := newFakeProc(t)
			path := f.pinnedFile(content)
			tt.setup(f, path)
			obs, err := f.observe()
			if err != nil {
				t.Fatalf("Observe = %v", err)
			}
			want := tt.want(path)
			if len(obs.Files) != len(want) {
				t.Fatalf("files = %+v, want %d entries", obs.Files, len(want))
			}
			for i, w := range want {
				got := obs.Files[i]
				if got.Path != w.Path || got.SHA256 != w.SHA256 || got.Ino == 0 || got.Dev == 0 {
					t.Fatalf("file[%d] = %+v, want %+v with identity", i, got, w)
				}
			}
		})
	}

	t.Run("files are sorted by path", func(t *testing.T) {
		t.Parallel()
		f := newFakeProc(t)
		a, b := f.pinnedFile("a"), f.pinnedFile("b")
		f.symlink(b, strconv.Itoa(fakePID)+"/fd/4")
		f.symlink(a, strconv.Itoa(fakePID)+"/fd/5")
		obs, err := f.observe()
		if err != nil {
			t.Fatal(err)
		}
		paths := make([]string, len(obs.Files))
		for i, file := range obs.Files {
			paths[i] = file.Path
		}
		if len(paths) != 2 || !sort.StringsAreSorted(paths) {
			t.Fatalf("paths = %v, want two sorted entries", paths)
		}
	})
}

func TestObserveFakeProcIdentityAndEnvironment(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		environ string
		want    []string
	}{
		{name: "no control variables", environ: "PATH=/usr/bin\x00HOME=/nonexistent\x00"},
		{name: "empty environment", environ: ""},
		{name: "names only, sorted", environ: "PYTHONPATH=" + observeSecret + "\x00NODE_OPTIONS=" + observeSecret + "\x00LD_PRELOAD=/x\x00OK=1\x00noequals\x00", want: []string{"LD_PRELOAD", "NODE_OPTIONS", "PYTHONPATH"}},
		{name: "empty value still counts", environ: "NODE_OPTIONS=\x00", want: []string{"NODE_OPTIONS"}},
		{name: "similar names are not control variables", environ: "NODE_OPTIONS_EXTRA=1\x00MY_LD_PRELOAD=1\x00", want: nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			f := newFakeProc(t)
			f.write(strconv.Itoa(fakePID)+"/environ", tt.environ)
			obs, err := f.observe()
			if err != nil {
				t.Fatalf("Observe = %v", err)
			}
			if obs.PID != fakePID || obs.UID != fakeUID || obs.StartTime != fakeStart || obs.BootID != fakeBootID {
				t.Fatalf("identity = %+v", obs)
			}
			if obs.ExecutableSHA256 != sha256Hex([]byte(fakeExeBody)) {
				t.Fatalf("executable digest = %q", obs.ExecutableSHA256)
			}
			if strings.Join(obs.ControlEnvironment, ",") != strings.Join(tt.want, ",") {
				t.Fatalf("control environment = %v, want %v", obs.ControlEnvironment, tt.want)
			}
			if rendered := fmt.Sprintf("%+v", obs); strings.Contains(rendered, observeSecret) {
				t.Fatalf("observation leaks an environment value: %s", rendered)
			}
		})
	}
}

func TestObserveFakeProcErrors(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		setup   func(f *fakeProc)
		wantErr error
	}{
		{name: "no socket rows", setup: func(f *fakeProc) { f.writeTables("tcp", procNetHeader) }, wantErr: ErrSocketNotFound},
		{name: "no process holds the socket", setup: func(f *fakeProc) { f.remove(strconv.Itoa(fakePID) + "/fd/3") }, wantErr: ErrOwnerNotVisible},
		{name: "two processes hold the socket", setup: func(f *fakeProc) { f.addProcess(fakePID + 1) }, wantErr: ErrMultipleOwners},
		{name: "boot id unreadable", setup: func(f *fakeProc) { f.remove("sys/kernel/random/boot_id") }, wantErr: ErrOwnerNotVisible},
		{name: "status missing", setup: func(f *fakeProc) { f.remove(strconv.Itoa(fakePID) + "/status") }, wantErr: ErrOwnerChanged},
		{name: "executable unreadable", setup: func(f *fakeProc) { f.remove(strconv.Itoa(fakePID) + "/exe") }, wantErr: ErrOwnerNotVisible},
		{name: "fd table unreadable", setup: func(f *fakeProc) {
			f.remove(strconv.Itoa(fakePID) + "/fd")
			f.write(strconv.Itoa(fakePID)+"/fd", "")
		}, wantErr: ErrOwnerNotVisible},
		{name: "environment unreadable", setup: func(f *fakeProc) { f.remove(strconv.Itoa(fakePID) + "/environ") }, wantErr: ErrOwnerNotVisible},
		{name: "environment larger than the bound", setup: func(f *fakeProc) {
			f.write(strconv.Itoa(fakePID)+"/environ", strings.Repeat("A", environMaxBytes+1))
		}, wantErr: ErrOwnerNotVisible},
		{name: "start time changes between the reads", setup: func(f *fakeProc) {
			f.v.beforeRecheck = func() { f.write(strconv.Itoa(fakePID)+"/stat", statText("svc", fakeStart+1)) }
		}, wantErr: ErrOwnerChanged},
		{name: "socket descriptor goes away between the reads", setup: func(f *fakeProc) {
			f.v.beforeRecheck = func() { f.remove(strconv.Itoa(fakePID) + "/fd/3") }
		}, wantErr: ErrOwnerChanged},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			f := newFakeProc(t)
			tt.setup(f)
			obs, err := f.observe()
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Observe = %v, want %v", err, tt.wantErr)
			}
			if obs.PID != 0 || obs.ExecutableSHA256 != "" || len(obs.Files) != 0 || len(obs.ControlEnvironment) != 0 {
				t.Fatalf("failure returned partial observation %+v", obs)
			}
		})
	}
}

func TestObserveRealProcess(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		hold    string
		env     []string
		wantEnv []string
	}{
		{name: "native process"},
		{name: "pinned file held as a descriptor", hold: holdFD},
		{name: "pinned file held as a mapping", hold: holdMmap},
		{name: "control variable names are reported, not values", env: []string{"NODE_OPTIONS=" + observeSecret, "PYTHONPATH=" + observeSecret}, wantEnv: []string{"NODE_OPTIONS", "PYTHONPATH"}},
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
			conn := dialAccepted(t, h, "")
			obs, err := NewVerifier().Observe(context.Background(), conn)
			if err != nil {
				t.Fatalf("Observe = %v", err)
			}
			pin := basePin(t)
			if obs.PID != h.cmd.Process.Pid || obs.UID != pin.PrincipalUID || obs.ExecutableSHA256 != pin.ExecutableSHA256 {
				t.Fatalf("observation = %+v, want pid %d uid %d exe %s", obs, h.cmd.Process.Pid, pin.PrincipalUID, pin.ExecutableSHA256)
			}
			if obs.StartTime == 0 || obs.BootID == "" {
				t.Fatalf("observation lacks the incarnation: %+v", obs)
			}
			if strings.Join(obs.ControlEnvironment, ",") != strings.Join(tt.wantEnv, ",") {
				t.Fatalf("control environment = %v, want %v", obs.ControlEnvironment, tt.wantEnv)
			}
			if strings.Contains(fmt.Sprintf("%+v", obs), observeSecret) {
				t.Fatalf("observation leaks an environment value: %+v", obs)
			}

			var found bool
			seen := map[[2]uint64]bool{}
			paths := make([]string, len(obs.Files))
			for i, file := range obs.Files {
				paths[i] = file.Path
				if !filepath.IsAbs(file.Path) {
					t.Fatalf("relative path %q", file.Path)
				}
				k := [2]uint64{file.Dev, file.Ino}
				if seen[k] {
					t.Fatalf("duplicate inode %v for %q", k, file.Path)
				}
				seen[k] = true
				if file.Path == path {
					found = true
					if file.SHA256 != sha256Hex([]byte(pinnedContent)) {
						t.Fatalf("pinned file digest = %q", file.SHA256)
					}
				}
			}
			if !sort.StringsAreSorted(paths) {
				t.Fatalf("paths are not sorted: %v", paths)
			}
			if found != (tt.hold != "") {
				t.Fatalf("pinned file reported = %v, held = %q, files = %v", found, tt.hold, paths)
			}
		})
	}
}

func TestObserveRetriesUntilAccept(t *testing.T) {
	t.Parallel()
	h := startServer(t, modeLateAccept, loopbackAny)
	counter := newAttemptCounter()
	v := NewVerifier()
	v.onAttempt = counter.hook
	conn := dialUnaccepted(t, h)

	ctx, cancel := context.WithTimeout(context.Background(), testwait.Deadline(30*time.Second))
	defer cancel()
	type result struct {
		obs Observation
		err error
	}
	out := make(chan result, 1)
	go func() {
		obs, err := v.Observe(ctx, conn)
		out <- result{obs, err}
	}()
	counter.waitSecond(t)
	h.acceptNow(t)

	select {
	case r := <-out:
		if r.err != nil {
			t.Fatalf("Observe = %v, want success once the server accepts", r.err)
		}
		if r.obs.PID != h.cmd.Process.Pid {
			t.Fatalf("observed pid = %d, want %d", r.obs.PID, h.cmd.Process.Pid)
		}
	case <-time.After(testwait.Deadline(30 * time.Second)):
		t.Fatal("timed out waiting for Observe")
	}
}

func TestObserveNeverAcceptedFailsAtCap(t *testing.T) {
	t.Parallel()
	h := startServer(t, modeNoAccept, loopbackAny)
	v := NewVerifier()
	v.retryCap = 100 * time.Millisecond
	conn := dialUnaccepted(t, h)
	obs, err := v.Observe(context.Background(), conn)
	if !errors.Is(err, ErrSocketNotFound) {
		t.Fatalf("Observe = %v, want ErrSocketNotFound at the cap", err)
	}
	if obs.PID != 0 {
		t.Fatalf("failure returned %+v", obs)
	}
}

func TestObserveRefusesForwarder(t *testing.T) {
	t.Parallel()
	backend := startServer(t, modeServe, loopbackAny)
	fwd := startServer(t, modeForward, loopbackAny, envUpstream+"="+backend.addr)
	conn := dialAccepted(t, fwd, "")
	obs, err := NewVerifier().Observe(context.Background(), conn)
	if err != nil {
		t.Fatalf("Observe = %v", err)
	}
	if obs.PID != fwd.cmd.Process.Pid {
		t.Fatalf("observed pid = %d, want the forwarder %d, not the backend %d", obs.PID, fwd.cmd.Process.Pid, backend.cmd.Process.Pid)
	}
}

func TestObserveNotLoopback(t *testing.T) {
	t.Parallel()
	conn := addrConn{
		l: &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 1},
		r: &net.TCPAddr{IP: net.ParseIP("192.0.2.2"), Port: 2},
	}
	_, err := (&Verifier{procRoot: filepath.Join(t.TempDir(), "absent")}).Observe(context.Background(), conn)
	if !errors.Is(err, ErrNotLoopback) {
		t.Fatalf("Observe = %v, want ErrNotLoopback", err)
	}
}

func TestObserveFilesHelpers(t *testing.T) {
	t.Parallel()
	if hasAnyPrefix("/opt/x", nonFilePrefixes) {
		t.Fatal("/opt/x must not be a non-file path")
	}
	for _, p := range []string{"/dev/null", "/proc/1/maps", "/sys/x", "/memfd:x", "/SYSV1"} {
		if !hasAnyPrefix(p, nonFilePrefixes) {
			t.Fatalf("%s must be a non-file path", p)
		}
	}
	missing := filepath.Join(t.TempDir(), "absent")
	if file, verified := hashIfSameInode(ObservedFile{Path: missing}, heldFile{}, nil); verified || file.SHA256 != "" || file.Path != missing {
		t.Fatalf("hashIfSameInode(missing) = %+v", file)
	}
	dir := t.TempDir()
	if file, verified := hashIfSameInode(ObservedFile{Path: dir}, heldFile{}, nil); verified || file.SHA256 != "" || file.Path != "" {
		t.Fatalf("hashIfSameInode(dir) = %+v; want an empty observation", file)
	}
	unreadable := filepath.Join(t.TempDir(), "locked")
	if err := os.WriteFile(unreadable, []byte("x"), 0o000); err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() != 0 {
		if file, verified := hashIfSameInode(ObservedFile{Path: unreadable}, heldFile{}, nil); verified || file.SHA256 != "" || file.Path != unreadable {
			t.Fatalf("hashIfSameInode(unreadable) = %+v", file)
		}
	}
}

// The maps-identity seam models filesystem identity reports without requiring
// a particular filesystem. These cases must run serially while it is replaced.
func TestObserveFilesIdentityReconciliation(t *testing.T) {
	restore := mapsIdentity
	t.Cleanup(func() { mapsIdentity = restore })

	const content = "observed identity"
	for _, name := range []string{
		"equal stat and maps devices",
		"different stat and maps devices",
		"mapping before descriptor",
		"same inode number on different devices",
		"unverified descriptors with same inode number on different devices",
		"same maps identity at different paths",
		"unverified maps identity at different paths",
		"unverified mapping does not hide verified descriptor",
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "a.bin")
			if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			dev, ino := fileIdent(t, path)
			fd := heldFile{dev: dev, ino: ino, path: path}
			mapping := heldFile{dev: dev, ino: ino, path: path, mapped: true}
			if name != "equal stat and maps devices" {
				mapping.dev = dev ^ 1
			}
			ids := map[string]heldFile{path: mapping}
			mapsIdentity = func(f *os.File, _ int64) (heldFile, bool) {
				id, ok := ids[f.Name()]
				return id, ok
			}
			held := []heldFile{fd, mapping, mapping}
			want := []ObservedFile{{Path: path, Dev: dev, Ino: ino, SHA256: sha256Hex([]byte(content))}}
			switch name {
			case "mapping before descriptor":
				held = []heldFile{mapping, fd, mapping}
			case "same inode number on different devices", "unverified descriptors with same inode number on different devices", "same maps identity at different paths", "unverified maps identity at different paths":
				otherPath := filepath.Join(dir, "b.bin")
				if err := os.WriteFile(otherPath, []byte(content), 0o600); err != nil {
					t.Fatal(err)
				}
				otherDev, otherIno := fileIdent(t, otherPath)
				if otherDev == dev && otherIno == ino {
					t.Fatal("test requires two distinct files")
				}
				otherMapping := mapping
				otherMapping.path = otherPath
				if name == "same inode number on different devices" || name == "unverified descriptors with same inode number on different devices" {
					otherMapping.dev = mapping.dev ^ 2
				}
				ids[otherPath] = otherMapping
				held = []heldFile{otherMapping, mapping, otherMapping, mapping}
				want = append(want, ObservedFile{Path: otherPath, Dev: otherDev, Ino: otherIno, SHA256: sha256Hex([]byte(content))})
				if name == "unverified maps identity at different paths" {
					clear(ids)
					want[0] = ObservedFile{Path: path, Dev: mapping.dev, Ino: mapping.ino}
					want[1] = ObservedFile{Path: otherPath, Dev: otherMapping.dev, Ino: otherMapping.ino}
				}
				if name == "unverified descriptors with same inode number on different devices" {
					mapping.mapped, otherMapping.mapped = false, false
					held = []heldFile{otherMapping, mapping}
					want[0] = ObservedFile{Path: path, Dev: mapping.dev, Ino: mapping.ino}
					want[1] = ObservedFile{Path: otherPath, Dev: otherMapping.dev, Ino: otherMapping.ino}
				}
			case "unverified mapping does not hide verified descriptor":
				mapping.dev = dev
				clear(ids)
				held = []heldFile{mapping, fd}
				want = append([]ObservedFile{{Path: path, Dev: dev, Ino: ino}}, want...)
			}
			if got := observeFiles(held); !reflect.DeepEqual(got, want) {
				t.Fatalf("observeFiles = %+v, want %+v", got, want)
			}
		})
	}
}

func TestObserveOpenedFileErrors(t *testing.T) {
	restore := mapsIdentity
	t.Cleanup(func() { mapsIdentity = restore })
	for _, name := range []string{"stat fails", "hash fails", "seen inode skips hashing"} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "bundle.bin")
			if err := os.WriteFile(path, []byte(pinnedContent), 0o600); err != nil {
				t.Fatal(err)
			}
			dev, ino := fileIdent(t, path)
			file := ObservedFile{Path: path, Dev: dev ^ 1, Ino: ino}
			held := heldFile{path: path, dev: file.Dev, ino: ino, mapped: true}
			want := file
			wantVerified := name != "stat fails"
			seen := map[observedFileKey]bool{}
			if name == "seen inode skips hashing" {
				seen[observedFileKey{dev: dev, ino: ino}] = true
			}
			opened, err := os.Open(filepath.Clean(path))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = opened.Close() })
			if name == "stat fails" {
				if err := opened.Close(); err != nil {
					t.Fatal(err)
				}
			} else {
				want.Dev = dev
				mapsIdentity = func(f *os.File, _ int64) (heldFile, bool) {
					if name == "hash fails" {
						if err := f.Close(); err != nil {
							t.Fatal(err)
						}
					}
					return held, true
				}
			}
			if got, verified := hashOpenedIfSameInode(file, held, opened, seen); got != want || verified != wantVerified {
				t.Fatalf("hashOpenedIfSameInode = %+v, %v; want %+v, %v", got, verified, want, wantVerified)
			}
		})
	}
}
