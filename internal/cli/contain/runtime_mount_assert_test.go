// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package contain

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"testing/fstest"
)

func TestRuntimeMountSystemdPropagation(t *testing.T) {
	for _, parent := range []string{"systemd", "host"} {
		t.Run(parent, func(t *testing.T) {
			for _, tc := range []struct {
				name, root, options, want              string
				missingMount, unreadable               bool
				extraMount, cgroup, device, filesystem string
				missingStat, unknownOwner              bool
				statMode                               os.FileMode
				uid                                    uint32
				statErr, contentsErr                   error
				mutate                                 func(fstest.MapFS)
			}{
				{name: "documented layout"},
				{name: "unknown run entry", mutate: func(tree fstest.MapFS) {
					tree["extra-probe"] = &fstest.MapFile{}
				}, want: "/run must contain only"},
				{name: "unknown run directory", mutate: func(tree fstest.MapFS) {
					tree["extra-probe"] = &fstest.MapFile{Mode: os.ModeDir}
				}, want: "/run must contain only"},
				{name: "missing propagation mount", missingMount: true, want: "own systemd propagation mount"},
				{name: "host run bind", root: "/", want: "mount root must be under"},
				{name: "other root", root: "/unrelated/probe.service", want: "mount root must be under"},
				{name: "root prefix boundary", root: "/systemd/propagate-other/probe.service", want: "mount root must be under"},
				{name: "propagate root itself", root: "/systemd/propagate", want: "mount root must be under"},
				{name: "root traversal", root: "/systemd/propagate/../other", want: "mount root must be under"},
				{name: "writable propagation mount", options: "rw,nosuid,nodev", want: "must be read-only"},
				{name: "socket sibling", mutate: func(tree fstest.MapFS) {
					tree[parent+"/socket"] = &fstest.MapFile{Mode: os.ModeSocket}
				}, want: "must contain only incoming"},
				{name: "file sibling", mutate: func(tree fstest.MapFS) {
					tree[parent+"/z-file"] = &fstest.MapFile{}
				}, want: "must contain only incoming"},
				{name: "directory sibling", mutate: func(tree fstest.MapFS) {
					tree[parent+"/other"] = &fstest.MapFile{Mode: os.ModeDir}
				}, want: "must contain only incoming"},
				{name: "incoming file", mutate: func(tree fstest.MapFS) {
					tree[parent+"/incoming"] = &fstest.MapFile{}
				}, want: "must contain only incoming"},
				{name: "incoming symlink", mutate: func(tree fstest.MapFS) {
					tree[parent+"/incoming"] = &fstest.MapFile{Mode: os.ModeSymlink}
				}, want: "must contain only incoming"},
				{name: "parent file", mutate: func(tree fstest.MapFS) {
					delete(tree, parent+"/incoming")
					tree[parent] = &fstest.MapFile{}
				}, want: "/run must contain only"},
				{name: "parent symlink", mutate: func(tree fstest.MapFS) {
					delete(tree, parent+"/incoming")
					tree[parent] = &fstest.MapFile{Mode: os.ModeSymlink}
				}, want: "/run must contain only"},
				{name: "wrong child name", mutate: func(tree fstest.MapFS) {
					delete(tree, parent+"/incoming")
					tree[parent+"/other"] = &fstest.MapFile{Mode: os.ModeDir}
				}, want: "must contain only incoming"},
				{name: "missing namespace identity directory", mutate: func(tree fstest.MapFS) {
					delete(tree, "pipelock-contain/agent-netns.id")
				}, want: "cannot be verified"},
				{name: "unreadable parent", unreadable: true, want: "cannot be verified"},
				{name: "dbus descendant mount", extraMount: "24 23 0:50 /dbus /run/systemd/incoming/dbus ro - tmpfs tmpfs rw\n", want: "/run/systemd/incoming/dbus"},
				{name: "host run descendant mount", extraMount: "24 23 0:50 / /run/systemd/incoming/hostrun rw - tmpfs tmpfs rw\n", want: "/run/systemd/incoming/hostrun"},
				{name: "shm descendant mount", extraMount: "24 21 0:50 /dbus /dev/shm/dbus ro - tmpfs tmpfs rw\n", want: "/dev/shm/dbus"},
				{name: "var run descendant mount", extraMount: "24 20 0:50 /dbus /var/run/dbus ro - tmpfs tmpfs rw\n", want: "/var/run/dbus"},
				{name: "escaped descendant mount", extraMount: `24 23 0:50 /dbus /run/systemd/incoming/has\040space ro - tmpfs tmpfs rw` + "\n", want: "/run/systemd/incoming/has space"},
				{name: "socket inside incoming", mutate: func(tree fstest.MapFS) { tree[parent+"/incoming/socket"] = &fstest.MapFile{Mode: os.ModeSocket} }, want: "/run/systemd/incoming/socket"},
				{name: "file inside incoming", mutate: func(tree fstest.MapFS) { tree[parent+"/incoming/file"] = &fstest.MapFile{} }, want: "/run/systemd/incoming/file"},
				{name: "directory inside incoming", mutate: func(tree fstest.MapFS) { tree[parent+"/incoming/dir"] = &fstest.MapFile{Mode: os.ModeDir} }, want: "/run/systemd/incoming/dir"},
				{name: "other unit root", root: "/systemd/propagate/other.service", want: "does not match this unit"},
				{name: "non host device", device: "0:99", filesystem: "ext4", want: "device must match host /run"},
				{name: "group readable incoming", statMode: os.ModeDir | 0o640, want: "no group or other permissions"},
				{name: "other searchable incoming", statMode: os.ModeDir | 0o601, want: "no group or other permissions"},
				{name: "non root incoming", uid: 987, want: "root-owned directory"},
				{name: "stat incoming symlink", statMode: os.ModeSymlink | 0o600, want: "root-owned directory"},
				{name: "missing stat reader", missingStat: true, want: "cannot be verified"},
				{name: "unknown incoming owner", unknownOwner: true, want: "root-owned directory"},
				{name: "stat unavailable", statErr: os.ErrPermission, want: "cannot be verified"},
				{name: "incoming unreadable", contentsErr: os.ErrPermission},
				{name: "incoming read io failure", contentsErr: errors.New("read io failure"), want: "cannot be verified"},
				{name: "hidden cgroup service", cgroup: "0::/\n"},
				{name: "legacy cgroup service", cgroup: "1:name=systemd:/system.slice/probe.service\n"},
			} {
				t.Run(tc.name, func(t *testing.T) {
					tree := fstest.MapFS{
						"pipelock-contain/agent-netns.id": &fstest.MapFile{Mode: 0o600},
						parent + "/incoming":              &fstest.MapFile{Mode: os.ModeDir | 0o600},
					}
					if tc.mutate != nil {
						tc.mutate(tree)
					}
					root, options := tc.root, tc.options
					if root == "" {
						root = systemdPropagationRoot + "probe.service"
					}
					if options == "" {
						options = "ro,nosuid,nodev"
					}
					mounts := managedRuntimeMountFixture
					filesystem := tc.filesystem
					if filesystem == "" {
						filesystem = "tmpfs"
					}
					device := tc.device
					if device == "" {
						device = "0:50"
					}
					if !tc.missingMount {
						mounts += fmt.Sprintf("23 20 %s %s /run/%s/incoming %s master:12 - %s tmpfs rw\n", device, root, parent, options, filesystem)
					}
					mounts += tc.extraMount
					env := defaultNetnsAssertEnv()
					env.lstat = func(string) (os.FileInfo, error) {
						if tc.statErr != nil {
							return nil, tc.statErr
						}
						mode := tc.statMode
						if mode == 0 {
							mode = os.ModeDir | 0o600
						}
						sys := fakeFileSysWithUID(tc.uid)
						if tc.unknownOwner {
							sys = nil
						}
						return fakeFileInfo{mode: mode, sys: sys}, nil
					}
					if tc.missingStat {
						env.lstat = nil
					}
					env.readFile = func(path string) ([]byte, error) {
						if path == "/proc/self/cgroup" {
							cgroup := tc.cgroup
							if cgroup == "" {
								cgroup = "0::/system.slice/probe.service\n"
							}
							return []byte(cgroup), nil
						}
						if path == "/proc/self/mountinfo" {
							return []byte(mounts), nil
						}
						return managedRuntimeFixtureReadFile(path)
					}
					env.readDir = func(path string) ([]os.DirEntry, error) {
						if tc.unreadable && path == "/run/"+parent {
							return nil, os.ErrPermission
						}
						if path == systemdIncomingPath && tc.contentsErr != nil {
							return nil, tc.contentsErr
						}
						name := strings.TrimPrefix(path, "/run/")
						if path == "/run" {
							name = "."
						}
						return tree.ReadDir(name)
					}
					want := tc.want
					if parent == "host" {
						want = "unexpected runtime exposure"
					}
					err := assertManagedRuntimeMounts(env)
					if want == "" {
						if err != nil {
							t.Fatal(err)
						}
					} else if err == nil || !strings.Contains(err.Error(), want) {
						t.Fatalf("propagation refusal = %v, want %q", err, want)
					}
					if errors.Is(err, errUnexpectedRuntimeExposure) && (strings.Contains(err.Error(), "add TemporaryFileSystem=") || !strings.Contains(err.Error(), "remove the extra bind")) {
						t.Fatalf("wrong exposure remedy: %v", err)
					}
					if parent == "systemd" && tc.unreadable && !errors.Is(err, os.ErrPermission) {
						t.Fatalf("missing permission evidence: %v", err)
					}
				})
			}
		})
	}
}

func TestRuntimeMountPathEscapes(t *testing.T) {
	for _, tc := range []struct{ encoded, decoded string }{
		{`/run/has\040space`, "/run/has space"},
		{`/run/has\011tab`, "/run/has\ttab"},
		{`/run/has\012newline`, "/run/has\nnewline"},
		{`/systemd/propagate/probe\134x2dname.service`, `/systemd/propagate/probe\x2dname.service`},
	} {
		t.Run(tc.encoded, func(t *testing.T) {
			if got := runtimeMountPath(tc.encoded); got != tc.decoded {
				t.Fatalf("decoded mount path = %q, want %q", got, tc.decoded)
			}
		})
	}
}

func TestRuntimeMountBoundary(t *testing.T) {
	for _, root := range []string{"/run", "/var/run", "/dev/shm"} {
		for _, tc := range []struct {
			path string
			want bool
		}{
			{root, true},
			{root + "/child", true},
			{root + "-other/child", false},
		} {
			t.Run(tc.path, func(t *testing.T) {
				if got := isRuntimeMountPath(tc.path); got != tc.want {
					t.Fatalf("runtime mount classification = %t, want %t", got, tc.want)
				}
			})
		}
	}
}
