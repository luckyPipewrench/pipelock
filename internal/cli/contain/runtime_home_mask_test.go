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

func TestRuntimeProtectHomeMask(t *testing.T) {
	for _, tc := range []struct {
		name, root, device, options, filesystem, extra, hostExtra, want string
		off, missing                                                    bool
		contentsErr                                                     error
		entryMode                                                       os.FileMode
		nonempty                                                        bool
	}{
		{name: "enforce clean"},
		{name: "enforce unreadable", contentsErr: os.ErrPermission, want: "must be listable"},
		{name: "host shared tmpfs root", hostExtra: "12 1 0:202 / /srv/shared rw - tmpfs tmpfs rw,mode=711\n", want: "shared with a host mount"},
		{name: "off rejects mask", off: true, want: "/run/user"},
		{name: "missing mask", missing: true, want: "requested read-only tmpfs"},
		{name: "child mount", extra: "25 24 0:50 /dbus /run/user/dbus ro - tmpfs tmpfs rw\n", want: "/run/user/dbus"},
		{name: "writable mask", options: "rw,nodev", want: "read-only tmpfs"},
		{name: "wrong root", root: "/other", want: "tmpfs mask with root /"},
		{name: "wrong filesystem", filesystem: "ext4", want: "tmpfs mask"},
		{name: "host run device", device: "0:50", want: "distinct from host /run"},
		{name: "nonempty mask", nonempty: true, want: "/run/user/socket"},
		{name: "mask file", entryMode: 0o600, want: "/run/user must be a directory"},
		{name: "contents io error", contentsErr: errors.New("read io failure"), want: "cannot be verified"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root, device, options, fs := tc.root, tc.device, tc.options, tc.filesystem
			if root == "" {
				root = "/"
			}
			if device == "" {
				device = "0:202"
			}
			if options == "" {
				options = "ro,nodev"
			}
			if fs == "" {
				fs = "tmpfs"
			}
			mounts := managedRuntimeMountFixture
			if !tc.missing {
				mounts += fmt.Sprintf("24 20 %s %s /run/user %s - %s tmpfs rw\n", device, root, options, fs)
			}
			mounts += tc.extra
			mode := tc.entryMode
			if mode == 0 {
				mode = os.ModeDir | 0o755
			}
			tree := fstest.MapFS{"pipelock-contain/agent-netns.id": &fstest.MapFile{Mode: 0o600}, "user": &fstest.MapFile{Mode: mode}}
			if tc.nonempty {
				tree["user/socket"] = &fstest.MapFile{Mode: os.ModeSocket}
			}
			env := defaultNetnsAssertEnv()
			env.unitProperties = nil
			if !tc.off {
				env.unitProperties = []string{protectHomeTmpfsProperty}
			}
			env.readFile = func(path string) ([]byte, error) {
				if path == "/proc/self/mountinfo" {
					return []byte(mounts), nil
				}
				return []byte(hostRuntimeMountFixture + tc.hostExtra), nil
			}
			env.readDir = func(path string) ([]os.DirEntry, error) {
				if path == "/run/user" && tc.contentsErr != nil {
					return nil, tc.contentsErr
				}
				return tree.ReadDir(strings.TrimPrefix(path, "/run/"))
			}
			baseReader := env.readDir
			env.readDir = func(path string) ([]os.DirEntry, error) {
				if path == "/run" {
					return tree.ReadDir(".")
				}
				return baseReader(path)
			}
			err := assertManagedRuntimeMounts(env)
			if tc.want == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error=%v, want %q", err, tc.want)
			}
			if !tc.off && !errors.Is(err, errRuntimeMountEvidenceUnavailable) && (!strings.Contains(err.Error(), "retain the managed ProtectHome=tmpfs profile") || strings.Contains(err.Error(), "remove the extra bind")) {
				t.Fatalf("misleading managed-mask remedy: %v", err)
			}
		})
	}
}

func TestRuntimeHostInventoryIgnoresUnconsultedChildren(t *testing.T) {
	// A child is mounted, its parent is overmounted, and a new child appears at
	// the same path. Both children are real mountinfo records but aren't stacked.
	extra := "30 10 0:202 / /run/user/1000/probe rw - tmpfs tmpfs rw\n" +
		"31 30 0:203 / /run/user/1000/probe/doc rw - tmpfs tmpfs rw\n" +
		"32 30 0:204 / /run/user/1000/probe rw - tmpfs tmpfs rw\n" +
		"33 32 0:205 / /run/user/1000/probe/doc rw - tmpfs tmpfs rw\n"
	env := defaultNetnsAssertEnv()
	env.unitProperties = nil
	env.readFile = func(path string) ([]byte, error) {
		if path == "/proc/self/mountinfo" {
			return []byte(managedRuntimeMountFixture), nil
		}
		return []byte(hostRuntimeMountFixture + extra), nil
	}
	env.readDir = managedRuntimeFixtureReadDir
	if err := assertManagedRuntimeMounts(env); err != nil {
		t.Fatal(err)
	}
	env.readFile = func(string) ([]byte, error) { return []byte(managedRuntimeMountFixture + extra), nil }
	if _, err := readRuntimeMounts(env, "/proc/self/mountinfo"); err == nil || !strings.Contains(err.Error(), "ambiguous runtime mount evidence") {
		t.Fatalf("self inventory lost ambiguity check: %v", err)
	}
}

func TestRuntimePrivateMasksRejectHostSharedDevices(t *testing.T) {
	// Each private mask is bound from another host tmpfs root: root /, tmpfs,
	// a device distinct from the host mount at the same path, yet still shared.
	for _, tc := range []struct{ name, hostExtra, want string }{
		{name: "dev shm", hostExtra: "12 1 0:201 / /srv/shm rw - tmpfs tmpfs rw\n", want: "/dev/shm does not have a verified private filesystem identity"},
		{name: "run", hostExtra: "12 1 0:200 / /srv/run rw - tmpfs tmpfs rw\n", want: "/run does not have a verified private filesystem identity"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := defaultNetnsAssertEnv()
			env.unitProperties = nil
			env.readFile = func(path string) ([]byte, error) {
				if path == "/proc/self/mountinfo" {
					return []byte(managedRuntimeMountFixture), nil
				}
				return []byte(hostRuntimeMountFixture + tc.hostExtra), nil
			}
			env.readDir = managedRuntimeFixtureReadDir
			err := assertManagedRuntimeMounts(env)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error=%v, want %q", err, tc.want)
			}
			// The property is already present, so the remedy must name the
			// shared bind rather than ask for the property again.
			if !errors.Is(err, errUnexpectedRuntimeExposure) || !strings.Contains(err.Error(), "remove the extra bind") {
				t.Fatalf("host-shared mask must report an exposure remedy: %v", err)
			}
		})
	}
}
