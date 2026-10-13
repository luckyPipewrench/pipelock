// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

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
				name, root, options, want string
				missingMount, unreadable  bool
				mutate                    func(fstest.MapFS)
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
			} {
				t.Run(tc.name, func(t *testing.T) {
					tree := fstest.MapFS{
						"pipelock-contain/agent-netns.id": &fstest.MapFile{Mode: 0o600},
						parent + "/incoming":              &fstest.MapFile{Mode: os.ModeDir | 0o700},
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
					if !tc.missingMount {
						mounts += fmt.Sprintf("23 20 0:50 %s /run/%s/incoming %s master:12 - tmpfs tmpfs rw\n", root, parent, options)
					}
					env := defaultNetnsAssertEnv()
					env.readFile = func(path string) ([]byte, error) {
						if path == "/proc/self/mountinfo" {
							return []byte(mounts), nil
						}
						return managedRuntimeFixtureReadFile(path)
					}
					env.readDir = func(path string) ([]os.DirEntry, error) {
						if tc.unreadable && path == "/run/"+parent {
							return nil, os.ErrPermission
						}
						name := strings.TrimPrefix(path, "/run/")
						if path == "/run" {
							name = "."
						}
						return tree.ReadDir(name)
					}
					err := assertManagedRuntimeMounts(env)
					if tc.want == "" {
						if err != nil {
							t.Fatal(err)
						}
					} else if err == nil || !strings.Contains(err.Error(), tc.want) {
						t.Fatalf("propagation refusal = %v, want %q", err, tc.want)
					}
					if tc.unreadable && !errors.Is(err, os.ErrPermission) {
						t.Fatalf("missing permission evidence: %v", err)
					}
				})
			}
		})
	}
}
