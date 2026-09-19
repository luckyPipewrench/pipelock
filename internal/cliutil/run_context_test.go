// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package cliutil

import (
	"errors"
	"io/fs"
	"slices"
	"testing"
	"testing/fstest"
)

func TestDetectRunContextRuntimeMarkers(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name           string
		kubernetesHost string
		files          fstest.MapFS
		want           string
	}{
		{name: "host without runtime files", files: fstest.MapFS{}, want: RunContextHost},
		{name: "host with unified cgroup", files: fstest.MapFS{
			"proc/1/cgroup": {Data: []byte("0::/\n")},
		}, want: RunContextHost},
		{name: "Docker marker", files: fstest.MapFS{".dockerenv": {}}, want: RunContextContainer},
		{name: "Podman marker with private cgroup namespace", files: fstest.MapFS{
			"run/.containerenv": {}, "proc/1/cgroup": {Data: []byte("0::/\n")},
		}, want: RunContextContainer},
		{name: "Podman marker without proc", files: fstest.MapFS{
			"run/.containerenv": {},
		}, want: RunContextContainer},
		{name: "Docker cgroup fallback", files: fstest.MapFS{
			"proc/1/cgroup": {Data: []byte("1:name=systemd:/docker/example\n")},
		}, want: RunContextContainer},
		{name: "containerd cgroup fallback", files: fstest.MapFS{
			"proc/1/cgroup": {Data: []byte("0::/containerd/example\n")},
		}, want: RunContextContainer},
		{name: "Kubernetes cgroup fallback", files: fstest.MapFS{
			"proc/1/cgroup": {Data: []byte("0::/kubepods/example\n")},
		}, want: RunContextContainer},
		{name: "Podman cgroup fallback", files: fstest.MapFS{
			"proc/1/cgroup": {Data: []byte("0::/machine.slice/libpod-example.scope\n")},
		}, want: RunContextContainer},
		{name: "legacy Podman name remains recognized", files: fstest.MapFS{
			"proc/1/cgroup": {Data: []byte("0::/podman/example\n")},
		}, want: RunContextContainer},
		{name: "CRI-O name remains recognized", files: fstest.MapFS{
			"proc/1/cgroup": {Data: []byte("0::/cri-o/example\n")},
		}, want: RunContextContainer},
		{name: "unrelated cgroup is host", files: fstest.MapFS{
			"proc/1/cgroup": {Data: []byte("0::/user.slice/user-1000.slice\n")},
		}, want: RunContextHost},
		{name: "Kubernetes environment has priority over Podman marker", kubernetesHost: "cluster.example", files: fstest.MapFS{
			"run/.containerenv": {},
		}, want: RunContextPod},
		{name: "Kubernetes environment has priority over Docker marker", kubernetesHost: "cluster.example", files: fstest.MapFS{
			".dockerenv": {},
		}, want: RunContextPod},
		{name: "Kubernetes without runtime files", kubernetesHost: "cluster.example", files: fstest.MapFS{}, want: RunContextPod},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := detectRunContext(tc.kubernetesHost, tc.files); got != tc.want {
				t.Fatalf("run context = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestDetectRunContextFilesystemErrors(t *testing.T) {
	t.Parallel()
	readFailure := errors.New("fixture cgroup read failure")
	for _, tc := range []struct {
		name           string
		kubernetesHost string
		files          fstest.MapFS
		failures       map[string]error
		want           string
		wantOpened     []string
	}{
		{
			name: "marker errors permit cgroup fallback",
			files: fstest.MapFS{
				"proc/1/cgroup": {Data: []byte("0::/machine.slice/libpod-example.scope\n")},
			},
			failures: map[string]error{
				".dockerenv": fs.ErrPermission, "run/.containerenv": fs.ErrPermission,
			},
			want: RunContextContainer, wantOpened: []string{".dockerenv", "run/.containerenv", "proc/1/cgroup"},
		},
		{
			name: "unreadable Docker marker permits Podman marker",
			files: fstest.MapFS{
				"run/.containerenv": {},
			},
			failures: map[string]error{".dockerenv": fs.ErrPermission, "proc/1/cgroup": readFailure},
			want:     RunContextContainer, wantOpened: []string{".dockerenv", "run/.containerenv"},
		},
		{
			name:     "missing markers and failed cgroup read retain host context",
			files:    fstest.MapFS{},
			failures: map[string]error{"proc/1/cgroup": readFailure},
			want:     RunContextHost, wantOpened: []string{".dockerenv", "run/.containerenv", "proc/1/cgroup"},
		},
		{
			name:  "all filesystem signals unavailable retain host context",
			files: fstest.MapFS{},
			failures: map[string]error{
				".dockerenv": fs.ErrPermission, "run/.containerenv": fs.ErrPermission, "proc/1/cgroup": readFailure,
			},
			want: RunContextHost, wantOpened: []string{".dockerenv", "run/.containerenv", "proc/1/cgroup"},
		},
		{
			name: "pod signal avoids unavailable filesystem", kubernetesHost: "cluster.example",
			files: fstest.MapFS{},
			failures: map[string]error{
				".dockerenv": fs.ErrPermission, "run/.containerenv": fs.ErrPermission, "proc/1/cgroup": readFailure,
			},
			want: RunContextPod,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			root := &runContextErrorFS{FS: tc.files, failures: tc.failures}
			if got := detectRunContext(tc.kubernetesHost, root); got != tc.want {
				t.Fatalf("run context = %q, want %q", got, tc.want)
			}
			if !slices.Equal(root.opened, tc.wantOpened) {
				t.Fatalf("filesystem accesses = %v, want %v", root.opened, tc.wantOpened)
			}
		})
	}
}

type runContextErrorFS struct {
	fs.FS
	failures map[string]error
	opened   []string
}

func (f *runContextErrorFS) Open(name string) (fs.File, error) {
	f.opened = append(f.opened, name)
	if err := f.failures[name]; err != nil {
		return nil, err
	}
	return f.FS.Open(name)
}
