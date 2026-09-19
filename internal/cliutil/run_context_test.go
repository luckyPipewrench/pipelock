// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package cliutil

import (
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
