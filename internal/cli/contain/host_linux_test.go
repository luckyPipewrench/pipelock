// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package contain

import (
	"errors"
	"os"
	"strings"
	"testing"
)

func TestRequireContainHostWith(t *testing.T) {
	tests := []struct {
		name    string
		markers map[string]bool
		pidOne  string
		want    string
	}{
		{name: "supported host", pidOne: "systemd\n"},
		{name: "docker container", markers: map[string]bool{"/.dockerenv": true}, pidOne: "systemd\n", want: "container marker /.dockerenv is present"},
		{name: "init image", pidOne: "pipelock\n", want: `PID 1 is "pipelock", not systemd`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stat := func(path string) (os.FileInfo, error) {
				if tt.markers[path] {
					return containFileInfo{name: path}, nil
				}
				return nil, os.ErrNotExist
			}
			err := requireContainHostWith(stat, func(path string) ([]byte, error) {
				if path == "/proc/1/cgroup" {
					return []byte("0::/\n"), nil
				}
				return []byte(tt.pidOne), nil
			})
			if tt.want == "" {
				if err != nil {
					t.Fatalf("requireContainHostWith: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want %q", err, tt.want)
			}
			if !strings.Contains(err.Error(), "Run this command on the host instead") {
				t.Fatalf("operator remedy missing from %q", err)
			}
		})
	}
}

func TestContainerCgroup(t *testing.T) {
	for _, tt := range []struct {
		cgroup string
		want   bool
	}{
		{cgroup: "0::/", want: false},
		{cgroup: "0::/kubepods.slice/pod-id", want: true},
		{cgroup: "0::/docker/012345", want: true},
		{cgroup: "0::/system.slice/docker-012345.scope", want: true},
		{cgroup: "0::/system.slice/cri-containerd-012345.scope", want: true},
		{cgroup: "0::/system.slice/crio-012345.scope", want: true},
		{cgroup: "0::/machine.slice/libpod-deadbeef.scope", want: true},
	} {
		if got := containerCgroup(tt.cgroup); got != tt.want {
			t.Errorf("containerCgroup(%q) = %v, want %v", tt.cgroup, got, tt.want)
		}
	}
}

func TestRequireContainHostWithRefusesUnreadableMarker(t *testing.T) {
	err := requireContainHostWith(
		func(path string) (os.FileInfo, error) {
			if path == "/.dockerenv" {
				return nil, errors.New("permission denied")
			}
			return nil, os.ErrNotExist
		},
		func(string) ([]byte, error) { return []byte("systemd\n"), nil },
	)
	if err == nil || !strings.Contains(err.Error(), "cannot inspect container marker /.dockerenv") || !strings.Contains(err.Error(), "Run this command on the host instead") {
		t.Fatalf("error = %v, want fail-closed marker refusal with remedy", err)
	}
}

func TestRequireContainHostWithRefusesUnreadableInit(t *testing.T) {
	err := requireContainHostWith(
		func(string) (os.FileInfo, error) { return nil, os.ErrNotExist },
		func(string) ([]byte, error) { return nil, errors.New("denied") },
	)
	if err == nil || !strings.Contains(err.Error(), "cannot inspect host init process") || !strings.Contains(err.Error(), "Run this command on the host instead") {
		t.Fatalf("error = %v, want actionable unreadable init refusal", err)
	}
}

func TestRequireContainHostWithRefusesUnreadableCgroup(t *testing.T) {
	err := requireContainHostWith(
		func(string) (os.FileInfo, error) { return nil, os.ErrNotExist },
		func(path string) ([]byte, error) {
			if path == "/proc/1/cgroup" {
				return nil, errors.New("permission denied")
			}
			return []byte("systemd\n"), nil
		},
	)
	if err == nil || !strings.Contains(err.Error(), "cannot inspect host cgroup") || !strings.Contains(err.Error(), "Run this command on the host instead") {
		t.Fatalf("error = %v, want actionable unreadable cgroup refusal", err)
	}
}
