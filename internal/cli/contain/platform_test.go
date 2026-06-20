// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestParseOSRelease(t *testing.T) {
	fields := parseOSRelease([]byte(`
# comment
ID="ubuntu"
ID_LIKE='debian rhel'
BROKEN
 NAME = "ignored-key-with-space"
`))
	if fields["ID"] != "ubuntu" {
		t.Fatalf("ID: got %q, want ubuntu", fields["ID"])
	}
	if fields["ID_LIKE"] != "debian rhel" {
		t.Fatalf("ID_LIKE: got %q, want debian rhel", fields["ID_LIKE"])
	}
	if _, ok := fields["BROKEN"]; ok {
		t.Fatalf("malformed line was parsed: %#v", fields)
	}
}

func TestDetectContainPlatformUsesIDLikeAndDistroCABundle(t *testing.T) {
	stat := fakeContainStat(map[string]os.FileMode{
		"/etc/pki/tls/certs/ca-bundle.crt": 0o644,
		"/usr/bin/bash":                    0o755,
		"/usr/sbin/nologin":                0o755,
		"/usr/sbin/nft":                    0o755,
		"/usr/bin/curl":                    0o755,
	})
	readFile := func(path string) ([]byte, error) {
		if path == "/etc/os-release" {
			return []byte("ID=linux\nID_LIKE=\"rhel fedora\"\n"), nil
		}
		return nil, os.ErrNotExist
	}
	lookPath := func(name string) (string, error) {
		if name == "nft" {
			return "/custom/sbin/nft", nil
		}
		return "", errors.New("not found")
	}

	got := detectContainPlatform(readFile, stat, lookPath)
	if got.family != platformFamilyRHEL {
		t.Fatalf("family: got %q, want %q", got.family, platformFamilyRHEL)
	}
	if got.systemCABundlePath != "/etc/pki/tls/certs/ca-bundle.crt" {
		t.Fatalf("systemCABundlePath: got %q", got.systemCABundlePath)
	}
	if got.nftPath != "/usr/sbin/nft" {
		t.Fatalf("nftPath: got %q, want vetted candidate", got.nftPath)
	}
}

func TestDetectContainPlatformFallsBackToLookPathForNFT(t *testing.T) {
	readFile := func(path string) ([]byte, error) {
		if path == "/etc/os-release" {
			return []byte("ID=unknown\n"), nil
		}
		return nil, os.ErrNotExist
	}

	got := detectContainPlatform(readFile, fakeContainStat(nil), fakeContainLookPath(map[string]string{
		"nft": "/opt/nft/bin/nft",
	}))
	if got.nftPath != "/opt/nft/bin/nft" {
		t.Fatalf("nftPath: got %q, want lookPath fallback", got.nftPath)
	}
}

func TestDetectContainPlatformSUSECABundle(t *testing.T) {
	stat := fakeContainStat(map[string]os.FileMode{
		"/var/lib/ca-certificates/ca-bundle.pem": 0o644,
	})
	readFile := func(path string) ([]byte, error) {
		if path == "/usr/lib/os-release" {
			return []byte("ID=opensuse-tumbleweed\n"), nil
		}
		return nil, os.ErrNotExist
	}

	got := detectContainPlatform(readFile, stat, fakeContainLookPath(nil))
	if got.family != platformFamilySUSE {
		t.Fatalf("family: got %q, want %q", got.family, platformFamilySUSE)
	}
	if got.systemCABundlePath != "/var/lib/ca-certificates/ca-bundle.pem" {
		t.Fatalf("systemCABundlePath: got %q", got.systemCABundlePath)
	}
}

func TestDetectContainPlatformGenericFallbacks(t *testing.T) {
	got := detectContainPlatform(
		func(string) ([]byte, error) { return nil, os.ErrNotExist },
		fakeContainStat(nil),
		fakeContainLookPath(nil),
	)
	if got.family != platformFamilyGeneric {
		t.Fatalf("family: got %q, want %q", got.family, platformFamilyGeneric)
	}
	if got.systemCABundlePath != defaultSystemCABundle {
		t.Fatalf("systemCABundlePath: got %q, want %q", got.systemCABundlePath, defaultSystemCABundle)
	}
	if got.bashPath != "/usr/bin/bash" {
		t.Fatalf("bashPath: got %q, want first candidate", got.bashPath)
	}
}

func fakeContainLookPath(paths map[string]string) func(string) (string, error) {
	return func(name string) (string, error) {
		if paths != nil {
			if path, ok := paths[name]; ok {
				return path, nil
			}
		}
		return "", errors.New("not found")
	}
}

func fakeContainStat(paths map[string]os.FileMode) func(string) (os.FileInfo, error) {
	return func(path string) (os.FileInfo, error) {
		mode, ok := paths[filepath.Clean(path)]
		if !ok {
			return nil, os.ErrNotExist
		}
		return containFileInfo{name: filepath.Base(path), mode: mode}, nil
	}
}

type containFileInfo struct {
	name string
	mode os.FileMode
}

func (i containFileInfo) Name() string       { return i.name }
func (i containFileInfo) Size() int64        { return 1 }
func (i containFileInfo) Mode() os.FileMode  { return i.mode }
func (i containFileInfo) ModTime() time.Time { return time.Time{} }
func (i containFileInfo) IsDir() bool        { return i.mode.IsDir() }
func (i containFileInfo) Sys() any           { return nil }
