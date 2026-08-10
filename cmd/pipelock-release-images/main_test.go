// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const testDigest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

type failWriter struct{ err error }

func (w failWriter) Write([]byte) (int, error) { return 0, w.err }

func validArgs(out string) []string {
	args := []string{
		"-tag", "v3.4.0",
		"-commit", strings.Repeat("a", 40),
	}
	if out != "" {
		args = append(args, "-out", out)
	}
	return append(args,
		"-image", "pipelock=ghcr.io/luckypipewrench/pipelock@"+testDigest,
		"-image", "pipelock-init=ghcr.io/luckypipewrench/pipelock-init@"+testDigest,
		"-image", "pipelock-license-service=ghcr.io/luckypipewrench/pipelock-license-service@"+testDigest,
	)
}

func TestRunWritesStableImageBundle(t *testing.T) {
	out := filepath.Join(t.TempDir(), "release-images.json")
	if err := run(validArgs(out), io.Discard, io.Discard); err != nil {
		t.Fatalf("run: %v", err)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(out)
		if err != nil {
			t.Fatalf("stat output: %v", err)
		}
		if got := info.Mode().Perm(); got != 0o600 {
			t.Fatalf("output permissions = %04o, want 0600", got)
		}
	}
	data, err := os.ReadFile(out) // #nosec G304 -- test reads its own temp output
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	var got releaseImages
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal output: %v", err)
	}
	if got.Schema != schema || got.Tag != "v3.4.0" || got.Commit != strings.Repeat("a", 40) {
		t.Fatalf("bundle identity = %+v", got)
	}
	if len(got.Images) != 3 || got.Images[0].Name != "pipelock" || got.Images[1].Name != "pipelock-init" || got.Images[2].Name != "pipelock-license-service" {
		t.Fatalf("images = %+v", got.Images)
	}
	for _, image := range got.Images {
		if image.Digest != testDigest {
			t.Fatalf("digest for %s = %q", image.Name, image.Digest)
		}
	}
}

func TestRunWritesBundleToStdout(t *testing.T) {
	var stdout bytes.Buffer
	if err := run(validArgs(""), &stdout, io.Discard); err != nil {
		t.Fatalf("run: %v", err)
	}
	if !strings.Contains(stdout.String(), `"schema": "pipelock-release-images-v1"`) {
		t.Fatalf("stdout = %q", stdout.String())
	}
}

func TestRunRejectsFlagAndOutputFailures(t *testing.T) {
	tests := []struct {
		name   string
		args   []string
		stdout io.Writer
		want   string
	}{
		{
			name: "unknown flag",
			args: []string{"--unknown"},
			want: "flag provided but not defined",
		},
		{
			name:   "positional argument",
			args:   append(validArgs(""), "unexpected"),
			stdout: io.Discard,
			want:   "unexpected positional arguments",
		},
		{
			name:   "stdout write failure",
			args:   validArgs(""),
			stdout: failWriter{err: errors.New("stdout unavailable")},
			want:   "write release image bundle: stdout unavailable",
		},
		{
			name:   "output path is directory",
			args:   validArgs(t.TempDir()),
			stdout: io.Discard,
			want:   "write ",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := run(tc.args, tc.stdout, io.Discard); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("run error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestBuildManifestRejectsWrongOrMissingInputs(t *testing.T) {
	validImages := []string{
		"pipelock=ghcr.io/luckypipewrench/pipelock@" + testDigest,
		"pipelock-init=ghcr.io/luckypipewrench/pipelock-init@" + testDigest,
		"pipelock-license-service=ghcr.io/luckypipewrench/pipelock-license-service@" + testDigest,
	}
	tests := []struct {
		name   string
		tag    string
		commit string
		images []string
		want   string
	}{
		{name: "bad tag", tag: "release-3.4.0", commit: strings.Repeat("a", 40), images: validImages, want: "--tag"},
		{name: "bad commit", tag: "v3.4.0", commit: "ABC", images: validImages, want: "--commit"},
		{name: "missing image", tag: "v3.4.0", commit: strings.Repeat("a", 40), images: validImages[:2], want: "missing required"},
		{name: "duplicate image", tag: "v3.4.0", commit: strings.Repeat("a", 40), images: append(validImages[:2], validImages[0]), want: "duplicate"},
		{name: "too many images", tag: "v3.4.0", commit: strings.Repeat("a", 40), images: append(validImages, validImages[0]), want: "exactly"},
		{name: "unknown image", tag: "v3.4.0", commit: strings.Repeat("a", 40), images: []string{
			"other=ghcr.io/luckypipewrench/other@" + testDigest,
			validImages[1], validImages[2],
		}, want: "unknown"},
		{name: "wrong repository", tag: "v3.4.0", commit: strings.Repeat("a", 40), images: []string{
			"pipelock=registry.example/pipelock@" + testDigest,
			validImages[1], validImages[2],
		}, want: "repository"},
		{name: "tagged reference", tag: "v3.4.0", commit: strings.Repeat("a", 40), images: []string{
			"pipelock=ghcr.io/luckypipewrench/pipelock:3.4.0@" + testDigest,
			validImages[1], validImages[2],
		}, want: "repository"},
		{name: "uppercase digest", tag: "v3.4.0", commit: strings.Repeat("a", 40), images: []string{
			"pipelock=ghcr.io/luckypipewrench/pipelock@sha256:0123456789ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef",
			validImages[1], validImages[2],
		}, want: "lowercase"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := buildManifest(tc.tag, tc.commit, tc.images)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("buildManifest error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestParseImageRejectsMalformedReferences(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  string
	}{
		{name: "missing name separator", value: "pipelock", want: "must use name"},
		{name: "empty name", value: "=ghcr.io/luckypipewrench/pipelock@" + testDigest, want: "must use name"},
		{name: "empty reference", value: "pipelock=", want: "must use name"},
		{name: "missing digest separator", value: "pipelock=ghcr.io/luckypipewrench/pipelock", want: "lowercase sha256"},
		{name: "empty repository", value: "pipelock=@" + testDigest, want: "must name a repository"},
		{name: "repeated digest separator", value: "pipelock=ghcr.io/luckypipewrench/pipelock@" + testDigest + "@again", want: "more than one @"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parseImage(tc.value); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("parseImage error = %v, want %q", err, tc.want)
			}
		})
	}
}
