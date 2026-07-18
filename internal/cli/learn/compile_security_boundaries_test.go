// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package learn

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestResolveCompileInputsRejectsUntrustedExactSessionMetadata(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		content []byte
	}{
		{
			name:    "malformed envelope",
			content: []byte("{not-json}\n"),
		},
		{
			name:    "missing recorder hash",
			content: []byte(`{"type":"capture","detail":{"agent":"agent-a"}}` + "\n"),
		},
		{
			name:    "wrong embedded agent",
			content: captureJSONL("attacker"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			root := t.TempDir()
			sessionDir := filepath.Join(root, "agent-a")
			if err := os.MkdirAll(sessionDir, 0o750); err != nil {
				t.Fatalf("MkdirAll: %v", err)
			}
			if err := os.WriteFile(filepath.Join(sessionDir, "capture.jsonl"), tt.content, 0o600); err != nil {
				t.Fatalf("WriteFile: %v", err)
			}
			cfg := config.Defaults()
			cfg.Learn.CaptureDir = root

			_, err := resolveCompileInputs(cfg, compileFlags{agent: "agent-a", since: time.Hour})
			if err == nil || !strings.Contains(err.Error(), "no recorder JSONL inputs matched") {
				t.Fatalf("resolveCompileInputs error = %v, want untrusted exact session rejected", err)
			}
		})
	}
}

func TestReadCompileInputsRejectsUnsafeFileTypes(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	target := filepath.Join(root, "capture.jsonl")
	if err := os.WriteFile(target, captureJSONL("agent-a"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	link := filepath.Join(root, "capture-link.jsonl")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("Symlink: %v", err)
	}

	tests := []struct {
		name string
		path string
		want string
	}{
		{name: "symlink", path: link, want: "must not be a symlink"},
		{name: "directory", path: root, want: "must be a regular file"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := readCompileInputs([]string{tt.path})
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("readCompileInputs error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestResolveCompileOutputsRejectsUnsafeArtifactPaths(t *testing.T) {
	t.Parallel()

	for _, artifact := range []string{"candidate", "review", "manifest"} {
		for _, kind := range []string{"symlink", "directory"} {
			t.Run(artifact+"/"+kind, func(t *testing.T) {
				t.Parallel()

				root := t.TempDir()
				candidate := filepath.Join(root, "candidate.yaml")
				review := filepath.Join(root, "candidate.review.md")
				manifest := filepath.Join(root, "candidate.manifest.json")

				var unsafePath string
				switch artifact {
				case "candidate":
					unsafePath = candidate
				case "review":
					unsafePath = review
				case "manifest":
					unsafePath = manifest
				}
				if kind == "symlink" {
					target := filepath.Join(root, artifact+".target")
					if err := os.WriteFile(target, []byte("do not overwrite"), 0o600); err != nil {
						t.Fatalf("WriteFile target: %v", err)
					}
					if err := os.Symlink(target, unsafePath); err != nil {
						t.Fatalf("Symlink: %v", err)
					}
				} else if err := os.Mkdir(unsafePath, 0o750); err != nil {
					t.Fatalf("Mkdir: %v", err)
				}

				_, _, _, err := resolveCompileOutputs(compileFlags{
					agent:    "agent-a",
					output:   candidate,
					review:   review,
					manifest: manifest,
				})
				want := "must be a regular file"
				if kind == "symlink" {
					want = "must not be a symlink"
				}
				if err == nil || !strings.Contains(err.Error(), want) {
					t.Fatalf("resolveCompileOutputs error = %v, want %q", err, want)
				}
			})
		}
	}
}
