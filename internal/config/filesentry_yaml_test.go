// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestWatchPath_UnmarshalYAML_StringForm(t *testing.T) {
	input := []byte(`
- "/etc/secrets"
- "/var/lib/app"
`)
	var paths []WatchPath
	if err := yaml.Unmarshal(input, &paths); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	want := []WatchPath{
		{Path: "/etc/secrets", Required: false},
		{Path: "/var/lib/app", Required: false},
	}
	if len(paths) != len(want) {
		t.Fatalf("len = %d, want %d", len(paths), len(want))
	}
	for i, p := range paths {
		if p.Path != want[i].Path {
			t.Errorf("[%d].Path = %q, want %q", i, p.Path, want[i].Path)
		}
		if p.Required != want[i].Required {
			t.Errorf("[%d].Required = %v, want %v", i, p.Required, want[i].Required)
		}
	}
}

func TestWatchPath_UnmarshalYAML_MappingForm(t *testing.T) {
	input := []byte(`
- path: "/etc/secrets"
  required: true
- path: "/var/optional"
  required: false
- path: "/var/default"
`)
	var paths []WatchPath
	if err := yaml.Unmarshal(input, &paths); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	want := []WatchPath{
		{Path: "/etc/secrets", Required: true},
		{Path: "/var/optional", Required: false},
		{Path: "/var/default", Required: false},
	}
	if len(paths) != len(want) {
		t.Fatalf("len = %d, want %d", len(paths), len(want))
	}
	for i, p := range paths {
		if p.Path != want[i].Path || p.Required != want[i].Required {
			t.Errorf("[%d] = %+v, want %+v", i, p, want[i])
		}
	}
}

func TestWatchPath_UnmarshalYAML_MixedList(t *testing.T) {
	input := []byte(`
- "/legacy/path"
- path: "/new/required/path"
  required: true
- "/another/legacy"
`)
	var paths []WatchPath
	if err := yaml.Unmarshal(input, &paths); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	want := []WatchPath{
		{Path: "/legacy/path", Required: false},
		{Path: "/new/required/path", Required: true},
		{Path: "/another/legacy", Required: false},
	}
	if len(paths) != len(want) {
		t.Fatalf("len = %d, want %d", len(paths), len(want))
	}
	for i, p := range paths {
		if p.Path != want[i].Path || p.Required != want[i].Required {
			t.Errorf("[%d] = %+v, want %+v", i, p, want[i])
		}
	}
}

func TestWatchPath_UnmarshalYAML_RejectsTypoedField(t *testing.T) {
	// Typo like "require" instead of "required" must reject loudly so the
	// operator doesn't silently lose the required:true opt-in.
	input := []byte(`
- path: "/etc/secrets"
  require: true
`)
	var paths []WatchPath
	err := yaml.Unmarshal(input, &paths)
	if err == nil {
		t.Fatal("expected error for unknown field 'require'")
	}
	if !strings.Contains(err.Error(), "require") {
		t.Errorf("error %q does not mention the offending field name", err.Error())
	}
}

func TestWatchPath_UnmarshalYAML_RejectsMissingPath(t *testing.T) {
	input := []byte(`
- required: true
`)
	var paths []WatchPath
	err := yaml.Unmarshal(input, &paths)
	if err == nil {
		t.Fatal("expected error for mapping form missing 'path'")
	}
	if !strings.Contains(err.Error(), "path") {
		t.Errorf("error %q does not mention the missing 'path' field", err.Error())
	}
}

func TestWatchPath_UnmarshalYAML_RejectsEmptyPath(t *testing.T) {
	input := []byte(`
- path: ""
  required: true
`)
	var paths []WatchPath
	err := yaml.Unmarshal(input, &paths)
	if err == nil {
		t.Fatal("expected error for empty path")
	}
}

func TestWatchPath_UnmarshalYAML_RejectsEmptyScalar(t *testing.T) {
	// Empty scalar would silently resolve to the config directory via
	// load.go's relative-path normalization. Reject at decode time.
	input := []byte(`
- ""
`)
	var paths []WatchPath
	err := yaml.Unmarshal(input, &paths)
	if err == nil {
		t.Fatal("expected error for empty scalar watch_paths entry")
	}
	if !strings.Contains(err.Error(), "empty") {
		t.Errorf("error %q does not mention emptiness", err.Error())
	}
}

func TestWatchPath_UnmarshalYAML_RejectsNonStringScalar(t *testing.T) {
	// A bare boolean or integer is not a valid path; reject rather than
	// coerce to its literal representation.
	input := []byte(`
- true
`)
	var paths []WatchPath
	err := yaml.Unmarshal(input, &paths)
	if err == nil {
		t.Fatal("expected error for non-string scalar")
	}
}
