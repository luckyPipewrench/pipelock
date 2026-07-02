// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package configs

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestPresetBytesMatchFiles(t *testing.T) {
	t.Parallel()

	for name, filename := range filePresets {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got, ok := Preset(name)
			if !ok {
				t.Fatalf("Preset(%q) not found", name)
			}

			want, err := os.ReadFile(filepath.Clean(filename))
			if err != nil {
				t.Fatalf("reading %s: %v", filename, err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("Preset(%q) bytes differ from %s", name, filename)
			}
		})
	}
}

func TestPresetRejectsUnknownName(t *testing.T) {
	t.Parallel()

	if data, ok := Preset("missing"); ok || data != nil {
		t.Fatalf("Preset returned (%q, %v), want nil false", data, ok)
	}
}

// Intentionally serial: this test mutates the shared filePresets map that
// parallel tests read through Preset.
func TestPresetRejectsMissingEmbeddedFile(t *testing.T) {
	filePresets["missing"] = "missing.yaml"
	defer delete(filePresets, "missing")

	if data, ok := Preset("missing"); ok || data != nil {
		t.Fatalf("Preset returned (%q, %v), want nil false", data, ok)
	}
}
