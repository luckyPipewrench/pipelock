// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestTransformProfileV1Fixtures(t *testing.T) {
	t.Parallel()
	path := filepath.Clean(filepath.Join("..", "..", "sdk", "conformance", "testdata", "transform-profile", "pipelock-transform-v1.json"))
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var profile struct {
		Profile  string `json:"profile"`
		Fixtures []struct {
			Name           string `json:"name"`
			NormalizedView string `json:"normalized_view"`
			Input          string `json:"input"`
			Output         string `json:"output"`
		} `json:"fixtures"`
	}
	if err := json.Unmarshal(body, &profile); err != nil {
		t.Fatalf("unmarshal fixture: %v", err)
	}
	if profile.Profile != transformProfileV1 {
		t.Fatalf("profile=%q want %q", profile.Profile, transformProfileV1)
	}
	for _, fixture := range profile.Fixtures {
		t.Run(fixture.Name, func(t *testing.T) {
			got, err := reproduceSpanView(fixture.Input, fixture.NormalizedView)
			if err != nil {
				t.Fatalf("reproduceSpanView: %v", err)
			}
			if got != fixture.Output {
				t.Fatalf("output=%q want %q", got, fixture.Output)
			}
		})
	}
}
