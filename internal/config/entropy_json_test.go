// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestEntropyHostExclusionJSONRoundTrip(t *testing.T) {
	for _, entries := range [][]EntropyHostExclusion{
		EntropyHostExclusions("uploads.vendor.example"),
		{{Host: "uploads.vendor.example", Expires: temporaryExpiryDate(MaxContentEntropyHostExclusionHorizon), mapped: true}},
	} {
		data, err := json.Marshal(entries)
		if err != nil {
			t.Fatal(err)
		}
		var got []EntropyHostExclusion
		if err := json.Unmarshal(data, &got); err != nil {
			t.Fatalf("decode %s: %v", data, err)
		}
		if !reflect.DeepEqual(got, entries) {
			t.Fatalf("got %+v, want %+v", got, entries)
		}
	}
}

func TestEntropyHostExclusionJSONMappingRequiresExpiry(t *testing.T) {
	var entries []EntropyHostExclusion
	if err := json.Unmarshal([]byte(`[{"host":"uploads.vendor.example"}]`), &entries); err != nil {
		t.Fatal(err)
	}
	if err := validateEntropyHostExclusions("content_entropy_exclusions", entries); err == nil {
		t.Fatal("JSON mapping without expiry became permanent")
	}
}

func TestEntropyHostExclusionJSONInvalidForms(t *testing.T) {
	for _, input := range []string{`null`, `true`, `123`, `[]`, `{"host":123}`, `{"host":"uploads.vendor.example","expiry":"tomorrow"}`, `"unterminated`} {
		t.Run(input, func(t *testing.T) {
			var entry EntropyHostExclusion
			if err := json.Unmarshal([]byte(input), &entry); err == nil {
				t.Fatal("invalid exclusion accepted")
			}
		})
	}
}

func TestEntropyHostExclusionJSONConfigAndBundleLoad(t *testing.T) {
	future := temporaryExpiryDate(MaxContentEntropyHostExclusionHorizon)
	for _, entries := range []string{`["uploads.vendor.example"]`, `[{"host":"uploads.vendor.example","expires":"` + future + `"}]`} {
		data := []byte(`{"mode":"balanced","request_body_scanning":{"content_entropy_exclusions":` + entries + `},"websocket_proxy":{"content_entropy_exclusions":` + entries + `}}`)
		for _, load := range []func([]byte) (*Config, error){LoadBytes, LoadPolicyBundleBytes} {
			cfg, err := load(data)
			if err != nil {
				t.Fatal(err)
			}
			if len(cfg.RequestBodyScanning.ContentEntropyExclusions) != 1 || len(cfg.WebSocketProxy.ContentEntropyExclusions) != 1 {
				t.Fatal("JSON config lost exclusions")
			}
			encoded, err := json.Marshal(cfg)
			if err != nil {
				t.Fatal(err)
			}
			var decoded Config
			if err := json.Unmarshal(encoded, &decoded); err != nil {
				t.Fatal(err)
			}
			if decoded.CanonicalPolicyHash() != cfg.CanonicalPolicyHash() {
				t.Fatal("JSON config round-trip changed canonical policy")
			}
		}
	}
}

func TestEntropyHostExclusionJSONCanonicalDuplicateIdentity(t *testing.T) {
	future := temporaryExpiryDate(MaxContentEntropyHostExclusionHorizon)
	cfg := Defaults()
	cfg.RequestBodyScanning.ContentEntropyExclusions = []EntropyHostExclusion{
		{Host: "uploads.vendor.example", Expires: future},
		{Host: "uploads.vendor.example", Expires: future, mapped: true},
	}
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Config
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if cfg.CanonicalPolicyHash() != decoded.CanonicalPolicyHash() {
		t.Fatal("mapping provenance changed duplicate canonical identity across JSON round-trip")
	}
}

func TestEntropyHostExclusionJSONBlankHostValidation(t *testing.T) {
	for _, input := range []string{`[""]`, `["   "]`, `[{"host":null,"expires":"` + temporaryExpiryDate(MaxContentEntropyHostExclusionHorizon) + `"}]`} {
		var entries []EntropyHostExclusion
		if err := json.Unmarshal([]byte(input), &entries); err != nil {
			t.Fatal(err)
		}
		if err := validateEntropyHostExclusions("content_entropy_exclusions", entries); err == nil {
			t.Fatalf("empty host accepted: %s", input)
		}
	}
}
