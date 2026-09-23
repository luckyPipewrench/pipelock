// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config_test

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func loadYAML(t *testing.T, body string) *config.Config {
	t.Helper()
	path := filepath.Join(t.TempDir(), "pipelock.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	return cfg
}

// TestBlocklistDefaultReachesAYAMLBackedConfig pins the shipped exfiltration
// blocklist on the path every deployment takes. Load() decodes into an empty
// config, so a list present only in Defaults() protected the no-config CLI and
// nothing else: a one-line config file, and the Helm chart's rendered config,
// both ran with zero blocklist entries while validation reported OK.
//
// Every spelling a YAML author can use is covered, because nil and empty are
// different decisions: omitted and null mean "I said nothing" and get the
// shipped set; an explicit [] is a deliberate opt-out and is preserved; an
// explicit list is taken as written, matching the entropy exclusion siblings.
func TestBlocklistDefaultReachesAYAMLBackedConfig(t *testing.T) {
	shipped := config.Defaults().FetchProxy.Monitoring.Blocklist
	if len(shipped) == 0 {
		t.Fatal("Defaults() ships no blocklist; this test would pass vacuously")
	}

	cases := []struct {
		name string
		yaml string
		want []string
	}{
		{"omitted", "mode: balanced\n", shipped},
		{"monitoring present, blocklist omitted", "fetch_proxy:\n  monitoring:\n    max_url_length: 4096\n", shipped},
		{"explicit null", "fetch_proxy:\n  monitoring:\n    blocklist:\n", shipped},
		{"explicit empty opts out", "fetch_proxy:\n  monitoring:\n    blocklist: []\n", []string{}},
		{"explicit list taken as written", "fetch_proxy:\n  monitoring:\n    blocklist:\n      - \"*.exfil.example\"\n", []string{"*.exfil.example"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := loadYAML(t, tc.yaml).FetchProxy.Monitoring.Blocklist
			if !slices.Equal(got, tc.want) {
				t.Fatalf("blocklist = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestBlocklistDefaultBlocksThroughTheScanner proves the loaded default is
// enforced, not merely present, and that the opt-out really turns it off.
func TestBlocklistDefaultBlocksThroughTheScanner(t *testing.T) {
	const target = "https://pastebin.com/raw/abc123"
	cases := []struct {
		name        string
		yaml        string
		wantBlocked bool
	}{
		{"omitted blocks", "mode: balanced\n", true},
		{"explicit empty allows", "fetch_proxy:\n  monitoring:\n    blocklist: []\n", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := loadYAML(t, tc.yaml)
			cfg.Internal = nil
			sc := scanner.MustNew(cfg)
			t.Cleanup(sc.Close)
			res := sc.Scan(context.Background(), target)
			blocked := !res.Allowed && res.Scanner == scanner.ScannerBlocklist
			if blocked != tc.wantBlocked {
				t.Fatalf("blocked by blocklist=%v want %v (allowed=%v scanner=%q reason=%q)",
					blocked, tc.wantBlocked, res.Allowed, res.Scanner, res.Reason)
			}
		})
	}
}

// TestBlocklistDefaultIsIdempotent covers reload: ApplyDefaults runs again on
// an already-defaulted config and must not duplicate or reorder entries.
func TestBlocklistDefaultIsIdempotent(t *testing.T) {
	cfg := loadYAML(t, "mode: balanced\n")
	before := slices.Clone(cfg.FetchProxy.Monitoring.Blocklist)
	cfg.ApplyDefaults()
	if !slices.Equal(cfg.FetchProxy.Monitoring.Blocklist, before) {
		t.Fatalf("second ApplyDefaults changed blocklist: %q -> %q", before, cfg.FetchProxy.Monitoring.Blocklist)
	}
	// The loaded slice must not alias Defaults(): mutating one config must not
	// leak into another loaded later.
	cfg.FetchProxy.Monitoring.Blocklist[0] = "mutated.example"
	if loadYAML(t, "mode: balanced\n").FetchProxy.Monitoring.Blocklist[0] == "mutated.example" {
		t.Fatal("loaded blocklist aliases the shared default slice")
	}
}

// intentionallyUndefaultedLists names every list that Defaults() populates but
// a YAML-backed config deliberately does NOT inherit when the key is omitted,
// with the reason. Anything not named here must survive Load.
var intentionallyUndefaultedLists = map[string]string{
	// Grants reachability in strict mode and exempts hosts from the blocklist
	// in balanced mode. Inheriting it on omission would widen trust for an
	// operator who wrote none, so omission fails toward denying.
	"api_allowlist": "trust-widening; omission must not grant reachability",
	// Filled by ApplyDefaults only when git_protection.enabled is true, which
	// is the only state in which it is consulted.
	"git_protection.allowed_branches": "defaulted conditionally on git_protection.enabled",
}

// TestNoShippedListDefaultIsDroppedByLoad is the class guard. It walks every
// list and map in Defaults() and fails when one that ships entries comes back
// empty from a minimal YAML load, unless it is named above with a reason. A new
// defaulted list therefore cannot repeat the blocklist's silent loss.
func TestNoShippedListDefaultIsDroppedByLoad(t *testing.T) {
	loaded := loadYAML(t, "mode: balanced\n")
	var dropped []string
	var walked int
	var walk func(path string, def, got reflect.Value)
	walk = func(path string, def, got reflect.Value) {
		switch def.Kind() {
		case reflect.Pointer:
			if !def.IsNil() && !got.IsNil() {
				walk(path, def.Elem(), got.Elem())
			}
		case reflect.Struct:
			for i := 0; i < def.NumField(); i++ {
				f := def.Type().Field(i)
				if !f.IsExported() {
					continue
				}
				name := strings.Split(f.Tag.Get("yaml"), ",")[0]
				if name == "" || name == "-" {
					continue
				}
				child := name
				if path != "" {
					child = path + "." + name
				}
				walk(child, def.Field(i), got.Field(i))
			}
		case reflect.Slice, reflect.Map:
			if def.Len() == 0 {
				return
			}
			walked++
			if got.Len() == 0 {
				if _, ok := intentionallyUndefaultedLists[path]; !ok {
					dropped = append(dropped, path)
				}
			}
		}
	}
	walk("", reflect.ValueOf(config.Defaults()).Elem(), reflect.ValueOf(loaded).Elem())
	if walked == 0 {
		t.Fatal("walked no defaulted lists; the guard would pass vacuously")
	}
	for _, p := range dropped {
		t.Errorf("Defaults() ships %s but a YAML config that omits it loads it empty; default it in ApplyDefaults or name it in intentionallyUndefaultedLists with a reason", p)
	}
}
