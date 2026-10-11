// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package envcontrol

import (
	"sort"
	"strings"
	"testing"
)

func TestCodeLoadingNames(t *testing.T) {
	t.Parallel()
	list := CodeLoadingNames()
	if !sort.StringsAreSorted(list) {
		t.Fatalf("list is not sorted: %v", list)
	}
	seen := make(map[string]bool, len(list))
	for _, name := range list {
		if seen[name] {
			t.Fatalf("list repeats %q", name)
		}
		seen[name] = true
		if !IsCodeLoading(name) {
			t.Fatalf("IsCodeLoading(%q) = false for a listed name", name)
		}
		if name == "" || name != strings.ToUpper(name) || strings.ContainsAny(name, "=\x00") {
			t.Fatalf("list holds invalid name %q", name)
		}
	}
	if len(list) != len(codeLoadingSet) {
		t.Fatalf("list has %d names, set has %d", len(list), len(codeLoadingSet))
	}
	for _, must := range []string{"LD_PRELOAD", "LD_AUDIT", "LD_ORIGIN_PATH", "GCONV_PATH", "NODE_OPTIONS", "PYTHONPATH", "JAVA_TOOL_OPTIONS", "DOTNET_STARTUP_HOOKS", "BASH_ENV"} {
		if !seen[must] {
			t.Errorf("list lacks %s", must)
		}
	}
	// The exported value is a copy: mutating it must not change the policy.
	list[0] = "MUTATED"
	if IsCodeLoading("MUTATED") {
		t.Fatal("mutating the returned slice changed the lookup set")
	}
	if got := CodeLoadingNames(); got[0] == "MUTATED" {
		t.Fatal("mutating the returned slice changed the list")
	}
}

func TestIsCodeLoadingRefusesOnlyListedNames(t *testing.T) {
	t.Parallel()
	// Variables that change behavior without choosing code stay out, so a
	// surface refusing this list does not refuse ordinary configuration.
	for _, name := range []string{"PATH", "HOME", "TZ", "NODE_EXTRA_CA_CERTS", "GLIBC_TUNABLES", "LD_PROFILE", "ld_preload", ""} {
		if IsCodeLoading(name) {
			t.Errorf("IsCodeLoading(%q) = true, want false", name)
		}
	}
}
