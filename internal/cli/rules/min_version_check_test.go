// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	domrules "github.com/luckyPipewrench/pipelock/internal/rules"
)

// TestCheckBundleMinVersion pins the install and update commands to the
// runtime loader's decision. A test binary carries no release stamp, so a
// declared min_pipelock is unprovable: strict refuses it, the default warns
// and continues, and a bundle without a minimum needs neither.
func TestCheckBundleMinVersion(t *testing.T) {
	t.Run("strict refuses an unprovable version", func(t *testing.T) {
		var out bytes.Buffer
		err := checkBundleMinVersion(&out, "0.1.0", false)
		if !errors.Is(err, domrules.ErrUnverifiableVersion) {
			t.Fatalf("err = %v, want ErrUnverifiableVersion", err)
		}
		if out.Len() != 0 {
			t.Fatalf("strict refusal must not print a warning, got %q", out.String())
		}
	})
	t.Run("warn and load prints the warning and continues", func(t *testing.T) {
		var out bytes.Buffer
		if err := checkBundleMinVersion(&out, "0.1.0", true); err != nil {
			t.Fatalf("err = %v, want nil", err)
		}
		if !strings.Contains(out.String(), "minimum version was not proven") {
			t.Fatalf("expected the unprovable-version warning, got %q", out.String())
		}
	})
	t.Run("malformed minimum refuses even when unverifiable versions are allowed", func(t *testing.T) {
		var out bytes.Buffer
		err := checkBundleMinVersion(&out, "not-a-version", true)
		if err == nil || errors.Is(err, domrules.ErrUnverifiableVersion) {
			t.Fatalf("err = %v, want a malformed-metadata refusal distinct from the unverifiable case", err)
		}
		if out.Len() != 0 {
			t.Fatalf("a refusal must not print the warn-and-continue text, got %q", out.String())
		}
	})
	t.Run("no minimum needs no decision", func(t *testing.T) {
		var out bytes.Buffer
		if err := checkBundleMinVersion(&out, "", false); err != nil {
			t.Fatalf("err = %v, want nil", err)
		}
		if out.Len() != 0 {
			t.Fatalf("unexpected output %q", out.String())
		}
	})
}
