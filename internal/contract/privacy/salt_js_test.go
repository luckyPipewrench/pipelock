// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build js

package privacy

import (
	"errors"
	"testing"
)

// On the browser target a file: source fails closed instead of being opened
// without its symlink and permission guards; an environment source works.
func TestLoadSaltFileFailsClosedOnUnsupportedPlatform(t *testing.T) {
	if _, err := LoadSalt("file:/run/pipelock/salt.key"); !errors.Is(err, ErrSaltFileUnsupported) {
		t.Fatalf("file source err = %v, want ErrSaltFileUnsupported", err)
	}
	t.Setenv("PIPELOCK_TEST_JS_SALT", "synthetic-salt-value")
	if got, err := LoadSalt("${PIPELOCK_TEST_JS_SALT}"); err != nil || string(got) != "synthetic-salt-value" {
		t.Fatalf("env source = %q, %v", got, err)
	}
}
