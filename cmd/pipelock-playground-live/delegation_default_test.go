// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package main

import "testing"

// A dev run has no broker to mint a delegation, so --dev relaxes the demand
// unless the operator asked for it. A public serve keeps it on; the refusal for
// a public opt-out lives in validateServeSafety and is tested there.
func TestResolveDelegationDefault(t *testing.T) {
	for _, tc := range []struct {
		name     string
		dev      bool
		explicit bool
		start    bool
		want     bool
	}{
		{name: "dev_unset_relaxes", dev: true, explicit: false, start: true, want: false},
		{name: "dev_explicit_is_honored", dev: true, explicit: true, start: true, want: true},
		{name: "dev_explicit_off_is_honored", dev: true, explicit: true, start: false, want: false},
		{name: "public_keeps_the_default", dev: false, explicit: false, start: true, want: true},
		{name: "public_is_not_relaxed", dev: false, explicit: true, start: false, want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &serveFlags{dev: tc.dev, requireDelegated: tc.start}
			resolveDelegationDefault(f, tc.explicit)
			if f.requireDelegated != tc.want {
				t.Fatalf("requireDelegated = %v, want %v", f.requireDelegated, tc.want)
			}
		})
	}
}

// The flag ships on by default so a public serve that never mentions it still
// demands a delegation.
func TestServeCmd_DelegationFlagDefaultsOn(t *testing.T) {
	cmd := newServeCmd()
	fl := cmd.Flags().Lookup("require-delegated-signing")
	if fl == nil {
		t.Fatal("--require-delegated-signing must exist")
	}
	if fl.DefValue != "true" {
		t.Fatalf("default = %q, want \"true\"", fl.DefValue)
	}
}
