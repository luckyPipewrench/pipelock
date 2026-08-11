// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package guard

import (
	"strings"
	"testing"

	llsys "github.com/landlock-lsm/go-landlock/landlock/syscall"
)

// TestCapabilitiesFor_TiersByABI pins the mapping from kernel ABI to the rights
// Guard can actually request, and to the caveats it must report when it cannot.
//
// The mask half and the caveat half are asserted together on purpose. Trimming
// a right the kernel does not support is required -- requesting it makes
// LandlockCreateRuleset reject the whole ruleset -- but trimming it WITHOUT
// recording the loss is the silent-downgrade failure this package exists to
// prevent. A test that checked only the mask would pass for that bug.
func TestCapabilitiesFor_TiersByABI(t *testing.T) {
	for _, tt := range []struct {
		name           string
		abi            int
		wantResolve    bool
		wantScope      bool
		wantUnmediated int
	}{
		{"minimum has neither", MinimumABI, false, false, 2},
		{"ipc scope only", IPCScopeABI, false, true, 1},
		{"thread sync still lacks socket mediation", ThreadSyncABI, false, true, 1},
		{"socket mediation is full", SocketMediationABI, true, true, 0},
	} {
		t.Run(tt.name, func(t *testing.T) {
			accessFS, scoped, unmediated := capabilitiesFor(tt.abi)

			if got := accessFS&llsys.AccessFSResolveUnix != 0; got != tt.wantResolve {
				t.Errorf("resolve-unix requested = %v, want %v", got, tt.wantResolve)
			}
			if got := scoped != 0; got != tt.wantScope {
				t.Errorf("ipc scoping requested = %v, want %v", got, tt.wantScope)
			}
			if len(unmediated) != tt.wantUnmediated {
				t.Errorf("unmediated = %v, want %d entries", unmediated, tt.wantUnmediated)
			}
			// The full filesystem right set is available at every supported ABI;
			// only the socket and IPC capabilities tier.
			if accessFS&baseAccessFS != baseAccessFS {
				t.Errorf("base filesystem rights were trimmed at ABI %d", tt.abi)
			}
			// Every trimmed capability must be named in terms an operator can
			// act on, not as a bare flag name.
			if !tt.wantResolve {
				if !containsSubstring(unmediated, "unix socket") {
					t.Errorf("unmediated = %v, want it to name unix sockets", unmediated)
				}
			}
		})
	}
}

func containsSubstring(list []string, want string) bool {
	for _, s := range list {
		if strings.Contains(s, want) {
			return true
		}
	}
	return false
}

// TestEnforcementRecord_PartialCoverageIsNotFullyMediated proves the two
// questions stay distinct. Enforced answers "are the filesystem grants in
// force"; FullyMediated answers "is every capability covered". A caller that
// asks the first and reports the second is the bug.
func TestEnforcementRecord_PartialCoverageIsNotFullyMediated(t *testing.T) {
	abi := ThreadSyncABI
	partial := EnforcementRecord{
		State:       EnforcementEnforced,
		Mechanism:   "landlock",
		ObservedABI: &abi,
		Coverage:    CoveragePartial,
		Unmediated:  []string{"connect(2) on pathname unix sockets"},
	}
	if !partial.Enforced() {
		t.Error("partial coverage still enforces the filesystem grants")
	}
	if partial.FullyMediated() {
		t.Error("partial coverage must not report as fully mediated")
	}
	// The caveat has to survive into the operator-facing line, not sit in a
	// field nobody renders.
	desc := partial.Describe()
	if !strings.Contains(desc, "PARTIAL") || !strings.Contains(desc, "unix sockets") {
		t.Errorf("Describe() = %q, want it to lead with the partial coverage and name the gap", desc)
	}

	full := partial
	full.Coverage = CoverageFull
	full.Unmediated = nil
	if !full.FullyMediated() {
		t.Error("full coverage must report as fully mediated")
	}
	if strings.Contains(full.Describe(), "PARTIAL") {
		t.Errorf("Describe() = %q, want no partial caveat", full.Describe())
	}
}
