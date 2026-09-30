// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package sandbox

import (
	"slices"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/guard"
)

// The default sandbox grants /etc/ssl/ and /etc/pki/ as directories, which
// does not reach a CA bundle symlinked elsewhere (Arch links into
// /etc/ca-certificates/). Every CA file Guard declares must also be an exact
// read grant here, so both layers stay aligned from one list.
func TestDefaultPolicy_GrantsEveryExecutionCAFile(t *testing.T) {
	cas := guard.ExecutionCAFiles()
	if len(cas) == 0 {
		t.Skip("no CA bundle declarations exist on this host")
	}
	policy := DefaultPolicy(t.TempDir())
	for _, ca := range cas {
		if !slices.Contains(policy.AllowReadFiles, ca) {
			t.Errorf("default policy does not grant CA file %s: %v", ca, policy.AllowReadFiles)
		}
	}
}
