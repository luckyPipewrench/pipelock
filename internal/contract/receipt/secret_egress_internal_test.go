// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receipt

import "testing"

func TestSecretEgressDecisionRemainsFixtureOnly(t *testing.T) {
	t.Parallel()
	entry, ok := payloadMaturity[PayloadSecretEgressDecisionV1]
	if !ok || entry.maturity != PayloadMaturityFixtureOnly || entry.producer != nil {
		t.Fatal("secret-egress contract must remain fixture-only without a producer declaration")
	}
}
