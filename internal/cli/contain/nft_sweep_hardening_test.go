// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"math"
	"strconv"
	"strings"
	"testing"
)

// TestUnitHasExactEntryRejectsSubstringLookalikes covers the tampered managed
// persistence units that substring matching previously verified as healthy.
func TestUnitHasExactEntryRejectsSubstringLookalikes(t *testing.T) {
	const rulesPath = "/etc/pipelock/containment.nft"
	const target = "/usr/local/bin/pipelock"
	execValue := target + " contain reload-nft-rules"

	tests := []struct {
		name    string
		body    string
		section string
		key     string
		value   string
		want    bool
	}{
		{
			name:    "canonical unit",
			body:    "[Unit]\nConditionPathExists=" + rulesPath + "\n\n[Service]\nExecStart=" + execValue + "\n",
			section: "Unit",
			key:     "ConditionPathExists",
			value:   rulesPath,
			want:    true,
		},
		{
			name:    "commented condition",
			body:    "[Unit]\n#ConditionPathExists=" + rulesPath + "\n",
			section: "Unit",
			key:     "ConditionPathExists",
			value:   rulesPath,
		},
		{
			name:    "suffixed condition path",
			body:    "[Unit]\nConditionPathExists=" + rulesPath + ".bak\n",
			section: "Unit",
			key:     "ConditionPathExists",
			value:   rulesPath,
		},
		{
			name:    "condition in the wrong section",
			body:    "[Service]\nConditionPathExists=" + rulesPath + "\n",
			section: "Unit",
			key:     "ConditionPathExists",
			value:   rulesPath,
		},
		{
			name:    "canonical exec",
			body:    "[Service]\nExecStart=" + execValue + "\n",
			section: "Service",
			key:     "ExecStart",
			value:   execValue,
			want:    true,
		},
		{
			name:    "suffixed exec subcommand",
			body:    "[Service]\nExecStart=" + execValue + "-extra\n",
			section: "Service",
			key:     "ExecStart",
			value:   execValue,
		},
		{
			name:    "extra exec arguments",
			body:    "[Service]\nExecStart=" + execValue + " --allow-everything\n",
			section: "Service",
			key:     "ExecStart",
			value:   execValue,
		},
		{
			name:    "unintended executable containing the managed target",
			body:    "[Service]\nExecStart=/tmp/attacker" + execValue + "\n",
			section: "Service",
			key:     "ExecStart",
			value:   execValue,
		},
		{
			name:    "commented exec",
			body:    "[Service]\n# ExecStart=" + execValue + "\n",
			section: "Service",
			key:     "ExecStart",
			value:   execValue,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := unitHasExactEntry(tc.body, tc.section, tc.key, tc.value); got != tc.want {
				t.Fatalf("unitHasExactEntry = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestManagedContainmentDropPacketCountRejectsOverflow proves the aggregate
// reports an error instead of wrapping to a smaller count, which would let the
// verifier miscompute a real positive counter delta.
func TestManagedContainmentDropPacketCountRejectsOverflow(t *testing.T) {
	rule := func(packets string) string {
		return "meta skuid 966 counter packets " + packets + " bytes 0 log prefix " +
			strconv.Quote(nftLogPrefix(EgressClassNotRoutingThroughPipelock)+" ") + " drop"
	}
	lines := []string{
		rule(strconv.FormatUint(math.MaxUint64, 10)),
		rule("1"),
	}

	_, err := managedContainmentDropPacketCountFromLines(lines, defaultNFTChain, 966)
	if err == nil || !strings.Contains(err.Error(), "overflow") {
		t.Fatalf("aggregate error = %v, want uint64 overflow refusal", err)
	}
}

// TestLegacyManagedBlockDeletedAfterProxyPortChange proves reconciliation still
// removes the previous block when the operator changes the proxy port. Matching
// the loopback allow against the CURRENT port left the old block in place, and
// its catch-all DROP then sat ahead of the appended canonical rules and dropped
// the agent's traffic to the new port.
func TestLegacyManagedBlockDeletedAfterProxyPortChange(t *testing.T) {
	live := strings.Join([]string{
		`table inet pipelock_containment {`,
		`  chain output_filter {`,
		`    type filter hook output priority filter; policy accept;`,
		legacyManagedBlockWithHandles(40),
		`  }`,
		`}`,
	}, "\n")

	handles := legacyManagedNFTRuleBlockHandles(live, 1000, 967, 966)
	if len(handles) != 6 {
		t.Fatalf("legacy block handles = %v, want the complete previous-port block", handles)
	}

	body := renderNFTRules(1000, 967, 966, 9999, defaultNFTTable, defaultNFTChain)
	script := renderNFTManagedChainReloadScript(live, body, defaultNFTTable, defaultNFTChain, 1000, 967, 966)
	for _, handle := range handles {
		want := "delete rule inet " + defaultNFTTable + " " + defaultNFTChain + " handle " + strconv.Itoa(handle)
		if !strings.Contains(script, want) {
			t.Fatalf("reload script kept previous-port handle %d:\n%s", handle, script)
		}
	}
}

// TestLegacyManagedBlockMatchRejectsNonPortLoopbackAllow keeps the widened
// loopback match from accepting a rule whose destination port is not a port.
func TestLegacyManagedBlockMatchRejectsNonPortLoopbackAllow(t *testing.T) {
	if lineHasAgentProxyLoopbackAllowAnyPort(`meta skuid 966 ip daddr 127.0.0.1 tcp dport http accept`, 966) {
		t.Fatal("non-numeric dport matched the managed loopback allow")
	}
	if lineHasAgentProxyLoopbackAllowAnyPort(`meta skuid 966 ip daddr 127.0.0.1 tcp dport 0 accept`, 966) {
		t.Fatal("port zero matched the managed loopback allow")
	}
	if lineHasAgentProxyLoopbackAllowAnyPort(`meta skuid 966 ip daddr 127.0.0.2 tcp dport 8888 accept`, 966) {
		t.Fatal("non-loopback destination matched the managed loopback allow")
	}
	if !lineHasAgentProxyLoopbackAllowAnyPort(`meta skuid 966 ip daddr 127.0.0.1 tcp dport 8888 accept`, 966) {
		t.Fatal("canonical loopback allow did not match")
	}
}
