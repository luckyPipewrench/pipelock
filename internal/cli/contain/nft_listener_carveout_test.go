// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"fmt"
	"strings"
	"testing"
)

func TestReloadListenerGuardPreservesEarlierForeignCarveOut(t *testing.T) {
	const foreign = `meta skuid 966 ip daddr 127.0.0.1 tcp dport 9077 accept # handle 10`
	current := renderNFTRulesWithServices(nftRuleOptions{OperatorUID: loopbackTestOperatorUID, ProxyUID: loopbackTestProxyUID, AgentUID: loopbackTestAgentUID, ProxyPort: loopbackTestProxyPort, Table: defaultNFTTable, Chain: defaultNFTChain, AgentListener: "127.0.0.1:8889"})
	live := foreign + "\n" + nftListingFromRulesBodyForTest(current, 20)
	script := renderNFTManagedChainReloadScript(live, current, defaultNFTTable, defaultNFTChain, loopbackTestOperatorUID, loopbackTestProxyUID, loopbackTestAgentUID, true)
	if strings.Contains(script, "handle 10") {
		t.Fatalf("foreign carve-out deleted: %s", script)
	}
	if !strings.Contains(script, "handle 20") || !strings.Contains(script, "pipelock_agent_listener_blocked") {
		t.Fatalf("managed guard not replaced: %s", script)
	}
}

// A guard left over from an earlier proxy UID must be recognized and replaced
// with the rest of the managed block, not left in front of the new rules where
// it would drop the current proxy's own connections.
func TestReloadReplacesListenerGuardWithStaleProxyUID(t *testing.T) {
	current := renderNFTRulesWithServices(nftRuleOptions{OperatorUID: loopbackTestOperatorUID, ProxyUID: loopbackTestProxyUID, AgentUID: loopbackTestAgentUID, ProxyPort: loopbackTestProxyPort, Table: defaultNFTTable, Chain: defaultNFTChain, AgentListener: "127.0.0.1:8889"})
	currentGuard := fmt.Sprintf("meta skuid != { 0, %d }", loopbackTestProxyUID)
	staleGuard := fmt.Sprintf("meta skuid != { 0, %d }", loopbackTestProxyUID+50)
	if strings.Count(current, currentGuard) != 1 {
		t.Fatalf("rendered rules do not carry exactly one current guard:\n%s", current)
	}
	live := nftListingFromRulesBodyForTest(strings.Replace(current, currentGuard, staleGuard, 1), 20)
	if !strings.Contains(live, staleGuard) {
		t.Fatalf("fixture did not install the stale guard:\n%s", live)
	}
	script := renderNFTManagedChainReloadScript(live, current, defaultNFTTable, defaultNFTChain, loopbackTestOperatorUID, loopbackTestProxyUID, loopbackTestAgentUID, true)
	if !strings.Contains(script, "handle 20") {
		t.Fatalf("stale guard (handle 20) was not replaced:\n%s", script)
	}
}
