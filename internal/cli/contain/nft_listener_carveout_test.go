// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
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
