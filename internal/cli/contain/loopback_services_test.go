// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"gopkg.in/yaml.v3"
)

const (
	loopbackTestOperatorUID = 1000
	loopbackTestProxyUID    = 967
	loopbackTestAgentUID    = 966
	loopbackTestProxyPort   = 8888
)

func loopbackTestService(port int) config.ContainmentLoopbackService {
	return config.ContainmentLoopbackService{
		Host:      "127.0.0.1",
		Port:      port,
		Owner:     "search-team",
		Reason:    "agent needs a local search index",
		ExpiresAt: "2099-01-01T00:00:00Z",
	}
}

// TestRenderNFTRulesWithLoopbackServicesGolden pins the namespace-era
// contract: declarations never widen the host nftables boundary.
func TestRenderNFTRulesWithLoopbackServicesGolden(t *testing.T) {
	t.Parallel()

	want := RenderNFTRules(loopbackTestOperatorUID, loopbackTestProxyUID, loopbackTestAgentUID, loopbackTestProxyPort)
	got := RenderNFTRulesWithLoopbackServices(loopbackTestOperatorUID, loopbackTestProxyUID, loopbackTestAgentUID, loopbackTestProxyPort, []config.ContainmentLoopbackService{
		loopbackTestService(9200),
		loopbackTestService(9201),
	})
	if got != want || strings.Contains(got, "9200") || strings.Contains(got, "9201") {
		t.Fatalf("declared services widened host nft rules:\n%s", got)
	}
}

// IPv6 declarations use the same namespace socket mechanism and likewise do
// not create a host nftables exception.
func TestRenderNFTRulesWithLoopbackServicesIPv6(t *testing.T) {
	t.Parallel()
	svc := loopbackTestService(9200)
	svc.Host = "::1"
	body := RenderNFTRulesWithLoopbackServices(loopbackTestOperatorUID, loopbackTestProxyUID, loopbackTestAgentUID, loopbackTestProxyPort, []config.ContainmentLoopbackService{svc})
	if strings.Contains(body, "::1") || strings.Contains(body, "9200") {
		t.Fatalf("IPv6 declaration widened host nft rules:\n%s", body)
	}
}

func loopbackServiceRuleLine(port int, handle int) string {
	return `meta skuid ` + itoa(loopbackTestAgentUID) + ` oifname "lo" ip daddr 127.0.0.1 tcp dport ` + itoa(port) + ` accept # handle ` + itoa(handle)
}

func loopbackServiceReplyRuleLine(port int, handle int) string {
	return `meta skuid ` + itoa(loopbackTestAgentUID) + ` oifname "lo" ip saddr 127.0.0.1 tcp sport ` + itoa(port) + ` ct state established ct direction reply accept # handle ` + itoa(handle)
}

// numericNftStateListing mirrors the normalized connection-state spelling
// emitted by `nft -n -a list chain`: rules are rendered with named state and
// direction, but the live listing presents their numeric values.
func numericNftStateListing(listing string) string {
	return strings.NewReplacer(
		"ct state established", "ct state 0x2",
		"ct direction reply", "ct direction 1",
	).Replace(listing)
}

func managedBlockWithLoopbackServicePairs(first int, ports []int) (string, int) {
	handle := first
	lines := []string{`meta skuid 1000 accept # handle ` + itoa(handle)}
	handle++
	lines = append(lines, `meta skuid 967 accept # handle `+itoa(handle))
	handle++
	lines = append(lines, `meta skuid 966 ip daddr 127.0.0.1 tcp dport 8888 accept # handle `+itoa(handle))
	handle++
	for _, port := range ports {
		lines = append(lines, loopbackServiceRuleLine(port, handle))
		handle++
		lines = append(lines, loopbackServiceReplyRuleLine(port, handle))
		handle++
	}
	lines = append(lines,
		`meta skuid 966 udp dport 53 counter packets 0 bytes 0 log prefix "pipelock-contain class=direct_dns_blocked " drop # handle `+itoa(handle))
	handle++
	lines = append(lines,
		`meta skuid 966 tcp dport 53 counter packets 0 bytes 0 log prefix "pipelock-contain class=direct_dns_blocked " drop # handle `+itoa(handle))
	handle++
	lines = append(lines,
		`meta skuid 966 counter packets 0 bytes 0 log prefix "pipelock-contain class=not_routing_through_pipelock " drop # handle `+itoa(handle))
	return strings.Join(lines, "\n"), handle + 1
}

// historicalManagedBlockWithLoopbackServicePairs mirrors the pair emitted
// before the forward interface and reply source-address corrections. Reload
// must recognize this block only long enough to replace it.
func historicalManagedBlockWithLoopbackServicePairs(first int, ports []int) (string, int) {
	handle := first
	lines := []string{`meta skuid 1000 accept # handle ` + itoa(handle)}
	handle++
	lines = append(lines, `meta skuid 967 accept # handle `+itoa(handle))
	handle++
	lines = append(lines, `meta skuid 966 ip daddr 127.0.0.1 tcp dport 8888 accept # handle `+itoa(handle))
	handle++
	for _, port := range ports {
		lines = append(lines, `meta skuid 966 ip daddr 127.0.0.1 tcp dport `+itoa(port)+` accept # handle `+itoa(handle))
		handle++
		lines = append(lines, `meta skuid 966 oifname "lo" ip daddr 127.0.0.1 tcp sport `+itoa(port)+` ct state established ct direction reply accept # handle `+itoa(handle))
		handle++
	}
	lines = append(lines,
		`meta skuid 966 udp dport 53 counter packets 0 bytes 0 log prefix "pipelock-contain class=direct_dns_blocked " drop # handle `+itoa(handle))
	handle++
	lines = append(lines,
		`meta skuid 966 tcp dport 53 counter packets 0 bytes 0 log prefix "pipelock-contain class=direct_dns_blocked " drop # handle `+itoa(handle))
	handle++
	lines = append(lines,
		`meta skuid 966 counter packets 0 bytes 0 log prefix "pipelock-contain class=not_routing_through_pipelock " drop # handle `+itoa(handle))
	return strings.Join(lines, "\n"), handle + 1
}

// legacyManagedBlockWithLoopbackServices renders a managed block carrying N
// declared loopback service accepts between the implicit proxy allow and the
// DNS drops, with sequential handles starting at first.
func legacyManagedBlockWithLoopbackServices(first int, ports []int) string {
	handle := first
	lines := []string{
		`meta skuid 1000 accept # handle ` + itoa(handle),
	}
	handle++
	lines = append(lines, `meta skuid 967 accept # handle `+itoa(handle))
	handle++
	lines = append(lines, `meta skuid 966 ip daddr 127.0.0.1 tcp dport 8888 accept # handle `+itoa(handle))
	handle++
	for _, port := range ports {
		lines = append(lines, loopbackServiceRuleLine(port, handle))
		handle++
	}
	lines = append(lines,
		`meta skuid 966 udp dport 53 counter packets 0 bytes 0 log prefix "pipelock-contain class=direct_dns_blocked " drop # handle `+itoa(handle))
	handle++
	lines = append(lines,
		`meta skuid 966 tcp dport 53 counter packets 0 bytes 0 log prefix "pipelock-contain class=direct_dns_blocked " drop # handle `+itoa(handle))
	handle++
	lines = append(lines,
		`meta skuid 966 counter packets 0 bytes 0 log prefix "pipelock-contain class=not_routing_through_pipelock " drop # handle `+itoa(handle))
	return strings.Join(lines, "\n")
}

// TestReloadRecognizesBlockWithDeclaredLoopbackServices proves reload
// recognizes and REPLACES (not appends alongside) a managed block that
// carries declared loopback service accepts, in both the legacy six-rule
// shape and the expanded shape.
func TestReloadRecognizesBlockWithDeclaredLoopbackServices(t *testing.T) {
	t.Parallel()

	t.Run("legacy six-rule block still recognized", func(t *testing.T) {
		block := legacyManagedBlockWithLoopbackServices(20, nil)
		live := strings.Join([]string{
			`table inet pipelock_containment {`,
			`  chain output_filter { type filter hook output priority filter; policy accept;`,
			block,
			`  }`,
			`}`,
		}, "\n")
		handles := legacyManagedNFTRuleBlockHandles(live, loopbackTestOperatorUID, loopbackTestProxyUID, loopbackTestAgentUID)
		if len(handles) != 6 {
			t.Fatalf("legacy block: got %d handles, want 6: %v", len(handles), handles)
		}
	})

	t.Run("block with two declared loopback services recognized as one block", func(t *testing.T) {
		block, _ := managedBlockWithLoopbackServicePairs(20, []int{9200, 9201})
		live := strings.Join([]string{
			`table inet pipelock_containment {`,
			`  chain output_filter { type filter hook output priority filter; policy accept;`,
			block,
			`  }`,
			`}`,
		}, "\n")
		handles := legacyManagedNFTRuleBlockHandles(live, loopbackTestOperatorUID, loopbackTestProxyUID, loopbackTestAgentUID)
		if len(handles) != 10 {
			t.Fatalf("expanded block: got %d handles, want 10 (6 base + 2 pairs): %v", len(handles), handles)
		}
		for _, want := range []int{20, 21, 22, 23, 24, 25, 26, 27, 28, 29} {
			found := false
			for _, h := range handles {
				if h == want {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("handle %d missing from recognized block: %v", want, handles)
			}
		}
	})

	t.Run("previous malformed pair is recovered", func(t *testing.T) {
		block, _ := historicalManagedBlockWithLoopbackServicePairs(20, []int{9200})
		live := strings.Join([]string{
			`table inet pipelock_containment {`,
			`  chain output_filter { type filter hook output priority filter; policy accept;`,
			block,
			`  }`,
			`}`,
		}, "\n")
		handles := legacyManagedNFTRuleBlockHandles(live, loopbackTestOperatorUID, loopbackTestProxyUID, loopbackTestAgentUID)
		if len(handles) != 8 {
			t.Fatalf("historical block: got %d handles, want 8: %v", len(handles), handles)
		}
		script := renderNFTManagedChainReloadScript(live, RenderNFTRulesWithLoopbackServices(loopbackTestOperatorUID, loopbackTestProxyUID, loopbackTestAgentUID, loopbackTestProxyPort, []config.ContainmentLoopbackService{loopbackTestService(9200)}), defaultNFTTable, defaultNFTChain, loopbackTestOperatorUID, loopbackTestProxyUID, loopbackTestAgentUID, true)
		for _, handle := range handles {
			if !strings.Contains(script, "handle "+itoa(handle)) {
				t.Fatalf("reload did not delete historical handle %d:\n%s", handle, script)
			}
		}
	})

	t.Run("foreign standalone rule between two expanded blocks is preserved", func(t *testing.T) {
		block1, next := managedBlockWithLoopbackServicePairs(20, []int{9200})
		foreign := `meta skuid 966 oifname "lo" ip daddr 127.0.0.1 tcp sport 9119 ct state established ct direction reply accept # handle ` + itoa(next)
		block2, _ := managedBlockWithLoopbackServicePairs(next+1, []int{9200, 9201})
		live := strings.Join([]string{
			`table inet pipelock_containment {`,
			`  chain output_filter { type filter hook output priority filter; policy accept;`,
			block1,
			foreign,
			block2,
			`  }`,
			`}`,
		}, "\n")
		handles := legacyManagedNFTRuleBlockHandles(live, loopbackTestOperatorUID, loopbackTestProxyUID, loopbackTestAgentUID)
		for _, h := range handles {
			if h == next {
				t.Fatalf("foreign standalone rule handle %d was deleted alongside a managed block", next)
			}
		}
		if len(handles) != 8+10 {
			t.Fatalf("got %d handles across two blocks, want %d: %v", len(handles), 8+10, handles)
		}
	})

	t.Run("reload replaces rather than appends when declared services are present", func(t *testing.T) {
		block, _ := managedBlockWithLoopbackServicePairs(20, []int{9200})
		live := strings.Join([]string{
			`table inet pipelock_containment {`,
			`  chain output_filter { type filter hook output priority filter; policy accept;`,
			block,
			`  }`,
			`}`,
		}, "\n")
		newRules := RenderNFTRulesWithLoopbackServices(loopbackTestOperatorUID, loopbackTestProxyUID, loopbackTestAgentUID, loopbackTestProxyPort, []config.ContainmentLoopbackService{
			loopbackTestService(9200),
			loopbackTestService(9201),
		})
		script := renderNFTManagedChainReloadScript(live, newRules, defaultNFTTable, defaultNFTChain, loopbackTestOperatorUID, loopbackTestProxyUID, loopbackTestAgentUID, true)
		for _, handle := range []int{20, 21, 22, 23, 24, 25, 26} {
			want := "delete rule inet pipelock_containment output_filter handle " + itoa(handle)
			if !strings.Contains(script, want) {
				t.Fatalf("reload script missing delete for handle %d:\n%s", handle, script)
			}
		}
		if strings.Contains(script, "dport 9200 accept") || strings.Contains(script, "sport 9200 ct state established ct direction reply accept") {
			t.Fatalf("reload must remove the legacy declared pair without adding a host replacement:\n%s", script)
		}
	})
}

// TestReloadRecognizesNumericPairedBlocks reproduces the live nft listing
// form. The reconciler must collapse every managed copy, including paired
// blocks whose conntrack values nft prints numerically, while leaving
// unrelated rules in the shared chain alone.
func TestReloadRecognizesNumericPairedBlocks(t *testing.T) {
	t.Parallel()

	first, next := managedBlockWithLoopbackServicePairs(20, []int{9200})
	second, next := managedBlockWithLoopbackServicePairs(next, []int{9200})
	third, _ := managedBlockWithLoopbackServicePairs(next, []int{9200})
	foreignHandles := []int{10, 11, 12, 13}
	live := numericNftStateListing(strings.Join([]string{
		`meta skuid 966 oifname "lo" ip daddr 127.0.0.1 tcp sport 8789 ct state established ct direction reply accept # handle 10`,
		`meta skuid 966 oifname "lo" ip daddr 127.0.0.1 tcp sport 9119 ct state established ct direction reply accept # handle 11`,
		`meta skuid 966 oifname "tailscale0" ip saddr 100.64.0.1 tcp sport 8642 ct state established ct direction reply accept # handle 12`,
		`meta skuid 966 ip daddr 127.0.0.1 tcp dport 9077 accept # handle 13`,
		first,
		second,
		third,
	}, "\n"))

	handles := legacyManagedNFTRuleBlockHandles(live, loopbackTestOperatorUID, loopbackTestProxyUID, loopbackTestAgentUID)
	if len(handles) != 24 {
		t.Fatalf("numeric paired listing: got %d managed handles, want 24 across three blocks: %v", len(handles), handles)
	}
	for _, foreign := range foreignHandles {
		for _, handle := range handles {
			if handle == foreign {
				t.Fatalf("numeric paired listing deleted foreign handle %d", foreign)
			}
		}
	}
}

// applyNFTDeletionsForTest removes each handle named by a "delete rule ... handle N"
// command from a numeric nft listing, returning the surviving lines. It exists so a
// reload fake models the transaction the kernel actually performs: deletions first,
// then the canonical body. A fake that skips this cannot tell a reconciliation that
// removed stale rules from one that merely appended new ones.
func applyNFTDeletionsForTest(live, deletions string) ([]string, error) {
	deleted := map[int]bool{}
	for _, line := range strings.Split(deletions, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		match := nftDeleteHandlePatternForTest.FindStringSubmatch(line)
		if match == nil {
			return nil, fmt.Errorf("unrecognized reload command %q", line)
		}
		handle, err := strconv.Atoi(match[1])
		if err != nil {
			return nil, fmt.Errorf("delete command %q has a non-numeric handle: %w", line, err)
		}
		deleted[handle] = true
	}
	survivors := make([]string, 0)
	for _, rule := range nftRulesWithHandles(live) {
		if !deleted[rule.handle] {
			survivors = append(survivors, rule.line+" # handle "+itoa(rule.handle))
		}
	}
	return survivors, nil
}

var nftDeleteHandlePatternForTest = regexp.MustCompile(`^delete rule inet \S+ \S+ handle ([0-9]+)$`)

func nftListingFromRulesBodyForTest(rules string, firstHandle int) string {
	lines := make([]string, 0)
	for _, line := range strings.Split(rules, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "meta ") {
			continue
		}
		lines = append(lines, line+" # handle "+itoa(firstHandle))
		firstHandle++
	}
	return numericNftStateListing(strings.Join(lines, "\n"))
}

// TestReloadNumericPairedMigrationConvergesAcrossRepeatedReloads models the
// kernel result of each reload transaction. A forward-only migration block and
// three numeric paired copies converge to one paired block; later reloads are
// genuine no-ops, and foreign rules are still present.
func TestReloadNumericPairedMigrationConvergesAcrossRepeatedReloads(t *testing.T) {
	t.Parallel()
	const (
		rulesPath  = "/managed/50-pipelock-containment.nft"
		configPath = "/etc/pipelock/pipelock.yaml"
	)
	svc := loopbackTestService(9200)
	persisted := RenderNFTRulesWithLoopbackServices(loopbackTestOperatorUID, loopbackTestProxyUID, loopbackTestAgentUID, loopbackTestProxyPort, []config.ContainmentLoopbackService{svc})
	legacy := legacyManagedBlockWithLoopbackServices(20, []int{9200})
	first, next := managedBlockWithLoopbackServicePairs(27, []int{9200})
	second, next := managedBlockWithLoopbackServicePairs(next, []int{9200})
	third, _ := managedBlockWithLoopbackServicePairs(next, []int{9200})
	foreign := []string{
		`meta skuid 966 oifname "lo" ip daddr 127.0.0.1 tcp sport 8789 ct state established ct direction reply accept # handle 10`,
		`meta skuid 966 oifname "lo" ip daddr 127.0.0.1 tcp sport 9119 ct state established ct direction reply accept # handle 11`,
		`meta skuid 966 oifname "tailscale0" ip saddr 100.64.0.1 tcp sport 8642 ct state established ct direction reply accept # handle 12`,
		`meta skuid 966 ip daddr 127.0.0.1 tcp dport 9077 accept # handle 13`,
	}
	live := numericNftStateListing(strings.Join(append(foreign, legacy, first, second, third), "\n"))
	var reports []string
	var reloadScript string
	env := &nftReloadEnv{
		nftPath:    "nft",
		rulesPath:  rulesPath,
		configPath: configPath,
		table:      defaultNFTTable,
		chain:      defaultNFTChain,
		now:        func() time.Time { return time.Unix(1_800_000_000, 0) },
		report: func(message string) {
			reports = append(reports, message)
		},
		readFile: func(path string) ([]byte, error) {
			switch path {
			case rulesPath:
				return []byte(persisted), nil
			case configPath:
				return []byte(nftReloadTestConfigWithService("2099-01-01T00:00:00Z")), nil
			default:
				return nil, fmt.Errorf("unexpected read %q", path)
			}
		},
		writeFile: func(path string, data []byte, _ os.FileMode) error {
			if path == rulesPath+".reload" {
				reloadScript = string(data)
			}
			return nil
		},
		removeFile: func(string) error { return nil },
		runCmd: func(_ context.Context, _ string, args ...string) (string, int, error) {
			switch strings.Join(args, " ") {
			case "-n -a list chain inet pipelock_containment output_filter":
				return live, 0, nil
			case "-c -f /managed/50-pipelock-containment.nft.reload":
				return "", 0, nil
			case "-f /managed/50-pipelock-containment.nft.reload":
				bodyStart := strings.Index(reloadScript, "# Pipelock containment ruleset")
				if bodyStart < 0 {
					return "", 1, errors.New("reload script omitted canonical rules body")
				}
				// Apply the script's deletions to the live listing before adding the
				// canonical body, so a script that omits a deletion leaves the stale
				// rule behind and fails the assertions below. A fake that discards
				// deletions passes whether or not reconciliation removes anything.
				survivors, err := applyNFTDeletionsForTest(live, reloadScript[:bodyStart])
				if err != nil {
					return "", 1, err
				}
				live = strings.Join(append(survivors, nftListingFromRulesBodyForTest(reloadScript[bodyStart:], 100)), "\n")
				return "", 0, nil
			default:
				return "", 1, fmt.Errorf("unexpected nft command %q", strings.Join(args, " "))
			}
		},
	}

	for reload := 0; reload < 3; reload++ {
		if err := reloadNFTRules(context.Background(), env); err != nil {
			t.Fatalf("reload %d: %v", reload+1, err)
		}
	}
	handles := legacyManagedNFTRuleBlockHandles(live, loopbackTestOperatorUID, loopbackTestProxyUID, loopbackTestAgentUID)
	if len(handles) != 6 {
		t.Fatalf("after repeated reloads, got %d managed rules, want one namespace-era block of 6: %v", len(handles), handles)
	}
	for _, line := range foreign {
		// nft lists an established-reply rule in its numeric form, which is what a
		// live chain and therefore the reconciler actually see.
		want := numericNftStateListing(line)
		if !strings.Contains(live, want) {
			t.Fatalf("foreign rule was not preserved: %q\nlive:\n%s", want, live)
		}
	}
	if len(reports) != 3 || !strings.Contains(reports[0], "removed 31 managed rule(s)") || reports[1] != "containment nft rules already reconciled, no change" || reports[2] != "containment nft rules already reconciled, no change" {
		t.Fatalf("reports = %v, want one reconciliation followed by two no-op reports", reports)
	}
}

// TestLegacyLoopbackRuleMatchers keeps migration recognition narrow: reload
// may remove old host nft exceptions, but verify never treats them as safe.
func TestLegacyLoopbackRuleMatchers(t *testing.T) {
	t.Parallel()
	if !lineHasAgentLoopbackAllowForHost(`meta skuid 966 oifname "lo" ip daddr 127.0.0.1 tcp dport 9200 accept`, loopbackTestAgentUID, "127.0.0.1", 9200) {
		t.Fatal("legacy forward rule must be recognized for removal")
	}
	if lineHasAgentLoopbackAllowForHost("meta skuid 966 ip daddr 127.0.0.1 tcp dport 9200 accept", loopbackTestAgentUID, "127.0.0.1", 9200) {
		t.Fatal("an interface-unrestricted rule must not match the paired legacy form")
	}
	if lineHasAgentLoopbackReplyForHost(`meta skuid 966 oifname "lo" ip daddr 127.0.0.1 tcp sport 9200 ct state established ct direction reply accept`, loopbackTestAgentUID, "127.0.0.1", 9200) {
		t.Fatal("a destination-address reply rule must not be recognized")
	}
}

// TestUnsafeVerdictToleratesOnlyDeclaredLoopbackServices proves the core
// verify security decision: an undeclared loopback accept for the agent UID
// is unsafe, an accept the declared set names is not, and the implicit
// proxy-port allow keeps passing while every old host-loopback exception is
// rejected, even when the service remains declared for namespace forwarding.
func TestUnsafeVerdictRejectsLegacyLoopbackServices(t *testing.T) {
	t.Parallel()
	uids := containmentUIDs{operatorUID: loopbackTestOperatorUID, operatorKnown: true, proxyUID: loopbackTestProxyUID, agentUID: loopbackTestAgentUID}

	t.Run("undeclared loopback accept is unsafe", func(t *testing.T) {
		lines := []string{
			"meta skuid 966 ip daddr 127.0.0.1 tcp dport 9200 accept",
			"meta skuid 966 counter drop",
		}
		if !chainLinesHaveUnsafeVerdictBeforeAgentDrop(lines, uids, loopbackTestProxyPort) {
			t.Fatal("an undeclared loopback accept before the agent drop must be flagged unsafe")
		}
	})

	t.Run("formerly declared loopback accept is unsafe", func(t *testing.T) {
		lines := []string{
			`meta skuid 966 oifname "lo" ip daddr 127.0.0.1 tcp dport 9200 accept`,
			"meta skuid 966 counter drop",
		}
		if !chainLinesHaveUnsafeVerdictBeforeAgentDrop(lines, uids, loopbackTestProxyPort) {
			t.Fatal("a declared service no longer justifies a host nft accept")
		}
	})

	t.Run("implicit proxy port allow is never unsafe regardless of declared set", func(t *testing.T) {
		lines := []string{
			"meta skuid 966 ip daddr 127.0.0.1 tcp dport 8888 accept",
			"meta skuid 966 counter drop",
		}
		if chainLinesHaveUnsafeVerdictBeforeAgentDrop(lines, uids, loopbackTestProxyPort) {
			t.Fatal("the implicit proxy-port allow must never be flagged unsafe")
		}
	})

	t.Run("a declared service for a different port does not tolerate an undeclared one", func(t *testing.T) {
		lines := []string{
			"meta skuid 966 ip daddr 127.0.0.1 tcp dport 9300 accept",
			"meta skuid 966 counter drop",
		}
		if !chainLinesHaveUnsafeVerdictBeforeAgentDrop(lines, uids, loopbackTestProxyPort) {
			t.Fatal("an accept for an undeclared port must stay unsafe even with an unrelated declared service present")
		}
	})

	t.Run("formerly declared ::1 loopback accept is unsafe", func(t *testing.T) {
		lines := []string{
			`meta skuid 966 oifname "lo" ip6 daddr ::1 tcp dport 9200 accept`,
			"meta skuid 966 counter drop",
		}
		if !chainLinesHaveUnsafeVerdictBeforeAgentDrop(lines, uids, loopbackTestProxyPort) {
			t.Fatal("a declared ::1 service no longer justifies a host nft accept")
		}
	})

	t.Run("undeclared ::1 loopback accept is unsafe", func(t *testing.T) {
		lines := []string{
			"meta skuid 966 ip6 daddr ::1 tcp dport 9200 accept",
			"meta skuid 966 counter drop",
		}
		if !chainLinesHaveUnsafeVerdictBeforeAgentDrop(lines, uids, loopbackTestProxyPort) {
			t.Fatal("an undeclared ::1 loopback accept must be flagged unsafe")
		}
	})
}

// Declared IPv6 services are absent from the persisted host rules because the
// namespace socket inventory is their source of truth.
func TestVerifyPersistenceRendersDeclaredIPv6Service(t *testing.T) {
	t.Parallel()
	svc := loopbackTestService(9200)
	svc.Host = "::1"
	body := renderNFTRulesWithServices(nftRuleOptions{
		OperatorUID:      loopbackTestOperatorUID,
		ProxyUID:         loopbackTestProxyUID,
		AgentUID:         loopbackTestAgentUID,
		ProxyPort:        loopbackTestProxyPort,
		Table:            defaultNFTTable,
		Chain:            defaultNFTChain,
		LoopbackServices: []config.ContainmentLoopbackService{svc},
	})
	if strings.Contains(body, "::1") || strings.Contains(body, "9200") {
		t.Fatalf("rendered persisted rules unexpectedly carry declared ::1 service:\n%s", body)
	}
}

// TestContainmentLoopbackServicesFromMapping covers the decode-path error
// branches config_migrate.go shares with containmentMetricsExposureFromMapping:
// no containment key, a non-mapping containment, no loopback_services key,
// a non-sequence loopback_services, and a successful decode.
func TestContainmentLoopbackServicesFromMapping(t *testing.T) {
	t.Parallel()

	mustMapping := func(t *testing.T, yamlDoc string) *yaml.Node {
		t.Helper()
		root, err := parseSingleYAMLDocument([]byte(yamlDoc))
		if err != nil {
			t.Fatalf("parseSingleYAMLDocument: %v", err)
		}
		return documentMapping(root)
	}

	t.Run("no containment key", func(t *testing.T) {
		mapping := mustMapping(t, "fetch_proxy:\n  listen: 127.0.0.1:8888\n")
		declared, err := containmentLoopbackServicesFromMapping(mapping)
		if err != nil || declared != nil {
			t.Fatalf("got (%v, %v), want (nil, nil)", declared, err)
		}
	})

	t.Run("containment not a mapping", func(t *testing.T) {
		mapping := mustMapping(t, "containment: not-a-mapping\n")
		if _, err := containmentLoopbackServicesFromMapping(mapping); err == nil {
			t.Fatal("expected an error for a non-mapping containment key")
		}
	})

	t.Run("no loopback_services key", func(t *testing.T) {
		mapping := mustMapping(t, "containment:\n  metrics_exposure: null\n")
		declared, err := containmentLoopbackServicesFromMapping(mapping)
		if err != nil || declared != nil {
			t.Fatalf("got (%v, %v), want (nil, nil)", declared, err)
		}
	})

	t.Run("loopback_services not a sequence", func(t *testing.T) {
		mapping := mustMapping(t, "containment:\n  loopback_services: not-a-list\n")
		if _, err := containmentLoopbackServicesFromMapping(mapping); err == nil {
			t.Fatal("expected an error for a non-sequence loopback_services")
		}
	})

	t.Run("unknown field rejected", func(t *testing.T) {
		mapping := mustMapping(t, "containment:\n  loopback_services:\n  - host: 127.0.0.1\n    port: 9200\n    owner: x\n    reason: y\n    expires_at: \"2099-01-01T00:00:00Z\"\n    unknown_field: nope\n")
		if _, err := containmentLoopbackServicesFromMapping(mapping); err == nil {
			t.Fatal("expected an error for an unknown field")
		}
	})

	t.Run("successful decode", func(t *testing.T) {
		mapping := mustMapping(t, "containment:\n  loopback_services:\n  - host: 127.0.0.1\n    port: 9200\n    owner: x\n    reason: y\n    expires_at: \"2099-01-01T00:00:00Z\"\n")
		declared, err := containmentLoopbackServicesFromMapping(mapping)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(declared) != 1 || declared[0].Port != 9200 || declared[0].Host != "127.0.0.1" {
			t.Fatalf("got %+v, want one decoded entry on port 9200", declared)
		}
	})
}

// TestDeclaredContainmentLoopbackServices covers install.go's
// declaredContainmentLoopbackServices: a missing managed config is no
// declared exceptions, an unreadable-for-another-reason config is a hard
// install error, and a valid managed config decodes and validates.
func TestDeclaredContainmentLoopbackServices(t *testing.T) {
	t.Parallel()

	t.Run("missing managed config is no declared exceptions", func(t *testing.T) {
		env := &installEnv{configDir: "/etc/pipelock", readFile: func(string) ([]byte, error) { return nil, os.ErrNotExist }}
		declared, err := declaredContainmentLoopbackServices(env, 8888)
		if err != nil || declared != nil {
			t.Fatalf("got (%v, %v), want (nil, nil)", declared, err)
		}
	})

	t.Run("permission error fails install closed", func(t *testing.T) {
		env := &installEnv{configDir: "/etc/pipelock", readFile: func(string) ([]byte, error) { return nil, os.ErrPermission }}
		if _, err := declaredContainmentLoopbackServices(env, 8888); err == nil {
			t.Fatal("expected an error for an unreadable managed config")
		}
	})

	t.Run("invalid declared entry fails install closed", func(t *testing.T) {
		body := "containment:\n  loopback_services:\n  - host: 10.20.0.20\n    port: 9200\n    owner: x\n    reason: y\n    expires_at: \"2099-01-01T00:00:00Z\"\n"
		env := &installEnv{configDir: "/etc/pipelock", readFile: func(string) ([]byte, error) { return []byte(body), nil }}
		if _, err := declaredContainmentLoopbackServices(env, 8888); err == nil {
			t.Fatal("expected an error for a non-loopback declared host")
		}
	})

	t.Run("valid managed config decodes", func(t *testing.T) {
		body := "containment:\n  loopback_services:\n  - host: 127.0.0.1\n    port: 9200\n    owner: x\n    reason: y\n    expires_at: \"2099-01-01T00:00:00Z\"\n"
		env := &installEnv{configDir: "/etc/pipelock", readFile: func(string) ([]byte, error) { return []byte(body), nil }}
		declared, err := declaredContainmentLoopbackServices(env, 8888)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(declared) != 1 || declared[0].Port != 9200 {
			t.Fatalf("got %+v, want one decoded entry on port 9200", declared)
		}
	})

	t.Run("malformed yaml fails install closed", func(t *testing.T) {
		env := &installEnv{configDir: "/etc/pipelock", readFile: func(string) ([]byte, error) { return []byte("containment: [\n"), nil }}
		if _, err := declaredContainmentLoopbackServices(env, 8888); err == nil {
			t.Fatal("expected an error for malformed YAML")
		}
	})

	t.Run("non-mapping document fails install closed", func(t *testing.T) {
		env := &installEnv{configDir: "/etc/pipelock", readFile: func(string) ([]byte, error) { return []byte("- just\n- a\n- list\n"), nil }}
		if _, err := declaredContainmentLoopbackServices(env, 8888); err == nil {
			t.Fatal("expected an error for a non-mapping document")
		}
	})

	t.Run("unknown field in declared entry fails install closed", func(t *testing.T) {
		body := "containment:\n  loopback_services:\n  - host: 127.0.0.1\n    port: 9200\n    owner: x\n    reason: y\n    expires_at: \"2099-01-01T00:00:00Z\"\n    unknown_field: nope\n"
		env := &installEnv{configDir: "/etc/pipelock", readFile: func(string) ([]byte, error) { return []byte(body), nil }}
		if _, err := declaredContainmentLoopbackServices(env, 8888); err == nil {
			t.Fatal("expected an error for an unknown field in a declared entry")
		}
	})
}

// TestDeclaredContainmentLoopbackServicesForVerify covers verify.go's
// read-any-failure-as-empty-set behavior across every failure shape:
// unreadable, malformed YAML, non-mapping document, unknown field, and an
// invalid declared entry all report an empty set rather than an error, and
// a valid managed config decodes.
func TestDeclaredContainmentLoopbackServicesForVerify(t *testing.T) {
	t.Parallel()

	newEnv := func(body string, err error) *probeEnv {
		return &probeEnv{
			configPath: "/etc/pipelock/pipelock.yaml",
			readFile: func(string) ([]byte, error) {
				if err != nil {
					return nil, err
				}
				return []byte(body), nil
			},
		}
	}

	t.Run("absent managed config names that it was not found", func(t *testing.T) {
		env := newEnv("", os.ErrNotExist)
		declared, problem, unusable := declaredContainmentLoopbackServicesForVerify(env, 8888)
		if unusable != false {
			t.Errorf("unusable = %v, want false: a host with no managed config is not an unusable declaration; failing on it would refuse every host that has not got one", unusable)
		}
		if declared != nil {
			t.Fatalf("got %v, want nil", declared)
		}
		if !strings.Contains(problem, "no managed config was found") || !strings.Contains(problem, env.configPath) {
			t.Fatalf("problem = %q, want it to say no managed config was found and name the path", problem)
		}
	})

	t.Run("unreadable config (not absent) reports a problem", func(t *testing.T) {
		env := newEnv("", os.ErrPermission)
		declared, problem, unusable := declaredContainmentLoopbackServicesForVerify(env, 8888)
		if unusable != false {
			t.Errorf("unusable = %v, want false: an unreadable file cannot be told apart from a host that declared nothing", unusable)
		}
		if declared != nil {
			t.Fatalf("got %v, want nil", declared)
		}
		if problem == "" || strings.Contains(problem, "no managed config was found") {
			t.Fatalf("problem = %q, want a distinct unreadable-config problem, not the absent-config wording", problem)
		}
	})

	t.Run("malformed yaml", func(t *testing.T) {
		env := newEnv("containment: [", nil)
		declared, problem, unusable := declaredContainmentLoopbackServicesForVerify(env, 8888)
		if unusable != true {
			t.Errorf("unusable = %v, want true: the config exists and cannot be parsed", unusable)
		}
		if declared != nil {
			t.Fatalf("got %v, want nil", declared)
		}
		if problem == "" {
			t.Fatal("malformed YAML must surface a problem string naming the fallback")
		}
	})

	t.Run("non-mapping document", func(t *testing.T) {
		env := newEnv("- just\n- a\n- list\n", nil)
		declared, problem, unusable := declaredContainmentLoopbackServicesForVerify(env, 8888)
		if unusable != true {
			t.Errorf("unusable = %v, want true: the config exists and its shape is wrong", unusable)
		}
		if declared != nil {
			t.Fatalf("got %v, want nil", declared)
		}
		if problem == "" {
			t.Fatal("a non-mapping document must surface a problem string naming the fallback")
		}
	})

	t.Run("invalid declared entry", func(t *testing.T) {
		body := "containment:\n  loopback_services:\n  - host: 10.20.0.20\n    port: 9200\n    owner: x\n    reason: y\n    expires_at: \"2099-01-01T00:00:00Z\"\n"
		env := newEnv(body, nil)
		declared, problem, unusable := declaredContainmentLoopbackServicesForVerify(env, 8888)
		if unusable != true {
			t.Errorf("unusable = %v, want true: the config exists and its declaration fails validation", unusable)
		}
		if declared != nil {
			t.Fatalf("got %v, want nil", declared)
		}
		if !strings.Contains(problem, env.configPath) || !strings.Contains(problem, "loopback literal") {
			t.Fatalf("problem = %q, want it to name the config path and the validation failure", problem)
		}
	})

	t.Run("expired declared entry names host, owner, and reconciliation remedy", func(t *testing.T) {
		body := "containment:\n  loopback_services:\n  - host: 127.0.0.1\n    port: 9200\n    owner: search-team\n    reason: local index\n    expires_at: \"2000-01-01T00:00:00Z\"\n"
		env := newEnv(body, nil)
		declared, problem, unusable := declaredContainmentLoopbackServicesForVerify(env, 8888)
		if unusable != true {
			t.Errorf("unusable = %v, want true: an expired entry is a declaration this host can no longer honor", unusable)
		}
		if declared != nil {
			t.Fatalf("got %v, want nil", declared)
		}
		if !strings.Contains(problem, "expired at") {
			t.Fatalf("problem = %q, want it to name the expiry failure", problem)
		}
		if !strings.Contains(problem, "remove or re-approve") {
			t.Fatalf("problem = %q, want it to name the operator remedy", problem)
		}
	})

	t.Run("loopback_services not a sequence", func(t *testing.T) {
		body := "containment:\n  loopback_services: not-a-list\n"
		env := newEnv(body, nil)
		declared, problem, unusable := declaredContainmentLoopbackServicesForVerify(env, 8888)
		if unusable != true {
			t.Errorf("unusable = %v, want true: the config exists and the key's shape is wrong", unusable)
		}
		if declared != nil {
			t.Fatalf("got %v, want nil", declared)
		}
		if problem == "" {
			t.Fatal("a non-sequence loopback_services must surface a problem string naming the fallback")
		}
	})

	t.Run("valid managed config decodes", func(t *testing.T) {
		body := "containment:\n  loopback_services:\n  - host: 127.0.0.1\n    port: 9200\n    owner: x\n    reason: y\n    expires_at: \"2099-01-01T00:00:00Z\"\n"
		env := newEnv(body, nil)
		declared, problem, unusable := declaredContainmentLoopbackServicesForVerify(env, 8888)
		if unusable != false {
			t.Errorf("unusable = %v, want false: a declaration that parses and validates is usable", unusable)
		}
		if len(declared) != 1 || declared[0].Port != 9200 {
			t.Fatalf("got %+v, want one decoded entry on port 9200", declared)
		}
		if problem != "" {
			t.Fatalf("a valid declared set must not report a problem, got %q", problem)
		}
	})
}

// TestManagedNFTBlockLengthBoundaries covers managedNFTBlockLength's
// short-input and no-match branches directly.
func TestManagedNFTBlockLengthBoundaries(t *testing.T) {
	t.Parallel()

	t.Run("too few rules to even hold operator+proxy accepts", func(t *testing.T) {
		rules := []nftRuleWithHandle{{line: "meta skuid 1000 accept", handle: 1}}
		if got, _ := managedNFTBlockLength(rules, 0, 1000, 967, 966); got != 0 {
			t.Fatalf("got %d, want 0", got)
		}
	})

	t.Run("operator accept missing", func(t *testing.T) {
		rules := []nftRuleWithHandle{
			{line: "meta skuid 999 accept", handle: 1},
			{line: "meta skuid 967 accept", handle: 2},
			{line: "meta skuid 966 ip daddr 127.0.0.1 tcp dport 8888 accept", handle: 3},
		}
		if got, _ := managedNFTBlockLength(rules, 0, 1000, 967, 966); got != 0 {
			t.Fatalf("got %d, want 0", got)
		}
	})

	t.Run("no loopback allow at all", func(t *testing.T) {
		rules := []nftRuleWithHandle{
			{line: "meta skuid 1000 accept", handle: 1},
			{line: "meta skuid 967 accept", handle: 2},
			{line: "meta skuid 966 counter drop", handle: 3},
		}
		if got, _ := managedNFTBlockLength(rules, 0, 1000, 967, 966); got != 0 {
			t.Fatalf("got %d, want 0", got)
		}
	})

	t.Run("loopback allow present but tail truncated", func(t *testing.T) {
		rules := []nftRuleWithHandle{
			{line: "meta skuid 1000 accept", handle: 1},
			{line: "meta skuid 967 accept", handle: 2},
			{line: "meta skuid 966 ip daddr 127.0.0.1 tcp dport 8888 accept", handle: 3},
			{line: `meta skuid 966 udp dport 53 counter packets 0 bytes 0 log prefix "pipelock-contain class=direct_dns_blocked " drop`, handle: 4},
		}
		if got, _ := managedNFTBlockLength(rules, 0, 1000, 967, 966); got != 0 {
			t.Fatalf("got %d, want 0 (tail incomplete)", got)
		}
	})
}

// TestLineHasAgentLoopbackAllowForHostShortLine covers the too-short-line
// branch of lineHasAgentLoopbackAllowForHost directly.
func TestLineHasAgentLoopbackAllowForHostShortLine(t *testing.T) {
	t.Parallel()
	if lineHasAgentLoopbackAllowForHost("meta skuid 966 accept", 966, "127.0.0.1", 9200) {
		t.Fatal("a too-short line must not match")
	}
}

// TestReloadRecognizesBlockWithIPv6DeclaredLoopbackService proves reload
// recognizes and replaces a managed block that carries a ::1 declared
// loopback service, not only 127.0.0.1 ones. This test is written to FAIL
// against managedNFTBlockLength's original ip-daddr-only recognition (proven
// below by neutralizing the fix and re-running), and to PASS once
// managedNFTBlockLength recognizes both address families via
// lineHasAgentLoopbackAllowAnyPortAnyHost.
func TestReloadRecognizesBlockWithIPv6DeclaredLoopbackService(t *testing.T) {
	t.Parallel()

	ipv6Service := loopbackTestService(9200)
	ipv6Service.Host = "::1"

	block := strings.Join([]string{
		`meta skuid 1000 accept # handle 20`,
		`meta skuid 967 accept # handle 21`,
		`meta skuid 966 ip daddr 127.0.0.1 tcp dport 8888 accept # handle 22`,
		`meta skuid 966 ip6 daddr ::1 tcp dport 9200 accept # handle 23`,
		`meta skuid 966 oifname "lo" ip6 daddr ::1 tcp sport 9200 ct state established ct direction reply accept # handle 24`,
		`meta skuid 966 udp dport 53 counter packets 0 bytes 0 log prefix "pipelock-contain class=direct_dns_blocked " drop # handle 25`,
		`meta skuid 966 tcp dport 53 counter packets 0 bytes 0 log prefix "pipelock-contain class=direct_dns_blocked " drop # handle 26`,
		`meta skuid 966 counter packets 0 bytes 0 log prefix "pipelock-contain class=not_routing_through_pipelock " drop # handle 27`,
	}, "\n")
	live := strings.Join([]string{
		`table inet pipelock_containment {`,
		`  chain output_filter { type filter hook output priority filter; policy accept;`,
		block,
		`  }`,
		`}`,
	}, "\n")

	handles := legacyManagedNFTRuleBlockHandles(live, loopbackTestOperatorUID, loopbackTestProxyUID, loopbackTestAgentUID)
	if len(handles) != 8 {
		t.Fatalf("got %d handles, want 8 (6 base + 1 declared pair): %v", len(handles), handles)
	}

	newRules := RenderNFTRulesWithLoopbackServices(loopbackTestOperatorUID, loopbackTestProxyUID, loopbackTestAgentUID, loopbackTestProxyPort, []config.ContainmentLoopbackService{ipv6Service})
	script := renderNFTManagedChainReloadScript(live, newRules, defaultNFTTable, defaultNFTChain, loopbackTestOperatorUID, loopbackTestProxyUID, loopbackTestAgentUID, true)
	for _, handle := range []int{20, 21, 22, 23, 24, 25, 26, 27} {
		want := "delete rule inet pipelock_containment output_filter handle " + itoa(handle)
		if !strings.Contains(script, want) {
			t.Fatalf("reload script missing delete for handle %d (block not recognized, would append a second block):\n%s", handle, script)
		}
	}
	if strings.Contains(script, "ip6 daddr ::1 tcp dport 9200 accept") {
		t.Fatalf("reload must remove the legacy ::1 accept without adding a host replacement:\n%s", script)
	}
}

// TestProbeNFTContainmentSurfacesLoopbackConfigProblemDetail is the
// end-to-end LOW-severity proof: when an expired (or otherwise unusable)
// declared loopback service collapses to an empty set, and the live chain
// still carries an undeclared loopback accept as a result, the FAIL detail
// names the config problem (host:port, owner, why) and the remedy, not just
// the generic "unexpected verdict before agent drop".
func TestProbeNFTContainmentSurfacesLoopbackConfigProblemDetail(t *testing.T) {
	t.Parallel()
	expiredConfigBody := "containment:\n  loopback_services:\n  - host: 127.0.0.1\n    port: 9200\n    owner: search-team\n    reason: local index\n    expires_at: \"2000-01-01T00:00:00Z\"\n"
	liveWithUndeclaredAccept := strings.Replace(goodNFTContainmentOutput,
		"meta skuid 987 ip daddr 127.0.0.1 tcp dport 8888 accept",
		"meta skuid 987 ip daddr 127.0.0.1 tcp dport 8888 accept\n\t\tmeta skuid 987 ip daddr 127.0.0.1 tcp dport 9200 accept", 1)

	base := makeProbeEnv(t, func(e *probeEnv) {
		e.operatorUser = testOperatorUser
		e.lookupUser = containTestLookup
		e.nftRulesPath = "rules.nft"
		e.readFile = func(path string) ([]byte, error) {
			if path == e.configPath {
				return []byte(expiredConfigBody), nil
			}
			return []byte("# operator=1000 pipelock-proxy=988 pipelock-agent=987 proxy-port=8888\n"), nil
		}
		e.runCmd = func(context.Context, string, ...string) (string, int, error) {
			return liveWithUndeclaredAccept, 0, nil
		}
	})

	status, detail := probeNFTContainment(context.Background(), base)
	if status != statusFail {
		t.Fatalf("status = %q, want fail", status)
	}
	if !strings.Contains(detail, "127.0.0.1:9200") {
		t.Fatalf("detail = %q, want the declared host:port named", detail)
	}
	if !strings.Contains(detail, "owner=search-team") {
		t.Fatalf("detail = %q, want the declared owner named", detail)
	}
	if !strings.Contains(detail, "expired at") {
		t.Fatalf("detail = %q, want the expiry failure named", detail)
	}
	if !strings.Contains(detail, "remove or re-approve") {
		t.Fatalf("detail = %q, want the operator remedy named", detail)
	}
}

// nftReloadTestFixture builds a nftReloadEnv for the HIGH-severity end-to-end
// reconciliation tests: the persisted rules file and the live chain both
// start with the OLD declared shape (base or with a since-changed loopback
// service), and the managed config carries the CURRENT declaration. The
// returned getters observe what reloadNFTRules actually applied and
// persisted.
type nftReloadTestFixture struct {
	env          *nftReloadEnv
	warnings     []string
	appliedBody  func() string // the freshly rendered rules body loaded via -f
	persisted    func() (string, bool)
	deleteHandle func(handle int) bool
}

func newNFTReloadTestFixture(t *testing.T, live, configBody, persistedRules string) *nftReloadTestFixture {
	t.Helper()
	const rulesPath = "/managed/50-pipelock-containment.nft"
	const configPath = "/etc/pipelock/pipelock.yaml"

	fx := &nftReloadTestFixture{}
	writes := make(map[string]string)
	var reloadScript string

	fx.env = &nftReloadEnv{
		nftPath:    "nft",
		rulesPath:  rulesPath,
		configPath: configPath,
		table:      defaultNFTTable,
		chain:      defaultNFTChain,
		now:        func() time.Time { return time.Unix(1_800_000_000, 0) },
		warn: func(msg string) {
			fx.warnings = append(fx.warnings, msg)
		},
		readFile: func(path string) ([]byte, error) {
			switch path {
			case rulesPath:
				return []byte(persistedRules), nil
			case configPath:
				return []byte(configBody), nil
			default:
				return nil, fmt.Errorf("unexpected read %q", path)
			}
		},
		writeFile: func(path string, data []byte, _ os.FileMode) error {
			writes[path] = string(data)
			if path == rulesPath+".reload" {
				reloadScript = string(data)
			}
			return nil
		},
		removeFile: func(path string) error {
			delete(writes, path)
			return nil
		},
		runCmd: func(_ context.Context, _ string, args ...string) (string, int, error) {
			joined := strings.Join(args, " ")
			switch {
			case strings.HasPrefix(joined, "-n -a list chain"):
				return live, 0, nil
			case strings.HasPrefix(joined, "-c -f "), strings.HasPrefix(joined, "-f "):
				return "", 0, nil
			default:
				return "", 1, fmt.Errorf("unexpected nft invocation: %s", joined)
			}
		},
	}
	fx.appliedBody = func() string { return reloadScript }
	fx.persisted = func() (string, bool) {
		body, ok := writes[rulesPath]
		return body, ok
	}
	fx.deleteHandle = func(handle int) bool {
		return strings.Contains(reloadScript, "delete rule inet "+defaultNFTTable+" "+defaultNFTChain+" handle "+itoa(handle))
	}
	return fx
}

const nftReloadTestLiveWithOneService = `table inet pipelock_containment {
  chain output_filter { type filter hook output priority filter; policy accept;
    meta skuid 966 oifname "lo" ip daddr 127.0.0.1 tcp sport 9119 ct state established ct direction reply accept # handle 10
    meta skuid 1000 accept # handle 20
    meta skuid 967 accept # handle 21
    meta skuid 966 ip daddr 127.0.0.1 tcp dport 8888 accept # handle 22
    meta skuid 966 ip daddr 127.0.0.1 tcp dport 9200 accept # handle 23
    meta skuid 966 oifname "lo" ip daddr 127.0.0.1 tcp sport 9200 ct state established ct direction reply accept # handle 24
    meta skuid 966 udp dport 53 counter packets 0 bytes 0 log prefix "pipelock-contain class=direct_dns_blocked " drop # handle 25
    meta skuid 966 tcp dport 53 counter packets 0 bytes 0 log prefix "pipelock-contain class=direct_dns_blocked " drop # handle 26
    meta skuid 966 counter packets 0 bytes 0 log prefix "pipelock-contain class=not_routing_through_pipelock " drop # handle 27
  }
}
`

const nftReloadTestLiveWithNoService = `table inet pipelock_containment {
  chain output_filter { type filter hook output priority filter; policy accept;
    meta skuid 1000 accept # handle 20
    meta skuid 967 accept # handle 21
    meta skuid 966 ip daddr 127.0.0.1 tcp dport 8888 accept # handle 22
    meta skuid 966 udp dport 53 counter packets 0 bytes 0 log prefix "pipelock-contain class=direct_dns_blocked " drop # handle 23
    meta skuid 966 tcp dport 53 counter packets 0 bytes 0 log prefix "pipelock-contain class=direct_dns_blocked " drop # handle 24
    meta skuid 966 counter packets 0 bytes 0 log prefix "pipelock-contain class=not_routing_through_pipelock " drop # handle 25
  }
}
`

// nftReloadTestConfigWithService always declares port 9200 -- every
// fixture in this file that pairs with it (nftReloadTestLiveWithOneService,
// etc.) hardcodes that same port -- so it takes only expiresAt.
func nftReloadTestConfigWithService(expiresAt string) string {
	return "containment:\n  loopback_services:\n  - host: 127.0.0.1\n    port: 9200" +
		"\n    owner: search-team\n    reason: local index\n    expires_at: \"" + expiresAt + "\"\n"
}

// TestReloadNFTRulesReconcilesAddedLoopbackService: a declared entry that
// was never installed (the live chain and persisted file only carry the
// base block) is added to the managed config, and the NEXT reload -- not a
// re-run of `contain install` -- loads it.
func TestReloadNFTRulesReconcilesAddedLoopbackService(t *testing.T) {
	t.Parallel()
	basePersisted := renderNFTRules(loopbackTestOperatorUID, loopbackTestProxyUID, loopbackTestAgentUID, loopbackTestProxyPort, defaultNFTTable, defaultNFTChain)
	fx := newNFTReloadTestFixture(t, nftReloadTestLiveWithNoService, nftReloadTestConfigWithService("2099-01-01T00:00:00Z"), basePersisted)
	var forwarded []config.ContainmentLoopbackService
	fx.env.reconcileForwarders = func(_ context.Context, services []config.ContainmentLoopbackService) error {
		forwarded = append([]config.ContainmentLoopbackService(nil), services...)
		return nil
	}
	if err := reloadNFTRules(context.Background(), fx.env); err != nil {
		t.Fatalf("reloadNFTRules: %v", err)
	}
	if len(forwarded) != 1 || forwarded[0].Port != 9200 {
		t.Fatalf("namespace forwarders = %+v, want declared port 9200", forwarded)
	}
	if strings.Contains(fx.appliedBody(), "9200") {
		t.Fatalf("declared service leaked into host nft transaction:\n%s", fx.appliedBody())
	}
	if len(fx.warnings) != 0 {
		t.Fatalf("a valid new declaration must not warn, got %v", fx.warnings)
	}
}

// TestReloadNFTRulesReconcilesRevokedLoopbackService is the HIGH-severity
// proof: an operator REMOVES a declared entry from the managed config
// (never touching contain install), and the next reload drops the live
// accept and rewrites the persisted file to match -- it does not persist
// forever because reload used to trust the stale file verbatim.
func TestReloadNFTRulesReconcilesRevokedLoopbackService(t *testing.T) {
	t.Parallel()
	withServicePersisted := RenderNFTRulesWithLoopbackServices(loopbackTestOperatorUID, loopbackTestProxyUID, loopbackTestAgentUID, loopbackTestProxyPort, []config.ContainmentLoopbackService{loopbackTestService(9200)})
	fx := newNFTReloadTestFixture(t, nftReloadTestLiveWithOneService, "mode: balanced\n", withServicePersisted) // managed config with the entry simply removed
	var forwarded []config.ContainmentLoopbackService
	fx.env.reconcileForwarders = func(_ context.Context, services []config.ContainmentLoopbackService) error {
		forwarded = append([]config.ContainmentLoopbackService(nil), services...)
		return nil
	}
	if err := reloadNFTRules(context.Background(), fx.env); err != nil {
		t.Fatalf("reloadNFTRules: %v", err)
	}
	for _, handle := range []int{20, 21, 22, 23, 24, 25, 26, 27} {
		if !fx.deleteHandle(handle) {
			t.Fatalf("expected delete for old handle %d (including the revoked service's accept) in:\n%s", handle, fx.appliedBody())
		}
	}
	if strings.Contains(fx.appliedBody(), "dport 9200 accept") || strings.Contains(fx.appliedBody(), "sport 9200 ct state established ct direction reply accept") {
		t.Fatalf("revoked service's complete pair must not be reloaded:\n%s", fx.appliedBody())
	}
	if fx.deleteHandle(10) {
		t.Fatalf("reload removed foreign non-paired reply handle 10:\n%s", fx.appliedBody())
	}
	if len(forwarded) != 0 {
		t.Fatalf("revoked namespace forwarders = %+v, want none", forwarded)
	}
}

// TestReloadNFTRulesReconcilesExpiredLoopbackService: an entry is still
// present in the managed config but its expires_at has passed. Reload
// treats the whole declared set as invalid (matching ValidateContainmentLoopbackServices'
// atomic validation), drops the live accept the same way a revoked entry is
// dropped, and warns naming the entry and why.
func TestReloadNFTRulesReconcilesExpiredLoopbackService(t *testing.T) {
	t.Parallel()
	withServicePersistedExpired := RenderNFTRulesWithLoopbackServices(loopbackTestOperatorUID, loopbackTestProxyUID, loopbackTestAgentUID, loopbackTestProxyPort, []config.ContainmentLoopbackService{loopbackTestService(9200)})
	fx := newNFTReloadTestFixture(t, nftReloadTestLiveWithOneService, nftReloadTestConfigWithService("2000-01-01T00:00:00Z"), withServicePersistedExpired)
	var forwarded []config.ContainmentLoopbackService
	fx.env.reconcileForwarders = func(_ context.Context, services []config.ContainmentLoopbackService) error {
		forwarded = append([]config.ContainmentLoopbackService(nil), services...)
		return nil
	}
	if err := reloadNFTRules(context.Background(), fx.env); err != nil {
		t.Fatalf("reloadNFTRules: %v", err)
	}
	if strings.Contains(fx.appliedBody(), "dport 9200 accept") || strings.Contains(fx.appliedBody(), "sport 9200 ct state established ct direction reply accept") {
		t.Fatalf("expired service's complete pair must not be reloaded:\n%s", fx.appliedBody())
	}
	if len(forwarded) != 0 {
		t.Fatalf("expired namespace forwarders = %+v, want none", forwarded)
	}
	if len(fx.warnings) != 1 {
		t.Fatalf("expected exactly one warning naming the dropped entry, got %v", fx.warnings)
	}
	if !strings.Contains(fx.warnings[0], "expired at") || !strings.Contains(fx.warnings[0], "reload-nft-rules") {
		t.Fatalf("warning = %q, want it to name the expiry and the reconciliation command", fx.warnings[0])
	}
}

// TestReloadNFTRulesFailsClosedOnUnreadableManagedConfig proves the
// unreadable-managed-config branch of reconcileDeclaredContainmentLoopbackServicesForReload:
// a permission error (not a missing file) still renders zero declared
// services rather than erroring the whole reload, and warns.
func TestReloadNFTRulesFailsClosedOnUnreadableManagedConfig(t *testing.T) {
	t.Parallel()
	basePersistedUnreadable := renderNFTRules(loopbackTestOperatorUID, loopbackTestProxyUID, loopbackTestAgentUID, loopbackTestProxyPort, defaultNFTTable, defaultNFTChain)
	fx := newNFTReloadTestFixture(t, nftReloadTestLiveWithOneService, "mode: balanced\n", basePersistedUnreadable)
	fx.env.readFile = func(path string) ([]byte, error) {
		if path == fx.env.configPath {
			return nil, os.ErrPermission
		}
		return []byte(renderNFTRules(loopbackTestOperatorUID, loopbackTestProxyUID, loopbackTestAgentUID, loopbackTestProxyPort, defaultNFTTable, defaultNFTChain)), nil
	}
	if err := reloadNFTRules(context.Background(), fx.env); err != nil {
		t.Fatalf("reloadNFTRules: %v", err)
	}
	if strings.Contains(fx.appliedBody(), "dport 9200 accept") {
		t.Fatalf("an unreadable managed config must render zero declared services, got:\n%s", fx.appliedBody())
	}
	if len(fx.warnings) != 1 || !strings.Contains(fx.warnings[0], "unreadable") {
		t.Fatalf("expected exactly one unreadable-config warning, got %v", fx.warnings)
	}
}

// TestReloadNFTRulesWarnsOnAbsentManagedConfig is the LOW-severity fix: a
// genuinely absent managed config (os.ErrNotExist) is not silently treated
// as "declares nothing" -- it still renders zero declared services (the
// only safe choice), but it warns naming the path and the recovery command,
// matching what the docs already promised for an unreadable config.
func TestReloadNFTRulesWarnsOnAbsentManagedConfig(t *testing.T) {
	t.Parallel()
	basePersisted := renderNFTRules(loopbackTestOperatorUID, loopbackTestProxyUID, loopbackTestAgentUID, loopbackTestProxyPort, defaultNFTTable, defaultNFTChain)
	fx := newNFTReloadTestFixture(t, nftReloadTestLiveWithNoService, "mode: balanced\n", basePersisted)
	fx.env.readFile = func(path string) ([]byte, error) {
		if path == fx.env.configPath {
			return nil, os.ErrNotExist
		}
		return []byte(basePersisted), nil
	}
	if err := reloadNFTRules(context.Background(), fx.env); err != nil {
		t.Fatalf("reloadNFTRules: %v", err)
	}
	if len(fx.warnings) != 1 {
		t.Fatalf("expected exactly one absent-config warning, got %v", fx.warnings)
	}
	if !strings.Contains(fx.warnings[0], "not found") || !strings.Contains(fx.warnings[0], "contain install") {
		t.Fatalf("warning = %q, want it to say the config was not found and name `pipelock contain install`", fx.warnings[0])
	}
}

func TestReloadNFTRulesReportsNamespaceForwarderFailures(t *testing.T) {
	t.Parallel()
	basePersisted := renderNFTRules(loopbackTestOperatorUID, loopbackTestProxyUID, loopbackTestAgentUID, loopbackTestProxyPort, defaultNFTTable, defaultNFTChain)

	t.Run("no-op nft reconciliation", func(t *testing.T) {
		fx := newNFTReloadTestFixture(t, nftReloadTestLiveWithNoService, "mode: balanced\n", basePersisted)
		fx.env.reconcileForwarders = func(context.Context, []config.ContainmentLoopbackService) error {
			return errors.New("forwarder failed")
		}
		err := reloadNFTRules(context.Background(), fx.env)
		if err == nil || !strings.Contains(err.Error(), "namespace loopback forwarders failed to reconcile") {
			t.Fatalf("reload error = %v, want no-op forwarder reconciliation failure", err)
		}
	})

	t.Run("after nft rewrite", func(t *testing.T) {
		fx := newNFTReloadTestFixture(t, nftReloadTestLiveWithOneService, "mode: balanced\n", basePersisted)
		fx.env.reconcileForwarders = func(context.Context, []config.ContainmentLoopbackService) error {
			return errors.New("forwarder failed")
		}
		err := reloadNFTRules(context.Background(), fx.env)
		if err == nil || !strings.Contains(err.Error(), "nft boundary is current") {
			t.Fatalf("reload error = %v, want post-rewrite forwarder reconciliation failure", err)
		}
	})
}

func TestReloadNFTRulesLegacyReceiverQueryFailures(t *testing.T) {
	t.Parallel()
	basePersisted := renderNFTRules(loopbackTestOperatorUID, loopbackTestProxyUID, loopbackTestAgentUID, loopbackTestProxyPort, defaultNFTTable, defaultNFTChain)
	live := strings.Replace(nftReloadTestLiveWithNoService, "meta skuid 1000 accept", `ct mark set 0x504c4b01 socket cgroupv2 level 1 "pipelock_contained.slice" # handle 19
    meta skuid 1000 accept`, 1)

	t.Run("command error", func(t *testing.T) {
		fx := newNFTReloadTestFixture(t, live, "mode: balanced\n", basePersisted)
		err := reloadNFTRules(context.Background(), fx.env)
		if err == nil || !strings.Contains(err.Error(), "list legacy owned loopback receiver chain") {
			t.Fatalf("reload error = %v, want legacy receiver query error", err)
		}
	})

	t.Run("non-missing exit", func(t *testing.T) {
		fx := newNFTReloadTestFixture(t, live, "mode: balanced\n", basePersisted)
		originalRun := fx.env.runCmd
		fx.env.runCmd = func(ctx context.Context, name string, args ...string) (string, int, error) {
			if strings.HasPrefix(strings.Join(args, " "), "-n list chain") {
				return "permission denied", 1, nil
			}
			return originalRun(ctx, name, args...)
		}
		err := reloadNFTRules(context.Background(), fx.env)
		if err == nil || !strings.Contains(err.Error(), "exit=1: permission denied") {
			t.Fatalf("reload error = %v, want legacy receiver non-missing exit", err)
		}
	})
}

// statefulFakeFS is a minimal path->bytes store for the HIGH-severity
// crash-persistence proofs below: unlike nftReloadTestFixture's closures
// (which always read back a FIXED initial value regardless of what writeFile
// was told to store), this actually remembers what was last successfully
// written, so a test can prove a FAILED write left the previous content in
// place by reading it back afterward.
type statefulFakeFS struct {
	mu    sync.Mutex
	files map[string][]byte
	// failWriteOnce, if non-empty, makes the NEXT writeFile call to this
	// exact path fail once (simulating a crash mid-write or a failed
	// rename) without touching the stored content, then clears itself.
	failWriteOnce string
	failWriteErr  error
}

func newStatefulFakeFS(seed map[string][]byte) *statefulFakeFS {
	files := make(map[string][]byte, len(seed))
	for k, v := range seed {
		files[k] = append([]byte(nil), v...)
	}
	return &statefulFakeFS{files: files}
}

func (fs *statefulFakeFS) readFile(path string) ([]byte, error) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	data, ok := fs.files[path]
	if !ok {
		return nil, os.ErrNotExist
	}
	return append([]byte(nil), data...), nil
}

func (fs *statefulFakeFS) writeFile(path string, data []byte, _ os.FileMode) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	if fs.failWriteOnce == path {
		fs.failWriteOnce = ""
		if fs.failWriteErr == nil {
			return fmt.Errorf("simulated write failure for %s", path)
		}
		return fs.failWriteErr
	}
	fs.files[path] = append([]byte(nil), data...)
	return nil
}

func (fs *statefulFakeFS) removeFile(path string) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	delete(fs.files, path)
	return nil
}

// TestReloadNFTRulesWriteFailureLeavesPreviousFileIntact is the HIGH-severity
// crash-persistence proof, first half: if persisting the reconciled rules
// fails (simulating a crash mid-write or a failed atomic rename), the
// PREVIOUS known-good persisted rules file is left completely untouched --
// reloadNFTRules must never call the kernel with a transaction it could not
// durably record, and must never leave the file in a state between old and
// new.
func TestReloadNFTRulesWriteFailureLeavesPreviousFileIntact(t *testing.T) {
	t.Parallel()
	const rulesPath = "/managed/50-pipelock-containment.nft"
	const configPath = "/etc/pipelock/pipelock.yaml"
	oldRules := renderNFTRules(loopbackTestOperatorUID, loopbackTestProxyUID, loopbackTestAgentUID, loopbackTestProxyPort, defaultNFTTable, defaultNFTChain) + "# stale revision\n"
	fs := newStatefulFakeFS(map[string][]byte{
		rulesPath:  []byte(oldRules),
		configPath: []byte(nftReloadTestConfigWithService("2099-01-01T00:00:00Z")), // a NEW declared service, so the reconciled body differs
	})
	fs.failWriteOnce = rulesPath // fail exactly the persist-new-content write

	env := &nftReloadEnv{
		nftPath:           "nft",
		rulesPath:         rulesPath,
		configPath:        configPath,
		reconcileLockPath: t.TempDir() + "/reconcile.lock",
		table:             defaultNFTTable,
		chain:             defaultNFTChain,
		now:               func() time.Time { return time.Unix(1_800_000_000, 0) },
		readFile:          fs.readFile,
		writeFile:         fs.writeFile,
		removeFile:        fs.removeFile,
		runCmd: func(context.Context, string, ...string) (string, int, error) {
			t.Fatal("the kernel must never be touched when persisting the reconciled file failed first")
			return "", 1, nil
		},
	}

	err := reloadNFTRules(context.Background(), env)
	if err == nil {
		t.Fatal("expected an error when persisting the reconciled rules file fails")
	}
	got, readErr := fs.readFile(rulesPath)
	if readErr != nil {
		t.Fatalf("read back rules file: %v", readErr)
	}
	if string(got) != oldRules {
		t.Fatalf("previous known-good rules file was not left intact after a failed write:\ngot:\n%s\nwant:\n%s", got, oldRules)
	}
}

// TestReloadNFTRulesKernelFailureRestoresPreviousFile is the HIGH-severity
// crash-persistence proof, second half: the reconciled file is persisted
// FIRST (so a crash right after can never corrupt it -- writeFileAtomic in
// production always leaves either the old or the new content, never a
// partial write), but if the KERNEL transaction that follows then fails,
// reloadNFTRules restores the file to its PREVIOUS content rather than
// leaving it claiming a state the kernel never reached.
func TestReloadNFTRulesKernelFailureRestoresPreviousFile(t *testing.T) {
	t.Parallel()
	const rulesPath = "/managed/50-pipelock-containment.nft"
	const configPath = "/etc/pipelock/pipelock.yaml"
	oldRules := renderNFTRules(loopbackTestOperatorUID, loopbackTestProxyUID, loopbackTestAgentUID, loopbackTestProxyPort, defaultNFTTable, defaultNFTChain) + "# stale revision\n"
	fs := newStatefulFakeFS(map[string][]byte{
		rulesPath:  []byte(oldRules),
		configPath: []byte(nftReloadTestConfigWithService("2099-01-01T00:00:00Z")),
	})

	env := &nftReloadEnv{
		nftPath:           "nft",
		rulesPath:         rulesPath,
		configPath:        configPath,
		reconcileLockPath: t.TempDir() + "/reconcile.lock",
		table:             defaultNFTTable,
		chain:             defaultNFTChain,
		now:               func() time.Time { return time.Unix(1_800_000_000, 0) },
		readFile:          fs.readFile,
		writeFile:         fs.writeFile,
		removeFile:        fs.removeFile,
		runCmd: func(_ context.Context, _ string, args ...string) (string, int, error) {
			joined := strings.Join(args, " ")
			switch {
			case strings.HasPrefix(joined, "-n -a list chain"):
				return "", 0, nil // no live chain yet: first-boot state
			default:
				// Every kernel-facing invocation (validate and apply) fails,
				// simulating an nft rejection after the file was already
				// persisted.
				return "", 1, fmt.Errorf("simulated nft failure")
			}
		},
	}

	err := reloadNFTRules(context.Background(), env)
	if err == nil {
		t.Fatal("expected an error when the kernel transaction fails")
	}
	got, readErr := fs.readFile(rulesPath)
	if readErr != nil {
		t.Fatalf("read back rules file: %v", readErr)
	}
	if string(got) != oldRules {
		t.Fatalf("rules file was not restored to its previous content after a failed kernel load:\ngot:\n%s\nwant:\n%s", got, oldRules)
	}
}

// TestReloadNFTRulesFailsClosedOnEmptyPersistedFile is the boot-reloader
// half of the HIGH-severity fix: an empty or partial persisted rules file
// (the exact state a crash mid-write used to be able to leave, before
// atomic writes) makes reloadNFTRules error -- fail closed, load no
// partial/zero-UID chain -- naming the recovery command.
func TestReloadNFTRulesFailsClosedOnEmptyPersistedFile(t *testing.T) {
	t.Parallel()
	for name, content := range map[string]string{
		"empty":   "",
		"partial": "# operator=1000 pipelock-p", // truncated mid-header, no agent/proxy-port
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			env := &nftReloadEnv{
				nftPath:           "nft",
				rulesPath:         "/managed/50-pipelock-containment.nft",
				configPath:        "/etc/pipelock/pipelock.yaml",
				reconcileLockPath: t.TempDir() + "/reconcile.lock",
				table:             defaultNFTTable,
				chain:             defaultNFTChain,
				readFile: func(path string) ([]byte, error) {
					if path == "/managed/50-pipelock-containment.nft" {
						return []byte(content), nil
					}
					return nil, os.ErrNotExist
				},
				writeFile: func(string, []byte, os.FileMode) error {
					t.Fatal("must not attempt any write when the persisted rules file cannot be parsed")
					return nil
				},
				removeFile: func(string) error { return nil },
				runCmd: func(context.Context, string, ...string) (string, int, error) {
					t.Fatal("must not touch the kernel when the persisted rules file cannot be parsed")
					return "", 1, nil
				},
			}
			err := reloadNFTRules(context.Background(), env)
			if err == nil {
				t.Fatal("expected an error for an empty/partial persisted rules file")
			}
			if !strings.Contains(err.Error(), "pipelock contain install") {
				t.Fatalf("error = %v, want it to name the recovery command `pipelock contain install`", err)
			}
		})
	}
}

// TestInstallReloadInterleavingConvergesOnLatestConfig is the HIGH-severity
// proof for the install/reload race: a reload that snapshotted config A is
// paused (via pauseAfterSnapshot, widening the race window
// deterministically instead of depending on OS scheduling) while a
// concurrent `contain install`-shaped critical section promotes config B
// and applies+persists it, using the SAME withContainmentReconcileLock the
// production code shares between `contain install` and `contain
// reload-nft-rules`. The reload then resumes and finishes applying its
// stale A snapshot. Because both critical sections -- snapshot through
// apply through persist -- run under the one exclusive lock, "install"
// cannot even start until "reload" fully releases it, so whichever runs
// LAST re-reads the CURRENT config and wins: here that is install/B. The
// final live chain and persisted file must both reflect B, not a B-then-A
// regression.
func TestInstallReloadInterleavingConvergesOnLatestConfig(t *testing.T) {
	const rulesPath = "/managed/50-pipelock-containment.nft"
	const configPath = "/etc/pipelock/pipelock.yaml"
	lockPath := containmentReconcileLockPathFor(filepath.Join(t.TempDir(), "50-pipelock-containment.nft")) // mirrors the derived production path

	baseRules := renderNFTRules(loopbackTestOperatorUID, loopbackTestProxyUID, loopbackTestAgentUID, loopbackTestProxyPort, defaultNFTTable, defaultNFTChain)
	configA := nftReloadTestConfigWithService("2099-01-01T00:00:00Z")
	configB := "mode: balanced\n" // B revokes the declared service entirely

	fs := newStatefulFakeFS(map[string][]byte{
		rulesPath:  []byte(baseRules),
		configPath: []byte(configA),
	})

	reloadPaused := make(chan struct{})
	resumeReload := make(chan struct{})
	installEnteredLock := make(chan struct{}, 1)
	installDone := make(chan struct{})

	// "Live kernel" is modeled as the last-applied rules body, protected by
	// its own mutex (independent of the fake FS, mirroring how the real nft
	// binary is a separate piece of state from the persisted file).
	var kernelMu sync.Mutex
	var kernelBody string

	reloadEnv := &nftReloadEnv{
		nftPath:           "nft",
		rulesPath:         rulesPath,
		configPath:        configPath,
		reconcileLockPath: lockPath,
		table:             defaultNFTTable,
		chain:             defaultNFTChain,
		now:               func() time.Time { return time.Unix(1_800_000_000, 0) },
		readFile:          fs.readFile,
		writeFile:         fs.writeFile,
		removeFile:        fs.removeFile,
		lockFn:            withContainmentReconcileLock,
		pauseAfterSnapshot: func() {
			close(reloadPaused)
			<-resumeReload
		},
		runCmd: func(_ context.Context, _ string, args ...string) (string, int, error) {
			joined := strings.Join(args, " ")
			switch {
			case strings.HasPrefix(joined, "-n -a list chain"):
				kernelMu.Lock()
				defer kernelMu.Unlock()
				return kernelBody, 0, nil
			case strings.HasPrefix(joined, "-c -f "):
				return "", 0, nil
			case strings.HasPrefix(joined, "-f "):
				data, err := fs.readFile(rulesPath + ".reload")
				if err != nil {
					return "", 1, err
				}
				kernelMu.Lock()
				kernelBody = string(data)
				kernelMu.Unlock()
				return "", 0, nil
			default:
				return "", 1, fmt.Errorf("unexpected nft invocation: %s", joined)
			}
		},
	}

	go func() {
		defer close(installDone)
		<-reloadPaused // wait until reload holds the lock and is paused mid-flight
		_ = withContainmentReconcileLock(lockPath, func() error {
			// Reaching here means the shared lock was acquired. If reload
			// is still holding it, this select would time out below.
			select {
			case installEnteredLock <- struct{}{}:
			default:
			}
			// This IS config B being promoted: write it, then read it back
			// as `contain install`'s nft step would, and apply+persist it.
			if err := fs.writeFile(configPath, []byte(configB), modeConfigSecret); err != nil {
				return err
			}
			data, err := fs.readFile(configPath)
			if err != nil {
				return err
			}
			declared, err := parseContainmentLoopbackServicesFromConfigBytes(data, loopbackTestProxyPort, time.Now())
			if err != nil {
				return err
			}
			body := renderNFTRulesWithServices(nftRuleOptions{
				OperatorUID:      loopbackTestOperatorUID,
				ProxyUID:         loopbackTestProxyUID,
				AgentUID:         loopbackTestAgentUID,
				ProxyPort:        loopbackTestProxyPort,
				Table:            defaultNFTTable,
				Chain:            defaultNFTChain,
				LoopbackServices: declared,
			})
			kernelMu.Lock()
			kernelBody = body
			kernelMu.Unlock()
			return fs.writeFile(rulesPath, []byte(body), modeConfigSecret)
		})
	}()

	reloadErr := make(chan error, 1)
	go func() {
		reloadErr <- reloadNFTRules(context.Background(), reloadEnv)
	}()

	<-reloadPaused // confirm reload actually reached its critical section (still holding the lock)

	// The primary proof: install's goroutine has been runnable since
	// reloadPaused closed, and it tries the SAME real flock reload still
	// holds. It must NOT be able to enter its locked section yet.
	select {
	case <-installEnteredLock:
		t.Fatal("install entered its locked section while reload was still holding the shared reconcile lock -- the lock is not actually serializing the two critical sections")
	case <-time.After(150 * time.Millisecond):
		// expected: still blocked
	}

	close(resumeReload)
	if err := <-reloadErr; err != nil {
		t.Fatalf("reloadNFTRules: %v", err)
	}

	select {
	case <-installEnteredLock:
	case <-time.After(2 * time.Second):
		t.Fatal("install never entered its locked section after reload released the shared lock")
	}
	<-installDone

	persisted, err := fs.readFile(rulesPath)
	if err != nil {
		t.Fatalf("read persisted rules: %v", err)
	}
	if strings.Contains(string(persisted), "dport 9200 accept") {
		t.Fatalf("persisted rules file regressed to config A's revoked service after install/reload interleaving:\n%s", persisted)
	}
	kernelMu.Lock()
	finalKernel := kernelBody
	kernelMu.Unlock()
	if strings.Contains(finalKernel, "dport 9200 accept") {
		t.Fatalf("live kernel chain regressed to config A's revoked service after install/reload interleaving:\n%s", finalKernel)
	}
}

// TestReloadNFTRulesKernelFailureThenRestoreFailureJoinsBothErrors regression-tests
// nft_reload.go's restoreOnFailure: when the kernel transaction fails AND
// the attempt to restore the previous content ALSO fails (e.g. the
// filesystem went read-only between the two writes), the returned error
// surfaces BOTH causes -- an operator must not see only "restore failed"
// and lose the original kernel failure, or only the kernel failure while a
// corrupted-in-a-new-way file silently persists. It also proves recovery:
// the NEXT reload, once writes succeed again, converges the persisted file
// and the live kernel chain to the same (fully reconciled) content.
func TestReloadNFTRulesKernelFailureThenRestoreFailureJoinsBothErrors(t *testing.T) {
	t.Parallel()
	const rulesPath = "/managed/50-pipelock-containment.nft"
	const configPath = "/etc/pipelock/pipelock.yaml"
	oldRules := renderNFTRules(loopbackTestOperatorUID, loopbackTestProxyUID, loopbackTestAgentUID, loopbackTestProxyPort, defaultNFTTable, defaultNFTChain) + "# stale revision\n"
	fs := newStatefulFakeFS(map[string][]byte{
		rulesPath:  []byte(oldRules),
		configPath: []byte(nftReloadTestConfigWithService("2099-01-01T00:00:00Z")),
	})

	writeCount := 0
	env := &nftReloadEnv{
		nftPath:           "nft",
		rulesPath:         rulesPath,
		configPath:        configPath,
		reconcileLockPath: filepath.Join(t.TempDir(), "reconcile.lock"),
		table:             defaultNFTTable,
		chain:             defaultNFTChain,
		now:               func() time.Time { return time.Unix(1_800_000_000, 0) },
		readFile:          fs.readFile,
		removeFile:        fs.removeFile,
		lockFn:            withContainmentReconcileLock,
		writeFile: func(path string, data []byte, mode os.FileMode) error {
			writeCount++
			if writeCount == 2 {
				// The SECOND write in this reload attempt is the
				// restore-to-previous-content write (the first persisted
				// the new reconciled body). Fail exactly that one to
				// exercise restoreOnFailure's own write failure.
				return fmt.Errorf("simulated read-only filesystem")
			}
			return fs.writeFile(path, data, mode)
		},
		runCmd: func(context.Context, string, ...string) (string, int, error) {
			return "", 1, fmt.Errorf("simulated nft kernel failure")
		},
	}

	err := reloadNFTRules(context.Background(), env)
	if err == nil {
		t.Fatal("expected an error when both the kernel transaction and the restore write fail")
	}
	if !strings.Contains(err.Error(), "simulated nft kernel failure") {
		t.Fatalf("error = %v, want it to include the original kernel failure", err)
	}
	if !strings.Contains(err.Error(), "simulated read-only filesystem") {
		t.Fatalf("error = %v, want it to include the restore-write failure", err)
	}

	// Recovery: once writes succeed again, the next reload converges the
	// persisted file and the live kernel to the same reconciled content.
	env.writeFile = fs.writeFile
	var kernelBody string
	env.runCmd = func(_ context.Context, _ string, args ...string) (string, int, error) {
		joined := strings.Join(args, " ")
		switch {
		case strings.HasPrefix(joined, "-n -a list chain"):
			return kernelBody, 0, nil
		case strings.HasPrefix(joined, "-c -f "):
			return "", 0, nil
		case strings.HasPrefix(joined, "-f "):
			data, readErr := fs.readFile(rulesPath + ".reload")
			if readErr != nil {
				return "", 1, readErr
			}
			kernelBody = string(data)
			return "", 0, nil
		default:
			return "", 1, fmt.Errorf("unexpected nft invocation: %s", joined)
		}
	}
	if err := reloadNFTRules(context.Background(), env); err != nil {
		t.Fatalf("recovery reload: %v", err)
	}
	persisted, err := fs.readFile(rulesPath)
	if err != nil {
		t.Fatalf("read persisted rules: %v", err)
	}
	if string(persisted) != kernelBody {
		t.Fatalf("persisted file and live kernel did not converge after recovery:\npersisted:\n%s\nkernel:\n%s", persisted, kernelBody)
	}
	if strings.Contains(string(persisted), "dport 9200 accept") {
		t.Fatalf("recovered host rules must not carry the declared service:\n%s", persisted)
	}
}

// TestStepInstallNFTRulesFirstInstallAbsentRulesDirWithRealLock is the
// MEDIUM-severity reproduction: on a clean host (or an older install
// without /etc/nftables.d), stepInstallNFTRulesApplyLocked acquires the
// reconcile lock -- derived from the rules path, so it lives in the SAME
// not-yet-existing directory -- BEFORE the callback that creates that
// directory ever runs. With the REAL lock implementation (not a test
// double that tolerates a missing parent), the lock's O_CREAT open fails
// ENOENT and install never applies a single rule. The prescribed recovery
// ("rerun install") would repeat the exact same failure, because install is
// the thing that just failed. This test fails before the pre-lock
// directory-creation fix, and must pass after it.
func TestStepInstallNFTRulesFirstInstallAbsentRulesDirWithRealLock(t *testing.T) {
	env, runner, _ := newFakeEnv(t)
	// Confirm the premise: the rules directory genuinely does not exist yet.
	if _, err := os.Stat(filepath.Dir(env.nftRulesPath)); !os.IsNotExist(err) {
		t.Fatalf("premise failed: rules directory already exists or stat errored unexpectedly: %v", err)
	}
	env.reconcileLockPath = containmentReconcileLockPathFor(env.nftRulesPath)
	env.lockFn = withContainmentReconcileLock
	runner.on(argvFor(testNFT, "-n", "-a", "list", "chain", "inet", defaultNFTTable, defaultNFTChain), "", 1, fmt.Errorf("not loaded"))

	s := stepInstallNFTRules()
	applied, err := s.apply(context.Background(), env)
	if err != nil {
		t.Fatalf("first install on a clean host must succeed (rules directory must exist before the lock is acquired): %v", err)
	}
	if !applied {
		t.Fatal("expected apply=true on a fresh install")
	}
	if _, err := os.Stat(env.nftRulesPath); err != nil {
		t.Fatalf("rules file not written: %v", err)
	}
}

// TestStepInstallNFTRulesRefusesSymlinkedRulesDirAncestor proves the
// directory-safety half of the fix: if a component of the rules directory
// path is a symlink (an attacker or a broken prior install redirecting
// /etc/nftables.d elsewhere), install refuses to create/use it rather than
// silently following the symlink as root.
func TestStepInstallNFTRulesRefusesSymlinkedRulesDirAncestor(t *testing.T) {
	env, runner, _ := newFakeEnv(t)
	env.reconcileLockPath = containmentReconcileLockPathFor(env.nftRulesPath)
	env.lockFn = withContainmentReconcileLock
	runner.on(argvFor(testNFT, "-n", "-a", "list", "chain", "inet", defaultNFTTable, defaultNFTChain), "", 1, fmt.Errorf("not loaded"))

	rulesParent := filepath.Dir(env.nftRulesPath) // .../etc/nftables.d
	grandparent := filepath.Dir(rulesParent)      // .../etc
	elsewhere := filepath.Join(filepath.Dir(grandparent), "elsewhere-nftables.d")
	if err := os.MkdirAll(grandparent, 0o750); err != nil {
		t.Fatalf("mkdir grandparent: %v", err)
	}
	if err := os.MkdirAll(elsewhere, 0o750); err != nil {
		t.Fatalf("mkdir elsewhere: %v", err)
	}
	if err := os.Symlink(elsewhere, rulesParent); err != nil {
		t.Fatalf("symlink rules parent: %v", err)
	}

	s := stepInstallNFTRules()
	if _, err := s.apply(context.Background(), env); err == nil {
		t.Fatal("expected install to refuse a symlinked rules-directory ancestor")
	} else if !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("error = %v, want it to name the symlink refusal", err)
	}
	if _, err := os.Lstat(filepath.Join(elsewhere, filepath.Base(env.nftRulesPath))); !os.IsNotExist(err) {
		t.Fatalf("must not have written through the symlink into %s", elsewhere)
	}
}

// TestReloaderLockErrorNamesMissingDirectoryAndRecoveryCommand covers the
// reloader-side half of the MEDIUM fix: `contain reload-nft-rules` does NOT
// create the nft rules directory itself (only `contain install` does, via
// ensureNFTRulesDirSafe, before it ever acquires the lock), so on a host
// that never completed an install, the lock's ENOENT is a real, terminal
// condition -- the error text says the directory is missing and names
// `pipelock contain install` as the fix, rather than a generic open error.
func TestReloaderLockErrorNamesMissingDirectoryAndRecoveryCommand(t *testing.T) {
	t.Parallel()
	rulesDir := filepath.Join(t.TempDir(), "does-not-exist")
	lockPath := containmentReconcileLockPathFor(filepath.Join(rulesDir, "50-pipelock-containment.nft"))
	err := withContainmentReconcileLock(lockPath, func() error {
		t.Fatal("fn must not run when the lock directory does not exist")
		return nil
	})
	if err == nil {
		t.Fatal("expected an error when the lock's directory does not exist")
	}
	if !strings.Contains(err.Error(), "is missing") || !strings.Contains(err.Error(), "pipelock contain install") {
		t.Fatalf("error = %v, want it to say the directory is missing and name `pipelock contain install`", err)
	}
}

// TestStepInstallNFTRulesPreservesExistingRulesDirMode proves a reinstall
// never widens a rules directory an operator deliberately keeps stricter
// than the default: the pre-lock helper creates and sets the mode only on a
// directory it created itself. A genuinely absent directory is still created
// with the readable default the boot unit and proxy identity need.
func TestStepInstallNFTRulesPreservesExistingRulesDirMode(t *testing.T) {
	t.Run("no-op reinstall keeps an operator's stricter mode", func(t *testing.T) {
		env, runner, _ := newFakeEnv(t)
		dir := filepath.Dir(env.nftRulesPath)
		env.reconcileLockPath = containmentReconcileLockPathFor(env.nftRulesPath)
		env.lockFn = withContainmentReconcileLock
		runner.on(argvFor(testNFT, "-n", "-a", "list", "chain", "inet", defaultNFTTable, defaultNFTChain), "", 1, fmt.Errorf("not loaded"))

		s := stepInstallNFTRules()
		if _, err := s.apply(context.Background(), env); err != nil {
			t.Fatalf("first install must succeed: %v", err)
		}
		// The operator hardens the directory after install.
		if err := os.Chmod(dir, 0o750); err != nil { // #nosec G302 -- directory hardened by the operator in this fixture.
			t.Fatalf("harden rules directory: %v", err)
		}

		// A reinstall with the rules already matching must not touch it.
		if _, err := s.apply(context.Background(), env); err != nil {
			t.Fatalf("no-op reinstall must succeed: %v", err)
		}
		info, err := os.Stat(dir)
		if err != nil {
			t.Fatalf("stat rules directory: %v", err)
		}
		if got := info.Mode().Perm(); got != 0o750 {
			t.Fatalf("rules directory mode = %#o, want the operator's 0750 preserved by a no-op reinstall", got)
		}
	})

	t.Run("absent directory is created readable", func(t *testing.T) {
		env, runner, _ := newFakeEnv(t)
		dir := filepath.Dir(env.nftRulesPath)
		if _, err := os.Stat(dir); !os.IsNotExist(err) {
			t.Fatalf("premise failed: rules directory already exists: %v", err)
		}
		env.reconcileLockPath = containmentReconcileLockPathFor(env.nftRulesPath)
		env.lockFn = withContainmentReconcileLock
		runner.on(argvFor(testNFT, "-n", "-a", "list", "chain", "inet", defaultNFTTable, defaultNFTChain), "", 1, fmt.Errorf("not loaded"))

		s := stepInstallNFTRules()
		if _, err := s.apply(context.Background(), env); err != nil {
			t.Fatalf("first install must succeed: %v", err)
		}
		info, err := os.Stat(dir)
		if err != nil {
			t.Fatalf("stat rules directory: %v", err)
		}
		if got := info.Mode().Perm(); got != modeDirReadable {
			t.Fatalf("created rules directory mode = %#o, want %#o", got, modeDirReadable)
		}
	})
}

// TestEnsureNFTRulesDirSafeReportsEachFailure covers the three ways creating
// the rules directory can fail after the safety check passes. Each one must
// surface the operation that failed and the directory it failed on, because
// this runs before the lock is ever acquired: an operator who sees only a
// generic install failure here cannot tell a missing parent from a
// permission problem, and those need different repairs.
func TestEnsureNFTRulesDirSafeReportsEachFailure(t *testing.T) {
	statErr := errors.New("stat exploded")
	mkdirErr := errors.New("mkdir refused")
	chmodErr := errors.New("chmod refused")

	for _, tc := range []struct {
		name    string
		stat    func(string) (os.FileInfo, error)
		mkdir   func(string, os.FileMode) error
		chmod   func(string, os.FileMode) error
		wantErr string
	}{
		{
			name:    "stat fails for a reason other than absence",
			stat:    func(string) (os.FileInfo, error) { return nil, statErr },
			wantErr: "stat exploded",
		},
		{
			name:    "mkdir fails",
			stat:    func(string) (os.FileInfo, error) { return nil, os.ErrNotExist },
			mkdir:   func(string, os.FileMode) error { return mkdirErr },
			wantErr: "mkdir refused",
		},
		{
			name:    "chmod fails after the directory is created",
			stat:    func(string) (os.FileInfo, error) { return nil, os.ErrNotExist },
			mkdir:   func(string, os.FileMode) error { return nil },
			chmod:   func(string, os.FileMode) error { return chmodErr },
			wantErr: "chmod refused",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env, _, _ := newFakeEnv(t)
			env.nftRulesPath = filepath.Join(t.TempDir(), "nftables.d", "50-pipelock-containment.nft")
			env.stat = tc.stat
			if tc.mkdir != nil {
				env.mkdirAll = tc.mkdir
			}
			if tc.chmod != nil {
				env.chmod = tc.chmod
			}
			err := ensureNFTRulesDirSafe(env)
			if err == nil {
				t.Fatal("expected an error")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error = %v, want it to contain %q", err, tc.wantErr)
			}
			if !strings.Contains(err.Error(), filepath.Dir(env.nftRulesPath)) {
				t.Errorf("error = %v, want it to name the directory", err)
			}
		})
	}
}

// TestEnsureNFTRulesDirSafeAcceptsAnExistingDirectory is the positive
// control for the table above: the ordinary reinstall path, where the
// directory already exists, must succeed and must not touch its mode.
func TestEnsureNFTRulesDirSafeAcceptsAnExistingDirectory(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	dir := filepath.Join(t.TempDir(), "nftables.d")
	if err := os.Mkdir(dir, 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	env.nftRulesPath = filepath.Join(dir, "50-pipelock-containment.nft")
	env.chmod = func(string, os.FileMode) error {
		t.Fatal("chmod must not run for a directory that already exists")
		return nil
	}
	if err := ensureNFTRulesDirSafe(env); err != nil {
		t.Fatalf("ensureNFTRulesDirSafe: %v", err)
	}
}

// TestParseContainmentLoopbackServicesYAMLShapes parses REAL YAML for each way
// an operator can express "no declared services", because the previous test
// for this passed a nil Go slice straight to the validator and so could not
// see a decoder disagreement at all. An explicit null must mean the same thing
// as an omitted key: config.Load already decodes it into a nil slice, and when
// this parser refused it, `pipelock check` accepted a file that
// `contain install --config` then rejected before staging anything.
func TestParseContainmentLoopbackServicesYAMLShapes(t *testing.T) {
	future := time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339)

	for _, tc := range []struct {
		name      string
		yaml      string
		wantCount int
		wantErr   string
	}{
		{name: "containment absent entirely", yaml: "mode: balanced\n"},
		{name: "containment present without the key", yaml: "containment:\n  metrics_exposure: null\n"},
		{name: "explicit null", yaml: "containment:\n  loopback_services: null\n"},
		{name: "explicit empty tilde", yaml: "containment:\n  loopback_services: ~\n"},
		{name: "explicit empty list", yaml: "containment:\n  loopback_services: []\n"},
		{
			name: "one declared service",
			yaml: "containment:\n  loopback_services:\n    - host: 127.0.0.1\n      port: 9222\n" +
				"      owner: platform\n      reason: browser automation control port\n      expires_at: " + future + "\n",
			wantCount: 1,
		},
		{
			name:    "a scalar that is not null is still refused",
			yaml:    "containment:\n  loopback_services: 9222\n",
			wantErr: "must be a list",
		},
		{
			name:    "a mapping is still refused",
			yaml:    "containment:\n  loopback_services:\n    host: 127.0.0.1\n",
			wantErr: "must be a list",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			declared, err := parseContainmentLoopbackServicesFromConfigBytes(
				[]byte(tc.yaml), loopbackTestProxyPort, time.Now())
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("expected an error, got %d declared services", len(declared))
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("error = %v, want it to contain %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if len(declared) != tc.wantCount {
				t.Fatalf("declared = %d services, want %d", len(declared), tc.wantCount)
			}
		})
	}
}

// TestProbeNFTContainmentFailsOnUnusableConfigWithCanonicalChain covers the
// case the config-problem detail used to miss entirely. Once reload has
// already reconciled an unusable declaration down to zero services, the live
// chain is byte-identical to a host that declared nothing, so there is no
// unsafe verdict to hang the problem off. Verify used to return PASS there
// and claim a proxy-only loopback allow, which is a containment probe
// reporting success while unable to read the policy it exists to prove.
func TestProbeNFTContainmentFailsOnUnusableConfigWithCanonicalChain(t *testing.T) {
	t.Parallel()
	expiredConfigBody := "containment:\n  loopback_services:\n  - host: 127.0.0.1\n    port: 9200\n    owner: search-team\n    reason: local index\n    expires_at: \"2000-01-01T00:00:00Z\"\n"

	base := makeProbeEnv(t, func(e *probeEnv) {
		e.operatorUser = testOperatorUser
		e.lookupUser = containTestLookup
		e.nftRulesPath = "rules.nft"
		e.readFile = func(path string) ([]byte, error) {
			if path == e.configPath {
				return []byte(expiredConfigBody), nil
			}
			return []byte("# operator=1000 pipelock-proxy=988 pipelock-agent=987 proxy-port=8888\n"), nil
		}
		// The canonical zero-service chain: nothing undeclared in it at all.
		e.runCmd = func(context.Context, string, ...string) (string, int, error) {
			return goodNFTContainmentOutput, 0, nil
		}
	})

	status, detail := probeNFTContainment(context.Background(), base)
	if status != statusFail {
		t.Fatalf("status = %q (detail %q), want fail: the chain is canonical but the declaration cannot be honored", status, detail)
	}
	if !strings.Contains(detail, "cannot be honored") {
		t.Errorf("detail = %q, want it to say the declaration cannot be honored", detail)
	}
	if !strings.Contains(detail, "127.0.0.1:9200") || !strings.Contains(detail, "owner=search-team") {
		t.Errorf("detail = %q, want the offending entry and its owner named", detail)
	}
}

// TestProbeNFTContainmentPassesWithNoDeclarationAndCanonicalChain is the
// positive control for the test above: a host that genuinely declares
// nothing, with the same canonical chain, must still PASS. Without this,
// failing on an unreadable declaration could be satisfied by failing always.
func TestProbeNFTContainmentPassesWithNoDeclarationAndCanonicalChain(t *testing.T) {
	t.Parallel()
	base := makeProbeEnv(t, func(e *probeEnv) {
		e.operatorUser = testOperatorUser
		e.lookupUser = containTestLookup
		e.nftRulesPath = "rules.nft"
		e.readFile = func(path string) ([]byte, error) {
			if path == e.configPath {
				return []byte("mode: balanced\n"), nil
			}
			return []byte("# operator=1000 pipelock-proxy=988 pipelock-agent=987 proxy-port=8888\n"), nil
		}
		e.runCmd = func(context.Context, string, ...string) (string, int, error) {
			return goodNFTContainmentOutput, 0, nil
		}
	})

	status, detail := probeNFTContainment(context.Background(), base)
	if status != statusPass {
		t.Fatalf("status = %q (detail %q), want pass for a host that declares nothing", status, detail)
	}
}

// TestContainmentDropCounterRefusesUnusableLoopbackPolicy covers the sibling
// of the probe's refusal. The drop counter feeds direct-canary attribution,
// and it used to surface a loopback configuration problem only when the chain
// ALSO carried an unsafe verdict. With a canonical chain and an unusable
// declaration it therefore returned a clean count, reporting an attribution
// nobody could verify the policy behind. This is the same defect the probe
// had, in the path the first fix did not touch.
func TestContainmentDropCounterRefusesUnusableLoopbackPolicy(t *testing.T) {
	t.Parallel()
	body := legacyManagedBlockWithLoopbackServices(1, nil)
	chainText := "table inet " + defaultNFTTable + " {\n\tchain " + defaultNFTChain +
		" {\n\t\ttype filter hook output priority filter; policy accept;\n" + body + "\n\t}\n}"
	uids := containmentUIDs{
		operatorUID:   loopbackTestOperatorUID,
		proxyUID:      loopbackTestProxyUID,
		agentUID:      loopbackTestAgentUID,
		operatorKnown: true,
	}

	t.Run("unusable declaration refuses the count", func(t *testing.T) {
		_, err := containmentDropCounterFromChainText(
			chainText, defaultNFTChain, uids, loopbackTestProxyPort,
			"managed config declares something Pipelock cannot honor (expired at 2000-01-01T00:00:00Z)", true)
		if err == nil {
			t.Fatal("expected a refusal: the chain is canonical but the declared policy cannot be honored")
		}
		if !strings.Contains(err.Error(), "cannot be honored") {
			t.Errorf("error = %v, want it to say the declaration cannot be honored", err)
		}
		if !strings.Contains(err.Error(), "expired at") {
			t.Errorf("error = %v, want it to carry the underlying problem", err)
		}
	})

	// Positive control: the same canonical chain with a usable (empty)
	// declaration must still produce a count, so the refusal above cannot be
	// satisfied by refusing everything.
	t.Run("usable declaration still counts", func(t *testing.T) {
		if _, err := containmentDropCounterFromChainText(
			chainText, defaultNFTChain, uids, loopbackTestProxyPort, "", false); err != nil {
			t.Fatalf("canonical chain with a usable declaration: %v", err)
		}
	})
}

// TestStepInstallNFTRulesKeepsHardenedDirModeWhenRulesChange covers the gap
// the no-op-reinstall test above left open. The mode-preservation fix lives in
// the pre-lock helper, which sets a mode only on a directory it created, but
// the rules-write branch separately re-created and re-chmod'd the same
// directory whenever the rules body actually moved. A no-op reinstall
// therefore preserved an operator's hardened mode while any real rules change
// silently widened it, which is the case an operator actually hits.
func TestStepInstallNFTRulesKeepsHardenedDirModeWhenRulesChange(t *testing.T) {
	env, runner, _ := newFakeEnv(t)
	dir := filepath.Dir(env.nftRulesPath)
	env.reconcileLockPath = containmentReconcileLockPathFor(env.nftRulesPath)
	env.lockFn = withContainmentReconcileLock
	runner.on(argvFor(testNFT, "-n", "-a", "list", "chain", "inet", defaultNFTTable, defaultNFTChain), "", 1, fmt.Errorf("not loaded"))

	s := stepInstallNFTRules()
	if _, err := s.apply(context.Background(), env); err != nil {
		t.Fatalf("first install must succeed: %v", err)
	}
	before, err := os.ReadFile(filepath.Clean(env.nftRulesPath))
	if err != nil {
		t.Fatalf("read rules: %v", err)
	}

	if err := os.Chmod(dir, 0o750); err != nil { // #nosec G302 -- directory hardened by the operator in this fixture.
		t.Fatalf("harden rules directory: %v", err)
	}

	// Move the rules body for real: a different proxy port renders a
	// different managed block, so this install takes the write branch.
	env.proxyPort = env.proxyPort + 1
	if _, err := s.apply(context.Background(), env); err != nil {
		t.Fatalf("install with changed rules must succeed: %v", err)
	}

	after, err := os.ReadFile(filepath.Clean(env.nftRulesPath))
	if err != nil {
		t.Fatalf("read rules: %v", err)
	}
	if string(before) == string(after) {
		t.Fatal("this test is vacuous unless the rules body actually changed")
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat rules directory: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o750 {
		t.Fatalf("rules directory mode = %#o after a rules change, want the operator's 0750 preserved", got)
	}
}

// TestStepInstallNFTRulesUndoReportsAFailedTableDrop covers the rollback path
// taken when install fails on a host that had no prior containment table.
// Undo drops the table this step created, and that command's error used to be
// discarded, so a rollback could report success while the table it was meant
// to remove was still loaded in the kernel. Every other branch of that
// function returns its error; this one was the outlier.
func TestStepInstallNFTRulesUndoReportsAFailedTableDrop(t *testing.T) {
	t.Run("a failed drop is reported", func(t *testing.T) {
		env, runner, _ := newFakeEnv(t)
		env.prevNFTTableStateKnown = false
		runner.on(argvFor(testNFT, "delete", "table", "inet", defaultNFTTable), "", 1, fmt.Errorf("device or resource busy"))

		err := stepInstallNFTRulesUndo(context.Background(), env)
		if err == nil {
			t.Fatal("expected the failed table drop to be reported")
		}
		if !strings.Contains(err.Error(), "delete table") {
			t.Errorf("error = %v, want it to name the failed drop", err)
		}
	})

	// nft can report a failed command solely through its non-zero exit status.
	// Keep that path distinct from the OS-error case above: removing the exit
	// check must fail this test rather than being masked by an error return.
	t.Run("a non-zero exit is reported", func(t *testing.T) {
		env, runner, _ := newFakeEnv(t)
		env.prevNFTTableStateKnown = false
		runner.on(argvFor(testNFT, "delete", "table", "inet", defaultNFTTable), "", 1, nil)

		err := stepInstallNFTRulesUndo(context.Background(), env)
		if err == nil || !strings.Contains(err.Error(), "exited 1") {
			t.Fatalf("error = %v, want non-zero exit to be reported", err)
		}
	})

	// Positive control: the ordinary rollback, where the drop succeeds, must
	// still complete, so reporting a failure cannot be satisfied by failing
	// every rollback.
	t.Run("a successful drop still completes", func(t *testing.T) {
		env, runner, _ := newFakeEnv(t)
		env.prevNFTTableStateKnown = false
		runner.on(argvFor(testNFT, "delete", "table", "inet", defaultNFTTable), "", 0, nil)

		if err := stepInstallNFTRulesUndo(context.Background(), env); err != nil {
			t.Fatalf("an ordinary rollback must complete: %v", err)
		}
	})
}

// TestReloadRemovesPartiallyPairedManagedBlock pins the recovery path for a
// managed block whose pairs are incomplete: one declared service has its
// forward allow but no reply. Neither the paired matcher nor the legacy
// contiguous-forward matcher recognizes that shape on its own, and a block
// nothing recognizes is a block nothing deletes. The forward allow for a
// service the operator has since revoked would then stay in the chain while
// reload appends the replacement block, so the revoked service stays
// reachable. Partial states like this are reachable after an interrupted
// transaction, so the reconciler has to recover from one rather than assume
// it only ever sees blocks it wrote.
func TestReloadRemovesPartiallyPairedManagedBlock(t *testing.T) {
	t.Parallel()

	const revokedPort = 9300
	handle := 20
	lines := []string{
		`meta skuid 1000 accept # handle ` + itoa(handle),
		`meta skuid 967 accept # handle ` + itoa(handle+1),
		`meta skuid 966 ip daddr 127.0.0.1 tcp dport 8888 accept # handle ` + itoa(handle+2),
		loopbackServiceRuleLine(9200, handle+3),
		loopbackServiceReplyRuleLine(9200, handle+4),
		// The revoked service keeps its forward allow but lost its reply.
		loopbackServiceRuleLine(revokedPort, handle+5),
		`meta skuid 966 udp dport 53 counter packets 0 bytes 0 log prefix "pipelock-contain class=direct_dns_blocked " drop # handle ` + itoa(handle+6),
		`meta skuid 966 tcp dport 53 counter packets 0 bytes 0 log prefix "pipelock-contain class=direct_dns_blocked " drop # handle ` + itoa(handle+7),
		`meta skuid 966 counter packets 0 bytes 0 log prefix "pipelock-contain class=not_routing_through_pipelock " drop # handle ` + itoa(handle+8),
	}
	live := numericNftStateListing(strings.Join(lines, "\n"))

	handles := legacyManagedNFTRuleBlockHandles(live, loopbackTestOperatorUID, loopbackTestProxyUID, loopbackTestAgentUID)
	if len(handles) == 0 {
		t.Fatalf("a partially paired managed block was not recognized, so reload would delete nothing and leave the revoked service on port %d reachable\nlive:\n%s", revokedPort, live)
	}
	for _, want := range []int{handle + 5} {
		found := false
		for _, got := range handles {
			if got == want {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("handle %d (the revoked service's orphaned forward allow) was not scheduled for deletion: %v", want, handles)
		}
	}
}

// TestPartialBlockRecoveryLeavesUndeclaredReplyAlone is the safety half of
// TestReloadRemovesPartiallyPairedManagedBlock. Recovering a partial block
// must not become a licence to absorb any agent loopback reply that happens to
// sit inside the block's span: an operator's hand-written reply rule for a
// service the block never declared is theirs, and deleting it would break a
// service they deliberately allowed while reporting a successful reconcile.
func TestPartialBlockRecoveryLeavesUndeclaredReplyAlone(t *testing.T) {
	t.Parallel()

	const undeclaredPort = 8789
	handle := 20
	lines := []string{
		`meta skuid 1000 accept # handle ` + itoa(handle),
		`meta skuid 967 accept # handle ` + itoa(handle+1),
		`meta skuid 966 ip daddr 127.0.0.1 tcp dport 8888 accept # handle ` + itoa(handle+2),
		loopbackServiceRuleLine(9200, handle+3),
		// A reply for a port this block never declared a forward for.
		loopbackServiceReplyRuleLine(undeclaredPort, handle+4),
		`meta skuid 966 udp dport 53 counter packets 0 bytes 0 log prefix "pipelock-contain class=direct_dns_blocked " drop # handle ` + itoa(handle+5),
		`meta skuid 966 tcp dport 53 counter packets 0 bytes 0 log prefix "pipelock-contain class=direct_dns_blocked " drop # handle ` + itoa(handle+6),
		`meta skuid 966 counter packets 0 bytes 0 log prefix "pipelock-contain class=not_routing_through_pipelock " drop # handle ` + itoa(handle+7),
	}
	live := numericNftStateListing(strings.Join(lines, "\n"))

	for _, got := range legacyManagedNFTRuleBlockHandles(live, loopbackTestOperatorUID, loopbackTestProxyUID, loopbackTestAgentUID) {
		if got == handle+4 {
			t.Fatalf("handle %d is an operator reply rule for undeclared port %d and must not be scheduled for deletion", handle+4, undeclaredPort)
		}
	}
}

// TestReloadRemovesManagedForwardAroundUndeclaredReply covers the case where a
// partially paired block ALSO contains an operator reply rule the block never
// declared. Recovery must delete the managed rules and leave that reply alone.
// Treating the block as one contiguous span cannot do both: extending the span
// deletes the operator's rule, and stopping at it abandons the managed rules,
// which leaves a revoked service's forward allow reachable. Selecting managed
// handles individually is what satisfies both.
func TestReloadRemovesManagedForwardAroundUndeclaredReply(t *testing.T) {
	t.Parallel()

	const revokedPort, undeclaredPort = 9300, 8789
	h := 20
	lines := []string{
		`meta skuid 1000 accept # handle ` + itoa(h),
		`meta skuid 967 accept # handle ` + itoa(h+1),
		`meta skuid 966 ip daddr 127.0.0.1 tcp dport 8888 accept # handle ` + itoa(h+2),
		loopbackServiceRuleLine(revokedPort, h+3),
		// Operator's own reply rule for a port this block never declared.
		loopbackServiceReplyRuleLine(undeclaredPort, h+4),
		`meta skuid 966 udp dport 53 counter packets 0 bytes 0 log prefix "pipelock-contain class=direct_dns_blocked " drop # handle ` + itoa(h+5),
		`meta skuid 966 tcp dport 53 counter packets 0 bytes 0 log prefix "pipelock-contain class=direct_dns_blocked " drop # handle ` + itoa(h+6),
		`meta skuid 966 counter packets 0 bytes 0 log prefix "pipelock-contain class=not_routing_through_pipelock " drop # handle ` + itoa(h+7),
	}
	live := numericNftStateListing(strings.Join(lines, "\n"))

	got := legacyManagedNFTRuleBlockHandles(live, loopbackTestOperatorUID, loopbackTestProxyUID, loopbackTestAgentUID)
	selected := map[int]bool{}
	for _, handle := range got {
		selected[handle] = true
	}

	if !selected[h+3] {
		t.Fatalf("the revoked service's forward allow (handle %d) was not selected for deletion, so it survives reload and stays reachable: %v", h+3, got)
	}
	if selected[h+4] {
		t.Fatalf("the operator's undeclared reply rule (handle %d) must never be deleted: %v", h+4, got)
	}
	for _, want := range []int{h, h + 1, h + 2, h + 5, h + 6, h + 7} {
		if !selected[want] {
			t.Fatalf("managed handle %d was not selected for deletion: %v", want, got)
		}
	}
}

// TestReloadReportsInstallingManagedRulesIntoAForeignOnlyChain pins the honesty
// of the reload report for the case that changes the most while looking like it
// changed nothing: a chain that carries only operator rules and no managed block.
// Nothing is deleted and the persisted file already matches, so every signal the
// reporter used to read says "no change" while the kernel gains the entire
// managed block. An operator told their reconciliation did nothing has no reason
// to check what it actually did.
func TestReloadReportsInstallingManagedRulesIntoAForeignOnlyChain(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name         string
		fileChanged  bool
		removed      int
		missingChain bool
		applied      bool
		want         string
	}{
		{
			name:    "applied into a chain that had no managed block",
			applied: true,
			want:    "containment nft rules reconciled: loaded managed rules into a chain that carried none",
		},
		{
			name:    "genuine no-op reports no change",
			applied: false,
			want:    "containment nft rules already reconciled, no change",
		},
		{
			name:    "removals are still named",
			applied: true, removed: 3,
			want: "containment nft rules reconciled: removed 3 managed rule(s)",
		},
		{
			name:         "a missing chain keeps its own wording",
			applied:      true,
			missingChain: true,
			want:         "containment nft rules reconciled: loaded managed rules into a missing chain",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := nftReloadOutcome(tc.fileChanged, tc.removed, tc.missingChain, tc.applied)
			if got != tc.want {
				t.Fatalf("nftReloadOutcome(%t,%d,%t,%t) = %q, want %q",
					tc.fileChanged, tc.removed, tc.missingChain, tc.applied, got, tc.want)
			}
		})
	}
}
