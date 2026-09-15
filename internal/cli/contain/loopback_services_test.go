// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"context"
	"fmt"
	"os"
	"strings"
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

// TestRenderNFTRulesWithLoopbackServicesGolden pins the exact rule text for
// 0, 1, and 2 declared loopback services: the additional accepts sit inside
// the managed block, immediately after the implicit proxy-port allow and
// before the DNS drops, in declaration order.
func TestRenderNFTRulesWithLoopbackServicesGolden(t *testing.T) {
	t.Parallel()

	none := RenderNFTRulesWithLoopbackServices(loopbackTestOperatorUID, loopbackTestProxyUID, loopbackTestAgentUID, loopbackTestProxyPort, nil)
	if none != RenderNFTRules(loopbackTestOperatorUID, loopbackTestProxyUID, loopbackTestAgentUID, loopbackTestProxyPort) {
		t.Fatal("zero declared services must render identically to RenderNFTRules")
	}

	one := RenderNFTRulesWithLoopbackServices(loopbackTestOperatorUID, loopbackTestProxyUID, loopbackTestAgentUID, loopbackTestProxyPort, []config.ContainmentLoopbackService{
		loopbackTestService(9200),
	})
	wantOneLine := "\t        meta skuid 966 ip daddr 127.0.0.1 tcp dport 9200 accept\n"
	if !strings.Contains(one, wantOneLine) {
		t.Fatalf("one declared service: missing line %q in:\n%s", wantOneLine, one)
	}
	if idx := strings.Index(one, wantOneLine); idx == -1 || !strings.Contains(one[:idx], "dport 8888 accept") {
		t.Fatalf("declared loopback accept must render after the implicit proxy-port allow:\n%s", one)
	}
	if idx := strings.Index(one, wantOneLine); idx == -1 || !strings.Contains(one[idx:], "udp dport 53") {
		t.Fatalf("declared loopback accept must render before the DNS drops:\n%s", one)
	}

	two := RenderNFTRulesWithLoopbackServices(loopbackTestOperatorUID, loopbackTestProxyUID, loopbackTestAgentUID, loopbackTestProxyPort, []config.ContainmentLoopbackService{
		loopbackTestService(9200),
		loopbackTestService(9201),
	})
	wantTwoLines := "\t        meta skuid 966 ip daddr 127.0.0.1 tcp dport 9200 accept\n" +
		"\t        meta skuid 966 ip daddr 127.0.0.1 tcp dport 9201 accept\n"
	if !strings.Contains(two, wantTwoLines) {
		t.Fatalf("two declared services: missing contiguous lines in:\n%s", two)
	}
}

// TestRenderNFTRulesWithLoopbackServicesIPv6 confirms the ::1 render path
// uses "ip6 daddr" instead of "ip daddr".
func TestRenderNFTRulesWithLoopbackServicesIPv6(t *testing.T) {
	t.Parallel()
	svc := loopbackTestService(9200)
	svc.Host = "::1"
	body := RenderNFTRulesWithLoopbackServices(loopbackTestOperatorUID, loopbackTestProxyUID, loopbackTestAgentUID, loopbackTestProxyPort, []config.ContainmentLoopbackService{svc})
	want := "\t        meta skuid 966 ip6 daddr ::1 tcp dport 9200 accept\n"
	if !strings.Contains(body, want) {
		t.Fatalf("missing ipv6 declared accept line in:\n%s", body)
	}
}

func loopbackServiceRuleLine(agentUID, port int, handle int) string {
	return `meta skuid ` + itoa(agentUID) + ` ip daddr 127.0.0.1 tcp dport ` + itoa(port) + ` accept # handle ` + itoa(handle)
}

// legacyManagedBlockWithLoopbackServices renders a managed block carrying N
// declared loopback service accepts between the implicit proxy allow and the
// DNS drops, with sequential handles starting at first.
func legacyManagedBlockWithLoopbackServices(first int, ports []int) (string, int) {
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
		lines = append(lines, loopbackServiceRuleLine(966, port, handle))
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

// TestReloadRecognizesBlockWithDeclaredLoopbackServices proves reload
// recognizes and REPLACES (not appends alongside) a managed block that
// carries declared loopback service accepts, in both the legacy six-rule
// shape and the expanded shape.
func TestReloadRecognizesBlockWithDeclaredLoopbackServices(t *testing.T) {
	t.Parallel()

	t.Run("legacy six-rule block still recognized", func(t *testing.T) {
		block, _ := legacyManagedBlockWithLoopbackServices(20, nil)
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
		block, _ := legacyManagedBlockWithLoopbackServices(20, []int{9200, 9201})
		live := strings.Join([]string{
			`table inet pipelock_containment {`,
			`  chain output_filter { type filter hook output priority filter; policy accept;`,
			block,
			`  }`,
			`}`,
		}, "\n")
		handles := legacyManagedNFTRuleBlockHandles(live, loopbackTestOperatorUID, loopbackTestProxyUID, loopbackTestAgentUID)
		if len(handles) != 8 {
			t.Fatalf("expanded block: got %d handles, want 8 (6 base + 2 declared): %v", len(handles), handles)
		}
		for _, want := range []int{20, 21, 22, 23, 24, 25, 26, 27} {
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

	t.Run("foreign standalone rule between two expanded blocks is preserved", func(t *testing.T) {
		block1, next := legacyManagedBlockWithLoopbackServices(20, []int{9200})
		foreign := `meta skuid 966 oifname "lo" ip daddr 127.0.0.1 tcp sport 9119 ct state established ct direction reply accept # handle ` + itoa(next)
		block2, _ := legacyManagedBlockWithLoopbackServices(next+1, []int{9200, 9201})
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
		if len(handles) != 7+8 {
			t.Fatalf("got %d handles across two blocks, want %d: %v", len(handles), 7+8, handles)
		}
	})

	t.Run("reload replaces rather than appends when declared services are present", func(t *testing.T) {
		block, _ := legacyManagedBlockWithLoopbackServices(20, []int{9200})
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
		script := renderNFTManagedChainReloadScript(live, newRules, defaultNFTTable, defaultNFTChain, loopbackTestOperatorUID, loopbackTestProxyUID, loopbackTestAgentUID)
		for _, handle := range []int{20, 21, 22, 23, 24, 25} {
			want := "delete rule inet pipelock_containment output_filter handle " + itoa(handle)
			if !strings.Contains(script, want) {
				t.Fatalf("reload script missing delete for handle %d:\n%s", handle, script)
			}
		}
		if strings.Count(script, "dport 9200 accept") != 1 {
			t.Fatalf("reload should load exactly one fresh dport 9200 accept, not append alongside the old one:\n%s", script)
		}
	})
}

// TestVerifyDeclaredLoopbackServiceMatchers is the direct-function proof for
// the two verify-side matchers: an accept for a declared host:port is
// recognized before the drop, and lineHasAgentLoopbackAllowForHost does not
// falsely match an unrelated port or host.
func TestVerifyDeclaredLoopbackServiceMatchers(t *testing.T) {
	t.Parallel()
	lines := []string{
		"meta skuid 966 ip daddr 127.0.0.1 tcp dport 9200 accept",
		"meta skuid 966 counter drop",
	}
	if !chainLinesHaveDeclaredLoopbackAllowBeforeDrop(lines, loopbackTestAgentUID, "127.0.0.1", 9200) {
		t.Fatal("declared accept before the catch-all drop must be recognized")
	}
	if chainLinesHaveDeclaredLoopbackAllowBeforeDrop(lines, loopbackTestAgentUID, "127.0.0.1", 9201) {
		t.Fatal("a different declared port must not match")
	}
	if chainLinesHaveDeclaredLoopbackAllowBeforeDrop(lines, loopbackTestAgentUID, "::1", 9200) {
		t.Fatal("a different declared host must not match")
	}

	afterDrop := []string{
		"meta skuid 966 counter drop",
		"meta skuid 966 ip daddr 127.0.0.1 tcp dport 9200 accept",
	}
	if chainLinesHaveDeclaredLoopbackAllowBeforeDrop(afterDrop, loopbackTestAgentUID, "127.0.0.1", 9200) {
		t.Fatal("an accept appearing AFTER the catch-all drop is unreachable and must not count")
	}
}

// TestUnsafeVerdictToleratesOnlyDeclaredLoopbackServices proves the core
// verify security decision: an undeclared loopback accept for the agent UID
// is unsafe, an accept the declared set names is not, and the implicit
// proxy-port allow keeps passing regardless of the declared set.
func TestUnsafeVerdictToleratesOnlyDeclaredLoopbackServices(t *testing.T) {
	t.Parallel()
	uids := containmentUIDs{operatorUID: loopbackTestOperatorUID, operatorKnown: true, proxyUID: loopbackTestProxyUID, agentUID: loopbackTestAgentUID}

	t.Run("undeclared loopback accept is unsafe", func(t *testing.T) {
		lines := []string{
			"meta skuid 966 ip daddr 127.0.0.1 tcp dport 9200 accept",
			"meta skuid 966 counter drop",
		}
		if !chainLinesHaveUnsafeVerdictBeforeAgentDrop(lines, uids, loopbackTestProxyPort, nil) {
			t.Fatal("an undeclared loopback accept before the agent drop must be flagged unsafe")
		}
	})

	t.Run("declared loopback accept is not unsafe", func(t *testing.T) {
		lines := []string{
			"meta skuid 966 ip daddr 127.0.0.1 tcp dport 9200 accept",
			"meta skuid 966 counter drop",
		}
		declared := []config.ContainmentLoopbackService{loopbackTestService(9200)}
		if chainLinesHaveUnsafeVerdictBeforeAgentDrop(lines, uids, loopbackTestProxyPort, declared) {
			t.Fatal("a declared loopback accept must not be flagged unsafe")
		}
	})

	t.Run("implicit proxy port allow is never unsafe regardless of declared set", func(t *testing.T) {
		lines := []string{
			"meta skuid 966 ip daddr 127.0.0.1 tcp dport 8888 accept",
			"meta skuid 966 counter drop",
		}
		declared := []config.ContainmentLoopbackService{loopbackTestService(9200)}
		if chainLinesHaveUnsafeVerdictBeforeAgentDrop(lines, uids, loopbackTestProxyPort, declared) {
			t.Fatal("the implicit proxy-port allow must never be flagged unsafe")
		}
	})

	t.Run("a declared service for a different port does not tolerate an undeclared one", func(t *testing.T) {
		lines := []string{
			"meta skuid 966 ip daddr 127.0.0.1 tcp dport 9300 accept",
			"meta skuid 966 counter drop",
		}
		declared := []config.ContainmentLoopbackService{loopbackTestService(9200)}
		if !chainLinesHaveUnsafeVerdictBeforeAgentDrop(lines, uids, loopbackTestProxyPort, declared) {
			t.Fatal("an accept for an undeclared port must stay unsafe even with an unrelated declared service present")
		}
	})

	t.Run("declared ::1 loopback accept is not unsafe", func(t *testing.T) {
		lines := []string{
			"meta skuid 966 ip6 daddr ::1 tcp dport 9200 accept",
			"meta skuid 966 counter drop",
		}
		svc := loopbackTestService(9200)
		svc.Host = "::1"
		declared := []config.ContainmentLoopbackService{svc}
		if chainLinesHaveUnsafeVerdictBeforeAgentDrop(lines, uids, loopbackTestProxyPort, declared) {
			t.Fatal("a declared ::1 loopback accept must not be flagged unsafe")
		}
	})

	t.Run("undeclared ::1 loopback accept is unsafe", func(t *testing.T) {
		lines := []string{
			"meta skuid 966 ip6 daddr ::1 tcp dport 9200 accept",
			"meta skuid 966 counter drop",
		}
		if !chainLinesHaveUnsafeVerdictBeforeAgentDrop(lines, uids, loopbackTestProxyPort, nil) {
			t.Fatal("an undeclared ::1 loopback accept must be flagged unsafe")
		}
	})
}

// TestVerifyPersistenceRendersDeclaredIPv6Service confirms verifyNFTPersistence's
// canonical-rules comparison (via renderNFTRulesWithServices) includes a
// declared ::1 entry's ip6 accept line, so a persisted rules file that
// carries the ::1 exception still matches canonical instead of being
// reported as drifted.
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
	if !strings.Contains(body, "ip6 daddr ::1 tcp dport 9200 accept") {
		t.Fatalf("rendered persisted rules text missing declared ::1 accept:\n%s", body)
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

	t.Run("unreadable config", func(t *testing.T) {
		env := newEnv("", os.ErrNotExist)
		declared, problem := declaredContainmentLoopbackServicesForVerify(env, 8888)
		if declared != nil {
			t.Fatalf("got %v, want nil", declared)
		}
		if problem != "" {
			t.Fatalf("an absent managed config is not itself a reportable problem, got %q", problem)
		}
	})

	t.Run("malformed yaml", func(t *testing.T) {
		env := newEnv("containment: [", nil)
		declared, problem := declaredContainmentLoopbackServicesForVerify(env, 8888)
		if declared != nil {
			t.Fatalf("got %v, want nil", declared)
		}
		if problem == "" {
			t.Fatal("malformed YAML must surface a problem string naming the fallback")
		}
	})

	t.Run("non-mapping document", func(t *testing.T) {
		env := newEnv("- just\n- a\n- list\n", nil)
		declared, problem := declaredContainmentLoopbackServicesForVerify(env, 8888)
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
		declared, problem := declaredContainmentLoopbackServicesForVerify(env, 8888)
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
		declared, problem := declaredContainmentLoopbackServicesForVerify(env, 8888)
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
		declared, problem := declaredContainmentLoopbackServicesForVerify(env, 8888)
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
		declared, problem := declaredContainmentLoopbackServicesForVerify(env, 8888)
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
		if got := managedNFTBlockLength(rules, 0, 1000, 967, 966); got != 0 {
			t.Fatalf("got %d, want 0", got)
		}
	})

	t.Run("operator accept missing", func(t *testing.T) {
		rules := []nftRuleWithHandle{
			{line: "meta skuid 999 accept", handle: 1},
			{line: "meta skuid 967 accept", handle: 2},
			{line: "meta skuid 966 ip daddr 127.0.0.1 tcp dport 8888 accept", handle: 3},
		}
		if got := managedNFTBlockLength(rules, 0, 1000, 967, 966); got != 0 {
			t.Fatalf("got %d, want 0", got)
		}
	})

	t.Run("no loopback allow at all", func(t *testing.T) {
		rules := []nftRuleWithHandle{
			{line: "meta skuid 1000 accept", handle: 1},
			{line: "meta skuid 967 accept", handle: 2},
			{line: "meta skuid 966 counter drop", handle: 3},
		}
		if got := managedNFTBlockLength(rules, 0, 1000, 967, 966); got != 0 {
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
		if got := managedNFTBlockLength(rules, 0, 1000, 967, 966); got != 0 {
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
		`meta skuid 966 udp dport 53 counter packets 0 bytes 0 log prefix "pipelock-contain class=direct_dns_blocked " drop # handle 24`,
		`meta skuid 966 tcp dport 53 counter packets 0 bytes 0 log prefix "pipelock-contain class=direct_dns_blocked " drop # handle 25`,
		`meta skuid 966 counter packets 0 bytes 0 log prefix "pipelock-contain class=not_routing_through_pipelock " drop # handle 26`,
	}, "\n")
	live := strings.Join([]string{
		`table inet pipelock_containment {`,
		`  chain output_filter { type filter hook output priority filter; policy accept;`,
		block,
		`  }`,
		`}`,
	}, "\n")

	handles := legacyManagedNFTRuleBlockHandles(live, loopbackTestOperatorUID, loopbackTestProxyUID, loopbackTestAgentUID)
	if len(handles) != 7 {
		t.Fatalf("got %d handles, want 7 (6 base + 1 declared ::1 service): %v", len(handles), handles)
	}

	newRules := RenderNFTRulesWithLoopbackServices(loopbackTestOperatorUID, loopbackTestProxyUID, loopbackTestAgentUID, loopbackTestProxyPort, []config.ContainmentLoopbackService{ipv6Service})
	script := renderNFTManagedChainReloadScript(live, newRules, defaultNFTTable, defaultNFTChain, loopbackTestOperatorUID, loopbackTestProxyUID, loopbackTestAgentUID)
	for _, handle := range []int{20, 21, 22, 23, 24, 25, 26} {
		want := "delete rule inet pipelock_containment output_filter handle " + itoa(handle)
		if !strings.Contains(script, want) {
			t.Fatalf("reload script missing delete for handle %d (block not recognized, would append a second block):\n%s", handle, script)
		}
	}
	if strings.Count(script, "ip6 daddr ::1 tcp dport 9200 accept") != 1 {
		t.Fatalf("reload should load exactly one fresh ::1 accept, not append alongside the old one:\n%s", script)
	}
}

// TestDoctorSurfacesMissingDeclaredLoopbackService confirms `contain doctor`
// has a section that reports a declared loopback service: doctor.go has no
// dedicated "list declared exceptions" printout (checked: doctor.go has no
// occurrence of "metrics_exposure", "MetricsExposure", or "managed config" --
// grep run during this pass came back empty), but doctorChainStructureReader
// (doctor.go) passes probeNFTContainment's (verify.go) detail text straight
// through for any FAIL that is not a definite bypass, via the unknownInfra
// "managed chain structure could not establish containment: <detail>" path.
// A declared-but-missing loopback service therefore already surfaces to the
// operator through `contain doctor`, with no doctor.go change needed.
func TestDoctorSurfacesMissingDeclaredLoopbackService(t *testing.T) {
	t.Parallel()
	configBody := "containment:\n  loopback_services:\n  - host: 127.0.0.1\n    port: 9200\n    owner: search-team\n    reason: local index\n    expires_at: \"2099-01-01T00:00:00Z\"\n"
	base := makeProbeEnv(t, func(e *probeEnv) {
		e.operatorUser = testOperatorUser
		e.lookupUser = containTestLookup
		e.nftRulesPath = "rules.nft"
		e.readFile = func(path string) ([]byte, error) {
			if path == e.configPath {
				return []byte(configBody), nil
			}
			return []byte("# operator=1000 pipelock-proxy=988 pipelock-agent=987 proxy-port=8888\n"), nil
		}
		e.runCmd = func(context.Context, string, ...string) (string, int, error) {
			return goodNFTContainmentOutput, 0, nil
		}
	})
	doctor := &doctorEnv{port: defaultProxyPort, agentUserName: testAgentUser}
	reader := doctorChainStructureReader(base, doctor)
	res := reader(context.Background())
	if res.status == statusPass {
		t.Fatalf("expected doctor to report the missing declared service, got pass: %q", res.detail)
	}
	if !strings.Contains(res.detail, "declared loopback service 127.0.0.1:9200") || !strings.Contains(res.detail, "owner=search-team") {
		t.Fatalf("doctor detail = %q, want it to name the missing declared service and its owner", res.detail)
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
    meta skuid 1000 accept # handle 20
    meta skuid 967 accept # handle 21
    meta skuid 966 ip daddr 127.0.0.1 tcp dport 8888 accept # handle 22
    meta skuid 966 ip daddr 127.0.0.1 tcp dport 9200 accept # handle 23
    meta skuid 966 udp dport 53 counter packets 0 bytes 0 log prefix "pipelock-contain class=direct_dns_blocked " drop # handle 24
    meta skuid 966 tcp dport 53 counter packets 0 bytes 0 log prefix "pipelock-contain class=direct_dns_blocked " drop # handle 25
    meta skuid 966 counter packets 0 bytes 0 log prefix "pipelock-contain class=not_routing_through_pipelock " drop # handle 26
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

func nftReloadTestConfigWithService(port int, expiresAt string) string {
	return "containment:\n  loopback_services:\n  - host: 127.0.0.1\n    port: " + itoa(port) +
		"\n    owner: search-team\n    reason: local index\n    expires_at: \"" + expiresAt + "\"\n"
}

// TestReloadNFTRulesReconcilesAddedLoopbackService: a declared entry that
// was never installed (the live chain and persisted file only carry the
// base block) is added to the managed config, and the NEXT reload -- not a
// re-run of `contain install` -- loads it.
func TestReloadNFTRulesReconcilesAddedLoopbackService(t *testing.T) {
	t.Parallel()
	basePersisted := renderNFTRules(loopbackTestOperatorUID, loopbackTestProxyUID, loopbackTestAgentUID, loopbackTestProxyPort, defaultNFTTable, defaultNFTChain)
	fx := newNFTReloadTestFixture(t, nftReloadTestLiveWithNoService, nftReloadTestConfigWithService(9200, "2099-01-01T00:00:00Z"), basePersisted)
	if err := reloadNFTRules(context.Background(), fx.env); err != nil {
		t.Fatalf("reloadNFTRules: %v", err)
	}
	for _, handle := range []int{20, 21, 22, 23, 24, 25} {
		if !fx.deleteHandle(handle) {
			t.Fatalf("expected delete for old base-block handle %d in:\n%s", handle, fx.appliedBody())
		}
	}
	if !strings.Contains(fx.appliedBody(), "ip daddr 127.0.0.1 tcp dport 9200 accept") {
		t.Fatalf("newly-declared service was not loaded:\n%s", fx.appliedBody())
	}
	persisted, ok := fx.persisted()
	if !ok || !strings.Contains(persisted, "ip daddr 127.0.0.1 tcp dport 9200 accept") {
		t.Fatalf("persisted rules file was not updated to carry the newly-declared service: %q", persisted)
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
	if err := reloadNFTRules(context.Background(), fx.env); err != nil {
		t.Fatalf("reloadNFTRules: %v", err)
	}
	for _, handle := range []int{20, 21, 22, 23, 24, 25, 26} {
		if !fx.deleteHandle(handle) {
			t.Fatalf("expected delete for old handle %d (including the revoked service's accept) in:\n%s", handle, fx.appliedBody())
		}
	}
	if strings.Contains(fx.appliedBody(), "dport 9200 accept") {
		t.Fatalf("revoked service's accept must not be reloaded:\n%s", fx.appliedBody())
	}
	persisted, ok := fx.persisted()
	if !ok {
		t.Fatal("persisted rules file was not rewritten after revocation")
	}
	if strings.Contains(persisted, "dport 9200 accept") {
		t.Fatalf("persisted rules file still carries the revoked service: %q", persisted)
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
	fx := newNFTReloadTestFixture(t, nftReloadTestLiveWithOneService, nftReloadTestConfigWithService(9200, "2000-01-01T00:00:00Z"), withServicePersistedExpired)
	if err := reloadNFTRules(context.Background(), fx.env); err != nil {
		t.Fatalf("reloadNFTRules: %v", err)
	}
	if strings.Contains(fx.appliedBody(), "dport 9200 accept") {
		t.Fatalf("expired service's accept must not be reloaded:\n%s", fx.appliedBody())
	}
	persisted, ok := fx.persisted()
	if !ok || strings.Contains(persisted, "dport 9200 accept") {
		t.Fatalf("persisted rules file still carries the expired service: ok=%v %q", ok, persisted)
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
