// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
)

func TestRenderNFTManagedChainReloadScriptRemovesLegacyBlocksPreservesReplyRules(t *testing.T) {
	t.Parallel()
	const (
		operatorUID = 1000
		proxyUID    = 967
		agentUID    = 966
		proxyPort   = 8888
	)
	live := strings.Join([]string{
		`table inet pipelock_containment {`,
		`  chain output_filter { type filter hook output priority filter; policy accept;`,
		`    meta skuid 966 oifname "tailscale0" ip saddr 100.100.47.101 tcp sport 8642 ct state established ct direction reply accept # handle 10`,
		`    meta skuid 966 oifname "lo" ip daddr 127.0.0.1 tcp sport 8789 ct state established ct direction reply accept # handle 11`,
		`    meta skuid 966 oifname "lo" ip daddr 127.0.0.1 tcp sport 9119 ct state established ct direction reply accept # handle 12`,
		legacyManagedBlockWithHandles(20),
		legacyManagedBlockWithHandles(30),
		`  }`,
		`}`,
	}, "\n")
	body := renderNFTRules(operatorUID, proxyUID, agentUID, proxyPort, defaultNFTTable, defaultNFTChain)

	script := renderNFTManagedChainReloadScript(live, body, defaultNFTTable, defaultNFTChain, operatorUID, proxyUID, agentUID, proxyPort)
	for _, handle := range []int{20, 21, 22, 23, 24, 25, 30, 31, 32, 33, 34, 35} {
		want := "delete rule inet pipelock_containment output_filter handle "
		if !strings.Contains(script, want+itoa(handle)) {
			t.Fatalf("reload script did not remove managed handle %d:\n%s", handle, script)
		}
	}
	for _, handle := range []int{10, 11, 12} {
		if strings.Contains(script, "handle "+itoa(handle)) {
			t.Fatalf("reload script removed foreign established-reply handle %d:\n%s", handle, script)
		}
	}
	if strings.Contains(script, "delete chain") || strings.Contains(script, "delete table") {
		t.Fatalf("reload script must preserve the shared chain:\n%s", script)
	}
	if !strings.HasSuffix(script, body) {
		t.Fatalf("reload script does not finish by loading one canonical ruleset:\n%s", script)
	}
}

func TestLegacyManagedNFTRuleBlockHandlesDoesNotDeleteIncompleteLookalike(t *testing.T) {
	t.Parallel()
	live := strings.Join([]string{
		`meta skuid 1000 accept # handle 20`,
		`meta skuid 967 accept # handle 21`,
		`meta skuid 966 ip daddr 127.0.0.1 tcp dport 8888 accept # handle 22`,
		`meta skuid 966 udp dport 53 counter packets 0 bytes 0 log prefix "pipelock-contain class=direct_dns_blocked " drop # handle 23`,
		`meta skuid 966 tcp dport 53 counter packets 0 bytes 0 log prefix "pipelock-contain class=direct_dns_blocked " drop # handle 24`,
		`meta skuid 966 counter packets 0 bytes 0 log prefix "pipelock-contain class=not_routing_through_pipelock " accept # handle 25`,
	}, "\n")
	handles := legacyManagedNFTRuleBlockHandles(live, 1000, 967, 966, 8888)
	if len(handles) != 0 {
		t.Fatalf("incomplete lookalike handles = %v, want none", handles)
	}
}

func TestReloadNFTRulesReconcilesBeforeLoading(t *testing.T) {
	t.Parallel()
	const (
		operatorUID = 1000
		proxyUID    = 967
		agentUID    = 966
		proxyPort   = 8888
	)
	rules := renderNFTRules(operatorUID, proxyUID, agentUID, proxyPort, defaultNFTTable, defaultNFTChain)
	live := legacyManagedBlockWithHandles(20) + "\n" + legacyManagedBlockWithHandles(30)
	writes := make(map[string]string)
	var reloadScript string
	var calls []string
	env := &nftReloadEnv{
		nftPath:   "nft",
		rulesPath: "/managed/50-pipelock-containment.nft",
		table:     defaultNFTTable,
		chain:     defaultNFTChain,
		readFile: func(path string) ([]byte, error) {
			if path != "/managed/50-pipelock-containment.nft" {
				return nil, fmt.Errorf("unexpected read %q", path)
			}
			return []byte(rules), nil
		},
		writeFile: func(path string, data []byte, _ os.FileMode) error {
			writes[path] = string(data)
			reloadScript = string(data)
			return nil
		},
		removeFile: func(path string) error {
			delete(writes, path)
			return nil
		},
		runCmd: func(_ context.Context, name string, args ...string) (string, int, error) {
			calls = append(calls, name+" "+strings.Join(args, " "))
			switch strings.Join(args, " ") {
			case "-n -a list chain inet pipelock_containment output_filter":
				return live, 0, nil
			case "-c -f /managed/50-pipelock-containment.nft.reload", "-f /managed/50-pipelock-containment.nft.reload":
				return "", 0, nil
			default:
				return "", -1, fmt.Errorf("unexpected nft command %q", strings.Join(args, " "))
			}
		},
	}

	if err := reloadNFTRules(context.Background(), env); err != nil {
		t.Fatalf("reload nft rules: %v", err)
	}
	if got, want := calls, []string{
		"nft -n -a list chain inet pipelock_containment output_filter",
		"nft -c -f /managed/50-pipelock-containment.nft.reload",
		"nft -f /managed/50-pipelock-containment.nft.reload",
	}; strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("commands = %v, want %v", got, want)
	}
	if len(writes) != 0 {
		t.Fatalf("reload script was not removed: %v", writes)
	}
	if !strings.Contains(reloadScript, "delete rule inet pipelock_containment output_filter handle 20") ||
		!strings.Contains(reloadScript, "delete rule inet pipelock_containment output_filter handle 35") {
		t.Fatalf("reload script did not remove both legacy blocks:\n%s", reloadScript)
	}
}

func TestReloadNFTRulesRejectsMissingManagedHeader(t *testing.T) {
	t.Parallel()
	called := false
	err := reloadNFTRules(context.Background(), &nftReloadEnv{
		nftPath:   "nft",
		rulesPath: "/managed/50-pipelock-containment.nft",
		readFile:  func(string) ([]byte, error) { return []byte("table inet unrelated {}\n"), nil },
		runCmd: func(context.Context, string, ...string) (string, int, error) {
			called = true
			return "", 0, nil
		},
	})
	if err == nil || !strings.Contains(err.Error(), "missing the managed uid header") {
		t.Fatalf("error = %v, want missing managed header", err)
	}
	if called {
		t.Fatal("reloader invoked nft without an authenticated managed rules header")
	}
}

func TestReloadNFTRulesAllowsFirstBootMissingChain(t *testing.T) {
	t.Parallel()
	rules := renderNFTRules(1000, 967, 966, 8888, defaultNFTTable, defaultNFTChain)
	var reloadScript string
	env := &nftReloadEnv{
		nftPath:   "nft",
		rulesPath: "/managed/50-pipelock-containment.nft",
		table:     defaultNFTTable,
		chain:     defaultNFTChain,
		readFile:  func(string) ([]byte, error) { return []byte(rules), nil },
		writeFile: func(_ string, data []byte, _ os.FileMode) error {
			reloadScript = string(data)
			return nil
		},
		removeFile: func(string) error { return nil },
		runCmd: func(_ context.Context, _ string, args ...string) (string, int, error) {
			switch strings.Join(args, " ") {
			case "-n -a list chain inet pipelock_containment output_filter":
				return "Error: No such file or directory\n", 1, nil
			case "-c -f /managed/50-pipelock-containment.nft.reload", "-f /managed/50-pipelock-containment.nft.reload":
				return "", 0, nil
			default:
				return "", -1, fmt.Errorf("unexpected nft command %q", strings.Join(args, " "))
			}
		},
	}
	if err := reloadNFTRules(context.Background(), env); err != nil {
		t.Fatalf("reload nft rules: %v", err)
	}
	if strings.Contains(reloadScript, "delete rule") {
		t.Fatalf("first boot reload must not delete a rule:\n%s", reloadScript)
	}
}

func TestReloadNFTRulesFailsClosedOnUnexpectedListFailure(t *testing.T) {
	t.Parallel()
	rules := renderNFTRules(1000, 967, 966, 8888, defaultNFTTable, defaultNFTChain)
	wrote := false
	err := reloadNFTRules(context.Background(), &nftReloadEnv{
		nftPath:   "nft",
		rulesPath: "/managed/50-pipelock-containment.nft",
		table:     defaultNFTTable,
		chain:     defaultNFTChain,
		readFile:  func(string) ([]byte, error) { return []byte(rules), nil },
		writeFile: func(string, []byte, os.FileMode) error {
			wrote = true
			return nil
		},
		runCmd: func(context.Context, string, ...string) (string, int, error) {
			return "Operation not permitted", 1, nil
		},
	})
	if err == nil || !strings.Contains(err.Error(), "list nft managed chain exit=1") {
		t.Fatalf("error = %v, want a failed-closed list error", err)
	}
	if wrote {
		t.Fatal("reloader wrote an apply script after an untrusted nft listing failure")
	}
}

func TestReloadNFTRulesCmdRunsAsRootOnly(t *testing.T) {
	oldFactory := newNFTReloadEnv
	oldPrivilege := requireNFTReloadPrivilege
	t.Cleanup(func() {
		newNFTReloadEnv = oldFactory
		requireNFTReloadPrivilege = oldPrivilege
	})
	calledPrivilege := false
	requireNFTReloadPrivilege = func(action string) error {
		calledPrivilege = action == "reload-nft-rules"
		return nil
	}
	rules := renderNFTRules(1000, 967, 966, 8888, defaultNFTTable, defaultNFTChain)
	newNFTReloadEnv = func() *nftReloadEnv {
		return &nftReloadEnv{
			nftPath:    "nft",
			rulesPath:  "/managed/50-pipelock-containment.nft",
			table:      defaultNFTTable,
			chain:      defaultNFTChain,
			readFile:   func(string) ([]byte, error) { return []byte(rules), nil },
			writeFile:  func(string, []byte, os.FileMode) error { return nil },
			removeFile: func(string) error { return nil },
			runCmd: func(_ context.Context, _ string, args ...string) (string, int, error) {
				if strings.HasPrefix(strings.Join(args, " "), "-n -a list") {
					return "No such file or directory", 1, nil
				}
				return "", 0, nil
			},
		}
	}
	cmd := reloadNFTRulesCmd()
	cmd.SetArgs(nil)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute reload command: %v", err)
	}
	if !calledPrivilege {
		t.Fatal("reload command did not enforce root privilege")
	}
}

func TestReloadNFTRulesCmdRejectsUnprivilegedInvocation(t *testing.T) {
	oldFactory := newNFTReloadEnv
	oldPrivilege := requireNFTReloadPrivilege
	t.Cleanup(func() {
		newNFTReloadEnv = oldFactory
		requireNFTReloadPrivilege = oldPrivilege
	})
	newNFTReloadEnv = func() *nftReloadEnv {
		t.Fatal("unprivileged command constructed a reload environment")
		return nil
	}
	requireNFTReloadPrivilege = func(string) error { return errors.New("root required") }
	if err := reloadNFTRulesCmd().Execute(); err == nil || !strings.Contains(err.Error(), "root required") {
		t.Fatalf("error = %v, want privilege error", err)
	}
}

func TestDefaultNFTReloadEnvHasManagedDefaults(t *testing.T) {
	env := defaultNFTReloadEnv()
	if env.nftPath == "" || env.rulesPath != defaultNFTRulesPath || env.table != defaultNFTTable || env.chain != defaultNFTChain ||
		env.runCmd == nil || env.readFile == nil || env.writeFile == nil || env.removeFile == nil {
		t.Fatalf("default reload environment is incomplete: %#v", env)
	}
}

func TestReloadNFTRulesCleansTemporaryScriptWhenValidationFails(t *testing.T) {
	t.Parallel()
	rules := renderNFTRules(1000, 967, 966, 8888, defaultNFTTable, defaultNFTChain)
	removed := false
	err := reloadNFTRules(context.Background(), &nftReloadEnv{
		nftPath:   "nft",
		rulesPath: "/managed/50-pipelock-containment.nft",
		table:     defaultNFTTable,
		chain:     defaultNFTChain,
		readFile:  func(string) ([]byte, error) { return []byte(rules), nil },
		writeFile: func(string, []byte, os.FileMode) error { return nil },
		removeFile: func(string) error {
			removed = true
			return nil
		},
		runCmd: func(_ context.Context, _ string, args ...string) (string, int, error) {
			switch strings.Join(args, " ") {
			case "-n -a list chain inet pipelock_containment output_filter":
				return "No such file or directory", 1, nil
			case "-c -f /managed/50-pipelock-containment.nft.reload":
				return "syntax error", 1, nil
			default:
				return "", -1, fmt.Errorf("unexpected nft command %q", strings.Join(args, " "))
			}
		},
	})
	if err == nil || !strings.Contains(err.Error(), "validate nft managed chain reload exit=1") {
		t.Fatalf("error = %v, want validation error", err)
	}
	if !removed {
		t.Fatal("reloader left its temporary script after validation failed")
	}
}

func TestReloadNFTRulesReportsReadWriteAndApplyFailures(t *testing.T) {
	t.Parallel()
	t.Run("read", func(t *testing.T) {
		err := reloadNFTRules(context.Background(), &nftReloadEnv{
			rulesPath: "/managed/50-pipelock-containment.nft",
			readFile:  func(string) ([]byte, error) { return nil, os.ErrPermission },
		})
		if err == nil || !strings.Contains(err.Error(), "read nft rules") {
			t.Fatalf("error = %v, want read failure", err)
		}
	})
	t.Run("write", func(t *testing.T) {
		rules := renderNFTRules(1000, 967, 966, 8888, defaultNFTTable, defaultNFTChain)
		err := reloadNFTRules(context.Background(), &nftReloadEnv{
			nftPath:   "nft",
			rulesPath: "/managed/50-pipelock-containment.nft",
			table:     defaultNFTTable,
			chain:     defaultNFTChain,
			readFile:  func(string) ([]byte, error) { return []byte(rules), nil },
			writeFile: func(string, []byte, os.FileMode) error { return os.ErrPermission },
			runCmd: func(context.Context, string, ...string) (string, int, error) {
				return "No such file or directory", 1, nil
			},
		})
		if err == nil || !strings.Contains(err.Error(), "write nft managed chain reload file") {
			t.Fatalf("error = %v, want write failure", err)
		}
	})
	t.Run("apply", func(t *testing.T) {
		rules := renderNFTRules(1000, 967, 966, 8888, defaultNFTTable, defaultNFTChain)
		err := reloadNFTRules(context.Background(), &nftReloadEnv{
			nftPath:    "nft",
			rulesPath:  "/managed/50-pipelock-containment.nft",
			table:      defaultNFTTable,
			chain:      defaultNFTChain,
			readFile:   func(string) ([]byte, error) { return []byte(rules), nil },
			writeFile:  func(string, []byte, os.FileMode) error { return nil },
			removeFile: func(string) error { return nil },
			runCmd: func(_ context.Context, _ string, args ...string) (string, int, error) {
				switch strings.Join(args, " ") {
				case "-n -a list chain inet pipelock_containment output_filter":
					return "No such file or directory", 1, nil
				case "-c -f /managed/50-pipelock-containment.nft.reload":
					return "", 0, nil
				case "-f /managed/50-pipelock-containment.nft.reload":
					return "netlink failure", 1, nil
				default:
					return "", -1, fmt.Errorf("unexpected nft command %q", strings.Join(args, " "))
				}
			},
		})
		if err == nil || !strings.Contains(err.Error(), "reload nft managed chain exit=1") {
			t.Fatalf("error = %v, want apply failure", err)
		}
	})
}

func TestLegacyManagedRuleMatchersRejectNearMisses(t *testing.T) {
	t.Parallel()
	if lineHasManagedCatchAllDrop(`meta skuid 966`, 966) {
		t.Fatal("truncated rule matched catch-all managed rule")
	}
	if lineHasManagedDNSDrop(`meta skuid 966 tcp dport 53 counter packets 0 bytes 0 log prefix "pipelock-contain class=direct_dns_blocked " drop`, 966, "udp") {
		t.Fatal("TCP DNS rule matched UDP managed rule")
	}
	if lineHasManagedCatchAllDrop(`meta skuid 966 ip daddr 192.0.2.1 counter packets 0 bytes 0 log prefix "pipelock-contain class=not_routing_through_pipelock " drop`, 966) {
		t.Fatal("destination-specific rule matched catch-all managed rule")
	}
	if fieldsHaveNFTCounterLogDrop([]string{"counter", "log", "prefix", `"pipelock-contain class=direct_dns_blocked "`, "accept"}, nftLogPrefix(EgressClassDirectDNS)+" ") {
		t.Fatal("non-drop rule matched managed drop bookkeeping")
	}
}

func legacyManagedBlockWithHandles(first int) string {
	lines := []string{
		`meta skuid 1000 accept # handle ` + itoa(first),
		`meta skuid 967 accept # handle ` + itoa(first+1),
		`meta skuid 966 ip daddr 127.0.0.1 tcp dport 8888 accept # handle ` + itoa(first+2),
		`meta skuid 966 udp dport 53 counter packets 0 bytes 0 log prefix "pipelock-contain class=direct_dns_blocked " drop # handle ` + itoa(first+3),
		`meta skuid 966 tcp dport 53 counter packets 0 bytes 0 log prefix "pipelock-contain class=direct_dns_blocked " drop # handle ` + itoa(first+4),
		`meta skuid 966 counter packets 0 bytes 0 log prefix "pipelock-contain class=not_routing_through_pipelock " drop # handle ` + itoa(first+5),
	}
	return strings.Join(lines, "\n")
}

func itoa(value int) string {
	return strconv.Itoa(value)
}

// The reconciler talks to nft and the filesystem through injected seams, so its
// error paths are only exercised when each seam is made to fail on purpose.
// These cover the branches that report a cause rather than returning a verdict:
// a caller acting on a wrong cause is as stuck as one acting on none.
func TestReloadNFTRulesReportsCauseForEachFailingSeam(t *testing.T) {
	t.Parallel()
	rules := renderNFTRules(1000, 967, 966, 8888, defaultNFTTable, defaultNFTChain)
	baseEnv := func() *nftReloadEnv {
		return &nftReloadEnv{
			nftPath:    "nft",
			rulesPath:  "/managed/50-pipelock-containment.nft",
			table:      defaultNFTTable,
			chain:      defaultNFTChain,
			readFile:   func(string) ([]byte, error) { return []byte(rules), nil },
			writeFile:  func(string, []byte, os.FileMode) error { return nil },
			removeFile: func(string) error { return nil },
		}
	}

	t.Run("unparseable header", func(t *testing.T) {
		env := baseEnv()
		// A header naming a non-numeric uid cannot yield the identities the
		// reconciler matches on, so it must refuse rather than guess them.
		env.readFile = func(string) ([]byte, error) {
			return []byte("# operator=notanumber pipelock-proxy=967 pipelock-agent=966 proxy-port=8888\n"), nil
		}
		err := reloadNFTRules(context.Background(), env)
		if err == nil {
			t.Fatal("error = nil, want a refusal for an unparseable managed header")
		}
	})

	t.Run("list invocation error", func(t *testing.T) {
		env := baseEnv()
		env.runCmd = func(context.Context, string, ...string) (string, int, error) {
			return "", -1, errors.New("nft binary missing")
		}
		err := reloadNFTRules(context.Background(), env)
		if err == nil || !strings.Contains(err.Error(), "list nft managed chain") {
			t.Fatalf("error = %v, want the list invocation cause", err)
		}
	})

	t.Run("validation invocation error", func(t *testing.T) {
		env := baseEnv()
		env.runCmd = func(_ context.Context, _ string, args ...string) (string, int, error) {
			joined := strings.Join(args, " ")
			if strings.HasPrefix(joined, "-n -a list") {
				return "No such file or directory", 1, nil
			}
			return "", -1, errors.New("nft check crashed")
		}
		err := reloadNFTRules(context.Background(), env)
		if err == nil || !strings.Contains(err.Error(), "validate nft managed chain reload") {
			t.Fatalf("error = %v, want the validation invocation cause", err)
		}
	})

	t.Run("apply invocation error", func(t *testing.T) {
		env := baseEnv()
		env.runCmd = func(_ context.Context, _ string, args ...string) (string, int, error) {
			joined := strings.Join(args, " ")
			switch {
			case strings.HasPrefix(joined, "-n -a list"):
				return "No such file or directory", 1, nil
			case strings.HasPrefix(joined, "-c -f"):
				return "", 0, nil
			default:
				return "", -1, errors.New("nft apply crashed")
			}
		}
		err := reloadNFTRules(context.Background(), env)
		if err == nil || !strings.Contains(err.Error(), "reload nft managed chain") {
			t.Fatalf("error = %v, want the apply invocation cause", err)
		}
	})
}

// A listing line whose handle is not a number must be skipped rather than
// deleted. Guessing a handle here would delete an unrelated rule, which is the
// failure this reconciler exists to avoid.
func TestLegacyManagedNFTRuleBlockHandlesSkipsUnparseableHandle(t *testing.T) {
	t.Parallel()
	listing := `table inet pipelock_containment {
	chain output_filter {
		type filter hook output priority filter; policy accept;
		meta skuid 1000 accept # handle notanumber
		meta skuid 967 accept # handle notanumber
		meta skuid 966 ip daddr 127.0.0.1 tcp dport 8888 accept # handle notanumber
		meta skuid 966 udp dport 53 counter log prefix "pipelock-contain class=direct_dns_blocked " drop # handle notanumber
		meta skuid 966 tcp dport 53 counter log prefix "pipelock-contain class=direct_dns_blocked " drop # handle notanumber
		meta skuid 966 counter log prefix "pipelock-contain class=not_routing_through_pipelock " drop # handle notanumber
	}
}`
	if got := legacyManagedNFTRuleBlockHandles(listing, 1000, 967, 966, 8888); len(got) != 0 {
		t.Fatalf("handles = %v, want none when every handle is unparseable", got)
	}
}

// The DNS-block matcher reads fixed positions, so a line shorter than the
// prefix it compares must be rejected before indexing rather than panicking,
// and a line of the right length with the wrong values must still be rejected.
func TestLineHasManagedDNSDropRejectsShortAndMismatchedLines(t *testing.T) {
	t.Parallel()
	for name, line := range map[string]string{
		"too short":      "meta skuid 966 udp dport 53",
		"wrong protocol": "meta skuid 966 sctp dport 53 counter log prefix \"x \" drop",
		"wrong uid":      "meta skuid 999 udp dport 53 counter log prefix \"x \" drop",
		"wrong port":     "meta skuid 966 udp dport 8888 counter log prefix \"x \" drop",
	} {
		if lineHasManagedDNSDrop(line, 966, "udp") {
			t.Fatalf("%s: line %q matched the managed DNS drop rule", name, line)
		}
	}
}
