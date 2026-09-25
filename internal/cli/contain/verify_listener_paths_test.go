// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
)

func TestProbeNFTListenerConfigFailures(t *testing.T) {
	base := renderNFTRules(1000, 988, 987, 8888, testTable, testChain)
	guarded := renderNFTRulesWithServices(nftRuleOptions{OperatorUID: 1000, ProxyUID: 988, AgentUID: 987, ProxyPort: 8888, Table: testTable, Chain: testChain, AgentListener: "127.0.0.1:8889"})
	for _, tc := range []struct {
		name, rules, config, want string
		readErr                   error
	}{
		{"read denied", base, "", "read managed listener config", os.ErrPermission},
		{"malformed", base, "containment: [", "parse managed listener config", nil},
		{"missing guard", base, "containment:\n  agent_listener: 127.0.0.1:8889\n", "owner guard is missing", nil},
		{"stale guard", guarded, "mode: balanced\n", "no listener is configured", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := makeProbeEnv(t, func(e *probeEnv) {
				e.operatorUser = testOperatorUser
				e.lookupUser = containTestLookup
				e.readFile = func(path string) ([]byte, error) {
					if path == e.configPath {
						if tc.readErr != nil {
							return nil, tc.readErr
						}
						return []byte(tc.config), nil
					}
					return nil, os.ErrNotExist
				}
				e.runCmd = func(context.Context, string, ...string) (string, int, error) { return tc.rules, 0, nil }
			})
			status, detail := probeNFTContainment(context.Background(), env)
			if status != statusFail || !strings.Contains(detail, tc.want) {
				t.Fatalf("probe = %s, %q; want fail with %q", status, detail, tc.want)
			}
		})
	}
}

func TestVerifyNFTPersistenceListenerConfigFailures(t *testing.T) {
	for _, tc := range []struct {
		name, config, want string
		readErr            error
	}{
		{"read denied", "", "read managed listener config", os.ErrPermission},
		{"malformed", "containment: [", "parse managed listener config", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			current := containmentUIDs{operatorUID: 1000, operatorKnown: true, proxyUID: 988, agentUID: 987}
			env := makeProbeEnv(t, func(e *probeEnv) {
				e.operatorUser = ""
				e.nftRulesPath = "/managed/rules.nft"
				e.nftPersistUnitPath = "/managed/pipelock-nft.service"
				e.readFile = func(path string) ([]byte, error) {
					switch path {
					case e.nftPersistUnitPath:
						return []byte(renderTestNFTPersistUnit(e.nftRulesPath, e.pipelockTarget)), nil
					case e.nftRulesPath:
						return []byte(renderNFTRules(1000, 988, 987, e.port, e.nftTable, e.nftChain)), nil
					case e.configPath:
						if tc.readErr != nil {
							return nil, tc.readErr
						}
						return []byte(tc.config), nil
					default:
						return nil, errors.New("unexpected read")
					}
				}
			})
			if err := verifyNFTPersistence(env, current); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("verify error = %v, want %q", err, tc.want)
			}
		})
	}
}
