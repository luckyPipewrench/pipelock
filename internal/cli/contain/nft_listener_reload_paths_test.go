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

func TestReloadNFTRulesKeepsExistingListenerGuardOnBadConfig(t *testing.T) {
	persisted := renderNFTRulesWithServices(nftRuleOptions{OperatorUID: loopbackTestOperatorUID, ProxyUID: loopbackTestProxyUID, AgentUID: loopbackTestAgentUID, ProxyPort: loopbackTestProxyPort, Table: defaultNFTTable, Chain: defaultNFTChain, AgentListener: "127.0.0.1:8889"})
	for _, tc := range []struct {
		name, config, want string
		readErr            error
	}{
		{"missing", "", "missing; refusing to remove", os.ErrNotExist},
		{"unreadable", "", "read managed listener config", os.ErrPermission},
		{"malformed", "containment: [", "parse managed listener config", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fx := newNFTReloadTestFixture(t, nftReloadTestLiveWithNoService, tc.config, persisted)
			prior := fx.env.readFile
			fx.env.readFile = func(path string) ([]byte, error) {
				if path == fx.env.configPath && tc.readErr != nil {
					return nil, tc.readErr
				}
				return prior(path)
			}
			if err := reloadNFTRules(context.Background(), fx.env); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("reload error = %v, want %q", err, tc.want)
			}
			if got, ok := fx.persisted(); !ok || got != persisted {
				t.Fatalf("bad config changed or removed persisted rules: present=%t body=%q", ok, got)
			}
		})
	}
}

func TestReloadNFTRulesRejectsUnreadableConfigWithoutGuard(t *testing.T) {
	persisted := renderNFTRulesWithServices(nftRuleOptions{OperatorUID: loopbackTestOperatorUID, ProxyUID: loopbackTestProxyUID, AgentUID: loopbackTestAgentUID, ProxyPort: loopbackTestProxyPort, Table: defaultNFTTable, Chain: defaultNFTChain})
	fx := newNFTReloadTestFixture(t, nftReloadTestLiveWithNoService, "", persisted)
	prior := fx.env.readFile
	fx.env.readFile = func(path string) ([]byte, error) {
		if path == fx.env.configPath {
			return nil, os.ErrPermission
		}
		return prior(path)
	}
	if err := reloadNFTRules(context.Background(), fx.env); !errors.Is(err, os.ErrPermission) || !strings.Contains(err.Error(), "read managed listener config") {
		t.Fatalf("reload error = %v, want wrapped config permission error", err)
	}
	if got, ok := fx.persisted(); !ok || got != persisted {
		t.Fatalf("unreadable config changed persisted rules: present=%t body=%q", ok, got)
	}
}
