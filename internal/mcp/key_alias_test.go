// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/mcp/transport"
)

func TestKeyAliasesInputTransports(t *testing.T) {
	policy := buildPolicyConfig(config.ActionBlock, []config.ToolPolicyRule{{Name: "deny-write", ToolPattern: `^write_file$`}})
	for _, raw := range []string{
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","Method":"ping","params":{"name":"write_file","arguments":{}}}`,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"write_file","Name":"read_file","arguments":{}}}`,
		`{"jsonrpc":"2.0","id":1,"method":"ping","params":{},"PARAMS":{}}`,
		`{"jsonrpc":"2.0","id":1,"method":"ping","params":{"arguments":{},"Arguments":{}}}`,
	} {
		t.Run(raw, func(t *testing.T) {
			opts := MCPProxyOpts{Scanner: testInputScanner(t), PolicyCfg: policy}
			if v := policy.CheckRequest([]byte(raw)); !v.Matched || v.Action != config.ActionBlock {
				t.Errorf("direct policy accepted ambiguous input: %+v", v)
			}
			result := scanHTTPInputDecision([]byte(raw), &bytes.Buffer{}, "session-1", "session-1", opts)
			if result.Blocked == nil {
				t.Error("HTTP accepted ambiguous input")
			}
			var upstream, logs bytes.Buffer
			blocked := make(chan BlockedRequest, 1)
			ForwardScannedInput(transport.NewStdioReader(strings.NewReader(raw+"\n")), transport.NewStdioWriter(&upstream), &logs, config.ActionWarn, config.ActionBlock, blocked, nil, nil, opts)
			if upstream.Len() != 0 {
				t.Errorf("stdio forwarded ambiguous input: %s", upstream.String())
			}
		})
	}
	raw := []byte(`{"jsonrpc":"2.0","id":2,"method":"ping"}`)
	if result := scanHTTPInputDecision(raw, &bytes.Buffer{}, "session-1", "session-1", MCPProxyOpts{Scanner: testInputScanner(t), PolicyCfg: policy}); result.Blocked != nil {
		t.Fatalf("valid control blocked: %+v", result)
	}
}

func TestKeyAliasesResponse(t *testing.T) {
	sc := testScanner(t)
	for _, raw := range []string{
		`{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"sample","description":"hello"}]},"Result":{"tools":[]}}`,
		`{"jsonrpc":"2.0","id":1,"result":{"tools":[],"Tools":[]}}`,
	} {
		if v := ScanResponse([]byte(raw), sc); v.Clean {
			t.Errorf("response accepted ambiguous input: %s", raw)
		}
	}
	if v := ScanResponse([]byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}`), sc); !v.Clean {
		t.Fatalf("valid response control: %+v", v)
	}
}

func TestKeyAliasesAgentCard(t *testing.T) {
	for _, scan := range []bool{true, false} {
		t.Run(fmt.Sprint(scan), func(t *testing.T) {
			sc := testA2AScanner(t)
			cfg := enabledA2ACfg()
			cfg.ScanAgentCards = scan
			cfg.DetectCardDrift = true
			baseline := NewCardBaseline(10)
			key := CardCacheKeyFromRequest("https://agent.vendor.example/card", "")
			clean := []byte(`{"name":"Agent","url":"https://agent.vendor.example/a2a","skills":[{"id":"read","description":"Search"}]}`)
			if v := ScanAgentCard(t.Context(), clean, sc, baseline, key, cfg); !v.Clean {
				t.Fatalf("valid baseline: %+v", v)
			}
			for _, raw := range []string{
				`{"name":"Agent","url":"https://other.vendor.example/a2a","URL":"https://agent.vendor.example/a2a","skills":[{"id":"read","description":"Search"}]}`,
				`{"name":"Agent","url":"https://agent.vendor.example/a2a","skills":[{"id":"write","description":"Search"}],"Skills":[{"id":"read","description":"Search"}]}`,
			} {
				if v := ScanAgentCard(t.Context(), []byte(raw), sc, baseline, key, cfg); v.Clean {
					t.Errorf("ambiguous card accepted: %s", raw)
				}
			}
			if v := ScanAgentCard(t.Context(), clean, sc, baseline, key, cfg); !v.Clean {
				t.Fatalf("baseline changed after rejection: %+v", v)
			}
		})
	}
}

func TestKeyAliasesResetDelegation(t *testing.T) {
	pub, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	delegation, err := MintResetDelegation(private, ResetDelegationRequest{
		Issuer: "operator", Kind: ResetKindDrift, Target: "mcp://fixture-listener",
		InstanceID: strings.Repeat("a", 32), Epoch: 1, IssuedAt: resetAuthorityTestNow,
		ExpiresAt: resetAuthorityTestNow.Add(time.Minute), Nonce: strings.Repeat("b", 32),
	})
	if err != nil {
		t.Fatal(err)
	}
	raw := resetDelegationBytes(t, delegation)
	parsed, err := ParseResetDelegation(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyResetDelegationSignature(pub, parsed); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"target", "epoch", "kind", "signature"} {
		changed := bytes.Replace(raw, []byte(`"`+key+`":`), []byte(`"`+strings.ToUpper(key)+`":`), 1)
		if bytes.Equal(changed, raw) {
			t.Fatalf("fixture missing %s", key)
		}
		if _, err := ParseResetDelegation(changed); err == nil {
			t.Errorf("accepted %s alias", key)
		}
	}
}
