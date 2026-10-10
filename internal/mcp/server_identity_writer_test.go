// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"io"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/mcp/transport"
)

func TestServerIdentityWriterRefusesChangedFields(t *testing.T) {
	admitted := ServerIdentity{Name: "local-tools", PolicyName: "local-tools", Binding: "binding", BindingMode: "verified-local-session", Revision: "revision"}
	tests := []struct {
		name   string
		change func(*ServerIdentity)
	}{
		{"refusal", func(id *ServerIdentity) { id.Refusal = "registration changed" }},
		{"name", func(id *ServerIdentity) { id.Name = "other" }},
		{"policy name", func(id *ServerIdentity) { id.PolicyName = "" }},
		{"binding", func(id *ServerIdentity) { id.Binding = "other" }},
		{"binding mode", func(id *ServerIdentity) { id.BindingMode = "transport-v2" }},
		{"revision", func(id *ServerIdentity) { id.Revision = "other" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			current := admitted
			opts := (MCPProxyOpts{ServerIdentityFn: func() ServerIdentity { return current }}).withServerIdentity(admitted)
			var out strings.Builder
			writer := &serverIdentityMessageWriter{writer: transport.NewStdioWriter(&out), opts: opts}
			if err := writer.WriteMessage([]byte(identityUpstreamOK)); err != nil {
				t.Fatalf("positive control: %v", err)
			}
			out.Reset()
			tt.change(&current)
			if err := writer.WriteMessage([]byte(identityUpstreamOK)); err == nil || out.Len() != 0 {
				t.Fatalf("changed identity: err=%v output=%s", err, out.String())
			}
		})
	}
}

func TestForwardScannedIdentityChangeAtOutput(t *testing.T) {
	id := ServerIdentity{Name: "local-tools", PolicyName: "local-tools", Binding: "binding", BindingMode: "verified-local-session", Revision: "revision"}
	calls := 0
	opts := (MCPProxyOpts{
		Scanner: testScannerForHTTP(t),
		ServerIdentityFn: func() ServerIdentity {
			calls++
			if calls > 1 {
				return ServerIdentity{Refusal: "registration changed during scan"}
			}
			return id
		},
	}).withServerIdentity(id)
	var out, log strings.Builder
	reader := &transport.SingleMessageReader{Body: io.NopCloser(strings.NewReader(identityUpstreamOK))}
	_, err := ForwardScanned(reader, transport.NewStdioWriter(&out), &log, nil, opts)
	if err == nil || out.Len() != 0 || calls != 2 {
		t.Fatalf("output check: err=%v calls=%d output=%s", err, calls, out.String())
	}
}
