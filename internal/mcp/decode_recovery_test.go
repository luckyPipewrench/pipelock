// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/mcp/transport"
)

func TestDecodeRecoveryMCPTransports(t *testing.T) {
	sc := testInputScanner(t)
	token := "ghp_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	h := hex.EncodeToString([]byte(token))
	for _, value := range []string{"g" + h, "gg" + base64.StdEncoding.EncodeToString([]byte(token)), "%67" + token[1:] + "%ZZ", "https://api.vendor.example/?q=" + h + ";x=1"} {
		msg := makeRequest(1, "tools/call", map[string]any{"name": "send", "arguments": map[string]string{"note": value}}) + "\n"
		opts := buildTestOpts(sc)
		opts.InputCfg = &InputScanConfig{Enabled: true, Action: config.ActionBlock, OnParseError: config.ActionBlock}
		var forwarded, logs bytes.Buffer
		blocked := make(chan BlockedRequest, 1)
		ForwardScannedInput(transport.NewStdioReader(strings.NewReader(msg)), transport.NewStdioWriter(&forwarded), &logs, config.ActionBlock, config.ActionBlock, blocked, nil, nil, opts)
		if forwarded.Len() != 0 {
			t.Error("stdio forwarded recovered credential")
		}
		select {
		case <-blocked:
		default:
			t.Error("stdio omitted blocked verdict")
		}
		if result := scanHTTPInput([]byte(msg), &logs, "session", "audit", opts); result == nil {
			t.Error("HTTP/SSE input accepted recovered credential")
		}
	}
}
