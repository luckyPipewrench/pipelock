// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/mcp/transport"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestDaybreak_EmbeddedResourceVideoBypassesMediaPolicy(t *testing.T) {
	sc, cfg := newMCPScannerWithMediaPolicy(t)
	payload := base64.StdEncoding.EncodeToString([]byte("fake video bytes"))

	topLevel := fmt.Sprintf(
		`{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"video","mimeType":"video/mp4","data":"%s"}]}}`,
		payload,
	)
	embedded := fmt.Sprintf(
		`{"jsonrpc":"2.0","id":2,"result":{"content":[{"type":"resource","resource":{"uri":"file:///clip.mp4","mimeType":"video/mp4","blob":"%s"}}]}}`,
		payload,
	)

	if !mcpLineMediaBlocked(t, sc, cfg, topLevel) {
		t.Fatal("control: top-level video/mp4 was not blocked")
	}
	if !mcpLineMediaBlocked(t, sc, cfg, embedded) {
		t.Fatal("embedded resource.blob video/mp4 was forwarded; media policy did not see nested mimeType/blob")
	}
}

func mcpLineMediaBlocked(t *testing.T, sc *scanner.Scanner, cfg *config.Config, line string) bool {
	t.Helper()
	var out, log bytes.Buffer
	found, err := ForwardScanned(
		transport.NewStdioReader(strings.NewReader(line+"\n")),
		transport.NewStdioWriter(&out),
		&log,
		nil,
		MCPProxyOpts{
			Scanner:     sc,
			MediaPolicy: &cfg.MediaPolicy,
			Transport:   testMCPMediaTransport,
		},
	)
	if err != nil {
		t.Fatalf("ForwardScanned: %v", err)
	}
	if found {
		return true
	}
	var resp rpcError
	if err := json.Unmarshal(bytes.TrimSpace(out.Bytes()), &resp); err != nil {
		return false
	}
	return resp.Error.Message != ""
}
