// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"errors"
	"fmt"

	"github.com/luckyPipewrench/pipelock/internal/contract/proxydecision"
	"github.com/luckyPipewrench/pipelock/internal/mcp"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

// buildMCPReceiptGroup binds each v2 emitter to the same acquired session as
// its v1 shard. The signed opening and session opens are durable before this
// returns, so callers must refuse traffic on any error.
func buildMCPReceiptGroup(template receipt.EmitterConfig, count int) (*mcp.MCPReceiptGroup, error) {
	if template.Recorder == nil || len(template.PrivKey) == 0 {
		return nil, errors.New("MCP receipt group requires a signed recorder")
	}
	trusted, err := receipt.TrustedGroupSignerKeys(template)
	if err != nil {
		return nil, err
	}
	previousID, hasPrevious, err := receipt.FindTerminalReceiptGroup(template.Recorder.Dir(), recorder.DefaultSessionBase, trusted)
	if err != nil {
		return nil, fmt.Errorf("find previous MCP receipt group: %w", err)
	}
	var shards *receipt.ReceiptShardSet
	if hasPrevious {
		shards, err = receipt.OpenSuccessorReceiptShardSet(template, recorder.DefaultSessionBase, count, 0, previousID)
	} else {
		shards, err = receipt.OpenInitialReceiptShardSet(template, recorder.DefaultSessionBase, count, 0)
	}
	if err != nil {
		return nil, fmt.Errorf("open MCP receipt group: %w", err)
	}
	opening, _ := shards.Opening()
	group := &mcp.MCPReceiptGroup{Shards: shards, V2: make([]*proxydecision.Emitter, len(opening.Shards))}
	for i, shard := range opening.Shards {
		group.V2[i] = proxydecision.NewEmitter(proxydecision.EmitterConfig{
			Recorder:  template.Recorder,
			Signer:    proxydecision.NewKeyedSigner(template.PrivKey),
			Sanitize:  proxydecision.SanitizeFromRedactor(template.Recorder.ReceiptRedactor()),
			Principal: template.Principal,
			Actor:     template.Actor,
			Session:   shard.SessionID,
		})
		if group.V2[i] == nil {
			return nil, fmt.Errorf("initialize MCP receipt group shard %d v2 emitter", i)
		}
	}
	return group, nil
}
