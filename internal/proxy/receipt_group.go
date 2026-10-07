// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"errors"
	"fmt"

	"github.com/luckyPipewrench/pipelock/internal/contract/proxydecision"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
)

// receiptGroupRuntime pairs each v1 shard with its v2 emitter. The slice is
// immutable after publication; both emitters write to the same recorder session.
type receiptGroupRuntime struct {
	shards            *receipt.ReceiptShardSet
	v2                []*proxydecision.Emitter
	onRequiredFailure func(error)
}

// WithReceiptShardSet validates and installs the fixed emitters for a group.
// The process shard remains available to legacy lifecycle consumers, while
// traffic emission requires an admission-time shard selection.
func WithReceiptShardSet(shards *receipt.ReceiptShardSet, v2 []*proxydecision.Emitter, onRequiredFailure ...func(error)) (Option, error) {
	if shards == nil || shards.ProcessEmitter() == nil {
		return nil, errors.New("receipt group has no process emitter")
	}
	open, _ := shards.Opening()
	if len(v2) != open.ShardCount {
		return nil, fmt.Errorf("receipt group has %d v2 emitters, want %d", len(v2), open.ShardCount)
	}
	for i, emitter := range v2 {
		if emitter == nil {
			return nil, fmt.Errorf("receipt group v2 shard %d is unavailable", i)
		}
	}
	if len(onRequiredFailure) > 1 {
		return nil, errors.New("receipt group accepts one required failure callback")
	}
	group := &receiptGroupRuntime{shards: shards, v2: append([]*proxydecision.Emitter(nil), v2...)}
	if len(onRequiredFailure) == 1 {
		group.onRequiredFailure = onRequiredFailure[0]
	}
	return func(p *Proxy) {
		p.receiptEmitterPtr.Store(shards.ProcessEmitter())
		p.v2EmitterPtr.Store(group.v2[open.ProcessShardIndex])
		p.noteReceiptSignerKey(shards.ProcessEmitter().SignerKeyHex())
		p.receiptGroupPtr.Store(group)
	}, nil
}

func (g *receiptGroupRuntime) failRequired(err error) {
	if g == nil || err == nil {
		return
	}
	g.shards.MarkUnhealthy(err)
	if g.onRequiredFailure != nil {
		g.onRequiredFailure(err)
	}
}

func (p *Proxy) admitReceiptShard() receipt.EmitOpts {
	if group := p.receiptGroupPtr.Load(); group != nil {
		return group.shards.Admit(receipt.EmitOpts{})
	}
	return receipt.EmitOpts{}
}

func withReceiptShard(opts, selected receipt.EmitOpts) receipt.EmitOpts {
	if selected.ShardSelected {
		opts.ShardIndex = selected.ShardIndex
		opts.ShardSelected = true
	}
	return opts
}

func receiptShardFromContext(ctx context.Context) receipt.EmitOpts {
	selected, _ := ctx.Value(ctxKeyReceiptShard).(receipt.EmitOpts)
	return selected
}

func (g *receiptGroupRuntime) v2Emitter(opts receipt.EmitOpts) (*proxydecision.Emitter, error) {
	if !opts.ShardSelected || opts.ShardIndex < 0 || opts.ShardIndex >= len(g.v2) || g.v2[opts.ShardIndex] == nil {
		return nil, errors.New("receipt group v2 shard was not selected at admission")
	}
	return g.v2[opts.ShardIndex], nil
}
