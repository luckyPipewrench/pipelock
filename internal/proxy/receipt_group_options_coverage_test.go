// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"errors"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/contract/proxydecision"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
)

func TestReceiptShardOptionsRejectIncompleteEmitterPairs(t *testing.T) {
	_, shards, proxy, cancels := newReceiptFailureGroup(t)
	v2 := proxy.receiptGroupPtr.Load().v2
	for _, tc := range []struct {
		name, want string
		shards     *receipt.ReceiptShardSet
		v2         []*proxydecision.Emitter
		callbacks  []func(error)
	}{
		{"missing group", "no process emitter", nil, v2, nil},
		{"wrong count", "v2 emitters", shards, v2[:1], nil},
		{"missing paired emitter", "v2 shard 1 is unavailable", shards, []*proxydecision.Emitter{v2[0], nil}, nil},
		{"ambiguous callback", "one required failure callback", shards, v2, []func(error){func(error) {}, func(error) {}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			option, err := WithReceiptShardSet(tc.shards, tc.v2, tc.callbacks...)
			if option != nil || err == nil || !strings.Contains(err.Error(), tc.want) || *cancels != 0 {
				t.Fatalf("invalid pair option=%v err=%v cancels=%d, want %q", option, err, *cancels, tc.want)
			}
		})
	}
	var absent *receiptGroupRuntime
	absent.failRequired(errors.New("no group"))
	if *cancels != 0 {
		t.Fatalf("nil group fired callback %d times", *cancels)
	}
}
