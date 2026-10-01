// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/killswitch"
)

// killSwitchBatchOfCalls builds a batch of n tool calls with ids 1..n.
func killSwitchBatchOfCalls(n int) []byte {
	var b strings.Builder
	b.WriteByte('[')
	for i := 1; i <= n; i++ {
		if i > 1 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `{"jsonrpc":"2.0","id":%d,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"x"}}}`, i)
	}
	b.WriteByte(']')
	return []byte(b.String())
}

// TestKillSwitchBatchReceiptsAreCapped proves one refused batch signs at most
// maxKillSwitchBatchReceipts receipts, says once how many members it did not
// receipt, and still answers every member with an id.
func TestKillSwitchBatchReceiptsAreCapped(t *testing.T) {
	d := killswitch.Decision{Active: true, Source: "api", Message: killSwitchBatchMessage}
	const over = maxKillSwitchBatchReceipts + 40
	cases := []struct {
		name        string
		members     int
		wantReceipt int
		wantSkipped int
	}{
		{"below the cap", maxKillSwitchBatchReceipts - 1, maxKillSwitchBatchReceipts - 1, 0},
		{"exactly the cap", maxKillSwitchBatchReceipts, maxKillSwitchBatchReceipts, 0},
		{"one over the cap", maxKillSwitchBatchReceipts + 1, maxKillSwitchBatchReceipts, 1},
		{"far over the cap", over, maxKillSwitchBatchReceipts, over - maxKillSwitchBatchReceipts},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := &allReceipts{}
			emitter, _, _, _ := newReceiptTestHarnessWithObserver(t, got.observe)
			var logW bytes.Buffer
			resp := refuseKillSwitchRequest(MCPProxyOpts{ReceiptEmitter: emitter, Transport: transportMCPStdio}, &logW, ParseMCPFrame(killSwitchBatchOfCalls(tc.members)), d)

			if n := len(got.snapshot()); n != tc.wantReceipt {
				t.Fatalf("receipts = %d, want %d", n, tc.wantReceipt)
			}
			var errs []struct {
				ID    int `json:"id"`
				Error struct {
					Code int `json:"code"`
				} `json:"error"`
			}
			if err := json.Unmarshal(resp, &errs); err != nil {
				t.Fatalf("response: %v", err)
			}
			if len(errs) != tc.members {
				t.Fatalf("response entries = %d, want one per member (%d)", len(errs), tc.members)
			}
			for i, e := range errs {
				if e.ID != i+1 || e.Error.Code != -32004 {
					t.Fatalf("response %d = %+v, want id %d code -32004", i, e, i+1)
				}
			}
			warning := fmt.Sprintf("%d refused members were not individually receipted", tc.wantSkipped)
			if tc.wantSkipped == 0 {
				if logW.Len() != 0 {
					t.Fatalf("no members skipped, but logged %q", logW.String())
				}
				return
			}
			if strings.Count(logW.String(), "\n") != 1 || !strings.Contains(logW.String(), warning) {
				t.Fatalf("log = %q, want exactly one line containing %q", logW.String(), warning)
			}
		})
	}
}

// TestKillSwitchBatchWithoutEmitterWarnsOfNothing keeps the warning honest: no
// emitter means nothing was receipted for any member, so there is nothing to
// say about a cap.
func TestKillSwitchBatchWithoutEmitterWarnsOfNothing(t *testing.T) {
	var logW bytes.Buffer
	d := killswitch.Decision{Active: true, Message: killSwitchBatchMessage}
	resp := refuseKillSwitchRequest(MCPProxyOpts{}, &logW, ParseMCPFrame(killSwitchBatchOfCalls(maxKillSwitchBatchReceipts+5)), d)
	if resp == nil || logW.Len() != 0 {
		t.Fatalf("resp nil=%v log=%q, want a response and no log", resp == nil, logW.String())
	}
}
