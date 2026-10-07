// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"strings"
	"testing"
)

func TestGroupAELMembershipRequiresEachSignedShardSession(t *testing.T) {
	open := ReceiptGroupOpen{GroupID: strings.Repeat("1", 32), Shards: []ReceiptGroupShard{
		{SessionID: "proxy.run." + strings.Repeat("a", 32)},
		{SessionID: "proxy.run." + strings.Repeat("b", 32)},
	}}
	for _, tc := range []struct {
		name       string
		sessions   []string
		incomplete bool
		want       string
	}{
		{"complete", []string{open.Shards[0].SessionID, open.Shards[1].SessionID}, false, ""},
		{"missing", []string{open.Shards[0].SessionID}, false, "claims"},
		{"foreign substitutes for missing", []string{open.Shards[0].SessionID, "proxy.run." + strings.Repeat("c", 32)}, false, "outside signed shard membership"},
		{"duplicate substitutes for missing", []string{open.Shards[0].SessionID, open.Shards[0].SessionID}, false, "duplicate claims"},
		{"incomplete prefix", []string{open.Shards[0].SessionID}, true, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			membership := newGroupAELMembership(open)
			var err error
			for _, session := range tc.sessions {
				if err = membership.Add(session); err != nil {
					break
				}
			}
			if err == nil {
				err = membership.Finish(tc.incomplete)
			}
			if tc.want == "" && err != nil || tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)) {
				t.Fatalf("membership = %v, want %q", err, tc.want)
			}
		})
	}
}
