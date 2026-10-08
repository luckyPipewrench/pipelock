// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGroupAELMembershipRequiresEachSignedShardSession(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "sdk", "verifiers", "receipt-group-membership-vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct {
		Name            string   `json:"name"`
		SignedSessions  []string `json:"signed_sessions"`
		ClaimedSessions []string `json:"claimed_sessions"`
		Incomplete      bool     `json:"incomplete"`
		Error           string   `json:"error"`
	}
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatal(err)
	}
	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			open := ReceiptGroupOpen{GroupID: strings.Repeat("1", 32)}
			for _, session := range tc.SignedSessions {
				open.Shards = append(open.Shards, ReceiptGroupShard{SessionID: session})
			}
			membership := newGroupAELMembership(open)
			var err error
			for _, session := range tc.ClaimedSessions {
				if err = membership.Add(session); err != nil {
					break
				}
			}
			if err == nil {
				err = membership.Finish(tc.Incomplete)
			}
			if tc.Error == "" && err != nil || tc.Error != "" && (err == nil || !strings.Contains(err.Error(), tc.Error)) {
				t.Fatalf("membership = %v, want %q", err, tc.Error)
			}
		})
	}
}
