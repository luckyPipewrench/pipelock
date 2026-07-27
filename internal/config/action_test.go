// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import "testing"

func TestStrongestAction(t *testing.T) {
	tests := []struct {
		name    string
		actions []string
		want    string
	}{
		{name: "none", want: ""},
		{name: "unknown only", actions: []string{"allow", ""}, want: ""},
		{name: "warn beats default", actions: []string{"", ActionWarn}, want: ActionWarn},
		{name: "block beats warn regardless of order", actions: []string{ActionWarn, ActionBlock}, want: ActionBlock},
		{name: "block beats warn when first", actions: []string{ActionBlock, ActionWarn}, want: ActionBlock},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := StrongestAction(tt.actions...); got != tt.want {
				t.Fatalf("StrongestAction(%v) = %q, want %q", tt.actions, got, tt.want)
			}
		})
	}
}
