// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package a2amethods

import "testing"

func TestKnownReturnsCopy(t *testing.T) {
	methods := Known()
	if !methods["SendMessage"] || !methods["message/send"] {
		t.Fatalf("Known missing expected A2A methods: %v", methods)
	}

	methods["StealEverything"] = true
	if Is("StealEverything") {
		t.Fatal("mutating Known result changed package method inventory")
	}
}

func TestCanonicalNormalizesCaseVariants(t *testing.T) {
	// A case variant of a known method must canonicalize to the exact known
	// name so detection and enforcement agree; unknown methods are rejected.
	cases := []struct {
		in     string
		want   string
		wantOK bool
	}{
		{"SendMessage", "SendMessage", true},
		{"sendmessage", "SendMessage", true},
		{"SENDMESSAGE", "SendMessage", true},
		{"tasks/get", "tasks/get", true},
		{"TASKS/GET", "tasks/get", true},
		{"StealEverything", "", false},
		{"a2a:GetTask", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			got, ok := Canonical(tc.in)
			if ok != tc.wantOK || got != tc.want {
				t.Fatalf("Canonical(%q) = (%q,%v), want (%q,%v)", tc.in, got, ok, tc.want, tc.wantOK)
			}
		})
	}
}

func TestIsRecognizesKnownAndRejectsUnknown(t *testing.T) {
	if !Is("SendMessage") || !Is("sendmessage") || !Is("tasks/get") {
		t.Fatal("Is failed to recognize a known method or case variant")
	}
	if Is("StealEverything") || Is("a2a:GetTask") {
		t.Fatal("Is recognized an unknown or reserved-prefix method")
	}
}
