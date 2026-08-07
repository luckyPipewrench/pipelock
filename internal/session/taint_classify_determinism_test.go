// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package session_test

import (
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/session"
)

// classifyRuns is high enough that map-order randomization cannot pass by
// chance. Each iteration re-decodes the arguments into a fresh map and
// exercises a new map iteration; with three candidate keys, current Go
// runtime behavior makes 400 consecutive runs agreeing on one arbitrary
// winner negligibly likely.
const classifyRuns = 400

// TestClassifyMCPToolCall_ActionRefIsStableAcrossRuns pins the action
// reference for a tool call carrying several candidate targets.
//
// The reference is not cosmetic. It is what an operator's taint trust
// override is matched against, so a reference that varies between runs makes
// the same tool call honor an override on one run and miss it on the next.
// Selecting it by Go map iteration order could make that happen when the
// arguments held distinct path or URL candidates.
//
// Both assertions matter and they fail for different reasons. Stability
// catches the randomization. The exact expected value catches a future change
// that is deterministic but silently picks a different target.
func TestClassifyMCPToolCall_ActionRefIsStableAcrossRuns(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		tool      string
		argsJSON  string
		wantClass session.ActionClass
		wantRef   string
	}{
		{
			name: "browse picks the first url by sorted key",
			tool: "fetch",
			// Deliberately not in sorted order in the document, so a
			// document-order implementation and a sorted implementation
			// disagree and the assertion pins which one shipped.
			argsJSON: `{"zeta_url":"https://zeta.vendor.example/z",` +
				`"alpha_url":"https://alpha.vendor.example/a",` +
				`"mid_url":"https://mid.vendor.example/m"}`,
			wantClass: session.ActionClassBrowse,
			wantRef:   "https://alpha.vendor.example/a",
		},
		{
			name: "read picks the first path by sorted key",
			tool: "read_file",
			argsJSON: `{"zeta_path":"/srv/zeta/data.txt",` +
				`"alpha_path":"/srv/alpha/data.txt",` +
				`"mid_path":"/srv/mid/data.txt"}`,
			wantClass: session.ActionClassRead,
			wantRef:   "/srv/alpha/data.txt",
		},
		{
			name: "nested objects are ordered at every depth",
			tool: "fetch",
			argsJSON: `{"outer":{"zeta_url":"https://zeta.vendor.example/z",` +
				`"alpha_url":"https://alpha.vendor.example/a"},` +
				`"also":{"beta_url":"https://beta.vendor.example/b"}}`,
			// "also" sorts before "outer", so its subtree is walked first.
			wantClass: session.ActionClassBrowse,
			wantRef:   "https://beta.vendor.example/b",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			for run := range classifyRuns {
				class, _, ref := session.ClassifyMCPToolCall(tc.tool, tc.argsJSON, nil, nil)
				if class != tc.wantClass {
					t.Fatalf("run %d: class = %v, want %v", run, class, tc.wantClass)
				}
				if ref != tc.wantRef {
					t.Fatalf("run %d: action ref = %q, want %q (selection must not vary between runs)",
						run, ref, tc.wantRef)
				}
			}
		})
	}
}

// TestClassifyMCPToolCall_ShellCommandOrderIsStable covers the second
// consumer of the same flattened slice. The exec path joins every extracted
// string into one command line and scans it for multi-token shell patterns
// such as "git push", so an unordered walk can push two tokens together
// across a join boundary and manufacture a match that the same input does not
// produce on the next run.
//
// These arguments are built for exactly that. The walk emits each key before
// its value, so the value "git" landing immediately before the key "push"
// spells the pattern, and whether that adjacency happens depends entirely on
// which key is visited first. Sorted keys settle it the same way every time.
func TestClassifyMCPToolCall_ShellCommandOrderIsStable(t *testing.T) {
	t.Parallel()

	const argsJSON = `{"x":"git","push":"origin main"}`

	// Pinned, not taken from the first run. Using run zero as the oracle
	// would let a deterministic regression that changes the verdict pass,
	// because every later run would agree with the new wrong answer.
	//
	// Sorted keys emit push, origin main, x, git, which spells no mutating
	// pattern, so this is a non-mutating exec and sensitivity stays
	// protected. Unsorted, the value git can land before the key push and
	// form "git push", which flips sensitivity to elevated.
	const (
		wantClass       = session.ActionClassExec
		wantSensitivity = session.SensitivityProtected
	)

	for run := range classifyRuns {
		class, sensitivity, _ := session.ClassifyMCPToolCall("shell", argsJSON, nil, nil)
		if class != wantClass || sensitivity != wantSensitivity {
			t.Fatalf("run %d: class/sensitivity = %v/%v, want %v/%v on every run",
				run, class, sensitivity, wantClass, wantSensitivity)
		}
	}
}
