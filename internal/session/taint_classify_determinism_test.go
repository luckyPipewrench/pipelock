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

// TestClassifyMCPToolCall_ShellCommandOrderIsStable proves shell classification
// scans declared command vectors, never object keys or a flattened mix of
// unrelated values. It retains the repeated-run assertion because command
// field extraction must remain deterministic.
func TestClassifyMCPToolCall_ShellCommandOrderIsStable(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		argsJSON        string
		wantSensitivity session.ActionSensitivity
	}{
		{
			name:            "keys cannot manufacture a command",
			argsJSON:        `{"a":"git","push":"origin main"}`,
			wantSensitivity: session.SensitivityProtected,
		},
		{
			name:            "command and argv form one vector despite unrelated fields",
			argsJSON:        `{"argv":["push","origin","main"],"command":"git","decoy":"status"}`,
			wantSensitivity: session.SensitivityElevated,
		},
		{
			name:            "array command vector is scanned",
			argsJSON:        `{"args":["git","push","origin","main"]}`,
			wantSensitivity: session.SensitivityElevated,
		},
		{
			// Arguments that are not JSON at all yield no command vector.
			// The call must still be treated as a protected exec rather
			// than read as benign for lack of a parseable command.
			name:            "unparseable arguments stay protected",
			argsJSON:        `{"command": "git push`,
			wantSensitivity: session.SensitivityProtected,
		},
		{
			// A top-level array still has to be walked, or a command
			// nested one level up from an object would be missed.
			name:            "top level array is walked",
			argsJSON:        `[{"command":"git push origin main"}]`,
			wantSensitivity: session.SensitivityElevated,
		},
		{
			// A vector field holding no strings contributes nothing, and
			// the base command alone decides the verdict.
			name:            "non string vector contributes no command text",
			argsJSON:        `{"command":"status","argv":[1,2,{"push":"origin"}]}`,
			wantSensitivity: session.SensitivityProtected,
		},
		{
			// A recognized field can hold a nested container. Without a
			// recursive walk into it the command never reaches the matcher
			// and a real mutation is scanned as if it were absent.
			name:            "nested container under a recognized field is scanned",
			argsJSON:        `{"command":{"cmd":"git","argv":["push","origin","main"]}}`,
			wantSensitivity: session.SensitivityElevated,
		},
		{
			// program marks an exec in hasExecIntent, so extraction has to
			// recognize it too or its command goes unscanned.
			name:            "program field is a command base",
			argsJSON:        `{"program":"git","argv":["push","origin","main"]}`,
			wantSensitivity: session.SensitivityElevated,
		},
		{
			// Two vector fields are two independent command candidates. A
			// regression that flattened them back into one would spell a
			// mutation out of tokens that were never one command.
			name:            "separate vectors do not form one command",
			argsJSON:        `{"args":["git"],"argv":["push"]}`,
			wantSensitivity: session.SensitivityProtected,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			for run := range classifyRuns {
				class, sensitivity, _ := session.ClassifyMCPToolCall("shell", tt.argsJSON, nil, nil)
				if class != session.ActionClassExec || sensitivity != tt.wantSensitivity {
					t.Fatalf("run %d: class/sensitivity = %v/%v, want %v/%v on every run",
						run, class, sensitivity, session.ActionClassExec, tt.wantSensitivity)
				}
			}
		})
	}
}
