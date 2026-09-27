// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// The run-chain fixtures are real evidence directories written by pipelock
// runs; each variant's expect.json is generated from the Go reference.
const runChainFixtures = "../../sdk/conformance/testdata/run-chains"

type runChainExpectation struct {
	Valid  bool `json:"valid"`
	Chains []struct {
		Session string `json:"session"`
	} `json:"chains"`
	Linked []struct {
		Trust string `json:"trust"`
	} `json:"linked"`
	Unlinked []string `json:"unlinked"`
	Findings []struct {
		Kind    string `json:"kind"`
		Session string `json:"session"`
	} `json:"findings"`
}

func readRunChainFixture(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Clean(filepath.Join(runChainFixtures, name)))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return strings.TrimSpace(string(data))
}

func TestChainDir_RunChainFixturesMatchGoReference(t *testing.T) {
	t.Parallel()
	key := readRunChainFixture(t, "signer-key.hex")
	for _, v := range []string{
		"valid", "tampered-predecessor", "tampered-successor", "link-edited", "link-deleted",
		"double-successor", "link-wrong-tail", "link-appended", "key-rotated",
	} {
		t.Run(v, func(t *testing.T) {
			t.Parallel()
			var exp runChainExpectation
			if err := json.Unmarshal([]byte(readRunChainFixture(t, filepath.Join(v, "expect.json"))), &exp); err != nil {
				t.Fatal(err)
			}
			stdout, stderr, code := runRoot(t, "chain", filepath.Join(runChainFixtures, v), "--dir", "--key", key, "--json")
			wantCode := 1
			if exp.Valid {
				wantCode = 0
			}
			if code != wantCode {
				t.Fatalf("exit %d, want %d\nstdout: %s\nstderr: %s", code, wantCode, stdout, stderr)
			}
			var got chainSetReport
			if err := json.Unmarshal([]byte(stdout), &got); err != nil {
				t.Fatalf("decode report: %v\n%s", err, stdout)
			}
			if got.Valid != exp.Valid || got.Base != "proxy" {
				t.Fatalf("valid=%v base=%q, want valid=%v base proxy", got.Valid, got.Base, exp.Valid)
			}
			if len(got.Chains) != len(exp.Chains) {
				t.Fatalf("chains %d, want %d", len(got.Chains), len(exp.Chains))
			}
			for i := range exp.Chains {
				if got.Chains[i].Session != exp.Chains[i].Session {
					t.Fatalf("chain %d session %q, want %q", i, got.Chains[i].Session, exp.Chains[i].Session)
				}
			}
			if strings.Join(got.Continuity.Unlinked, ",") != strings.Join(exp.Unlinked, ",") {
				t.Fatalf("unlinked %v, want %v", got.Continuity.Unlinked, exp.Unlinked)
			}
			var gotFindings, wantFindings []string
			for _, f := range got.Continuity.Findings {
				gotFindings = append(gotFindings, f.Kind+"@"+f.Session)
			}
			for _, f := range exp.Findings {
				wantFindings = append(wantFindings, f.Kind+"@"+f.Session)
			}
			sort.Strings(gotFindings)
			sort.Strings(wantFindings)
			if strings.Join(gotFindings, ",") != strings.Join(wantFindings, ",") {
				t.Fatalf("findings %v, want %v", gotFindings, wantFindings)
			}
			// A run the base check rejected must never be reported valid.
			if !exp.Valid {
				for i, c := range got.Chains {
					for _, f := range exp.Findings {
						if f.Kind == "corrupt_chain" && f.Session == c.Session && c.Valid {
							t.Fatalf("chain %d (%s) reported valid despite a corrupt action chain", i, c.Session)
						}
					}
				}
			}
		})
	}
}

func TestChainDir_ExplicitSessionKeepsSingleSession(t *testing.T) {
	t.Parallel()
	key := readRunChainFixture(t, "signer-key.hex")
	dir := filepath.Join(runChainFixtures, "valid")
	var exp runChainExpectation
	if err := json.Unmarshal([]byte(readRunChainFixture(t, "valid/expect.json")), &exp); err != nil {
		t.Fatal(err)
	}
	session := exp.Chains[0].Session
	stdout, stderr, code := runRoot(t, "chain", dir, "--dir", "--key", key, "--session", session, "--json")
	if code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, stdout, stderr)
	}
	var single map[string]any
	if err := json.Unmarshal([]byte(stdout), &single); err != nil {
		t.Fatal(err)
	}
	if _, ok := single["continuity"]; ok {
		t.Fatal("explicit --session must keep the single-session report")
	}
	if single["valid"] != true {
		t.Fatalf("single-session report: %v", single)
	}

	// The legacy base named explicitly has no shards here, as before.
	stdout, _, code = runRoot(t, "chain", dir, "--dir", "--key", key, "--session", "proxy", "--json")
	if code != 1 || !strings.Contains(stdout, "no receipts in chain") {
		t.Fatalf("explicit legacy session: exit %d\n%s", code, stdout)
	}
}

func TestChainDir_RunChainHumanOutput(t *testing.T) {
	t.Parallel()
	key := readRunChainFixture(t, "signer-key.hex")
	stdout, stderr, code := runRoot(t, "chain", filepath.Join(runChainFixtures, "valid"), "--dir", "--key", key)
	if code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, stdout, stderr)
	}
	for _, want := range []string{
		`RESTART CONTINUITY OK: base "proxy": 2 chain(s), 1 linked, 1 unlinked, 0 link finding(s)`,
		"(same_key)",
		"  unlinked: proxy.run.",
		"  result:     VALID",
	} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("output lacks %q:\n%s", want, stdout)
		}
	}
}
