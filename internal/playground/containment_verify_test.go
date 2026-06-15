// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package playground_test

import (
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/playground"
)

const hcwFile = "host-containment-witness.json"

// manifestHash reads the run dir's launch manifest and returns its Hash().
func manifestHash(t *testing.T, dir string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Clean(filepath.Join(dir, "launch-manifest.json")))
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	var lm playground.LaunchManifest
	if err := json.Unmarshal(data, &lm); err != nil {
		t.Fatalf("unmarshal manifest: %v", err)
	}
	return lm.Hash()
}

// writeHCW signs w with orchPriv and overwrites the run dir's witness file.
func writeHCW(t *testing.T, dir string, orchPriv ed25519.PrivateKey, w playground.HostContainmentWitness) {
	t.Helper()
	signed := playground.SignHostContainmentWitness(orchPriv, w)
	b, err := json.Marshal(signed)
	if err != nil {
		t.Fatalf("marshal hcw: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, hcwFile), b, 0o600); err != nil {
		t.Fatalf("write hcw: %v", err)
	}
}

func hasCheck(rep playground.VerifyReport, name string) (bool, bool) {
	for _, c := range rep.Checks {
		if c.Name == name {
			return true, c.OK
		}
	}
	return false, false
}

func TestVerify_ContainedRun_Passes(t *testing.T) {
	t.Parallel()
	dir, orchPubHex, _ := buildRunDir(t, true)

	rep, err := playground.VerifyRun(dir, orchPubHex)
	if err != nil {
		t.Fatalf("VerifyRun: %v", err)
	}
	if !rep.OK {
		t.Fatalf("contained run should verify; checks=%+v", rep.Checks)
	}
	for _, name := range []string{
		"host-containment-witness-signature",
		"host-containment-binds-run",
		"host-containment-enforced",
	} {
		present, ok := hasCheck(rep, name)
		if !present || !ok {
			t.Errorf("check %q present=%v ok=%v, want present+ok", name, present, ok)
		}
	}
}

func TestVerify_Contained_MissingWitness_FailsClosed(t *testing.T) {
	t.Parallel()
	dir, orchPubHex, _ := buildRunDir(t, true)
	if err := os.Remove(filepath.Join(dir, hcwFile)); err != nil {
		t.Fatalf("remove hcw: %v", err)
	}
	rep, err := playground.VerifyRun(dir, orchPubHex)
	if err == nil && rep.OK {
		t.Fatal("contained run with no host-containment witness must fail closed")
	}
}

func TestVerify_Contained_MalformedWitness_FailsClosed(t *testing.T) {
	t.Parallel()
	dir, orchPubHex, _ := buildRunDir(t, true)
	if err := os.WriteFile(filepath.Join(dir, hcwFile), []byte("{not valid json"), 0o600); err != nil {
		t.Fatalf("write malformed hcw: %v", err)
	}
	rep, err := playground.VerifyRun(dir, orchPubHex)
	if err == nil && rep.OK {
		t.Fatal("malformed host-containment witness must fail closed")
	}
}

func TestVerify_Contained_TamperedWitnessByte_FailsClosed(t *testing.T) {
	t.Parallel()
	dir, orchPubHex, _ := buildRunDir(t, true)
	flipByteInFile(t, filepath.Join(dir, hcwFile))
	rep, err := playground.VerifyRun(dir, orchPubHex)
	if err == nil && rep.OK {
		t.Fatal("tampered host-containment witness must fail closed")
	}
}

func TestVerify_Contained_WitnessBoundToOtherRun_FailsClosed(t *testing.T) {
	t.Parallel()
	dir, orchPubHex, orchPriv := buildRunDir(t, true)
	// Re-sign a witness bound to a DIFFERENT nonce but with the real orch key.
	w := validHostContainmentWitness("some-other-nonce", manifestHash(t, dir))
	writeHCW(t, dir, orchPriv, w)

	rep, err := playground.VerifyRun(dir, orchPubHex)
	if err == nil && rep.OK {
		t.Fatal("host-containment witness bound to another run must fail closed")
	}
	if present, ok := hasCheck(rep, "host-containment-binds-run"); present && ok {
		t.Error("binding check should not pass for a mismatched nonce")
	}
}

func TestVerify_Contained_NotEnforced_FailsClosed(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		mutate func(w playground.HostContainmentWitness) playground.HostContainmentWitness
	}{
		{
			name: "a direct-egress route was open (leak)",
			mutate: func(w playground.HostContainmentWitness) playground.HostContainmentWitness {
				w.AgentProbes[0].Open = true
				return w
			},
		},
		{
			name: "control agent probe connected (no kernel block)",
			mutate: func(w playground.HostContainmentWitness) playground.HostContainmentWitness {
				w.ControlAgentProbe.Open = true
				return w
			},
		},
		{
			name: "control operator probe blocked (broken differential)",
			mutate: func(w playground.HostContainmentWitness) playground.HostContainmentWitness {
				w.ControlOperatorProbe.Open = false
				return w
			},
		},
		{
			name: "direct-egress suite target omitted",
			mutate: func(w playground.HostContainmentWitness) playground.HostContainmentWitness {
				w.AgentProbes = w.AgentProbes[:len(w.AgentProbes)-1]
				return w
			},
		},
		{
			name: "direct-egress suite target substituted",
			mutate: func(w playground.HostContainmentWitness) playground.HostContainmentWitness {
				w.AgentProbes[0].Target = "127.0.0.1:1"
				return w
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dir, orchPubHex, orchPriv := buildRunDir(t, true)
			w := tc.mutate(validHostContainmentWitness("verify-test-nonce", manifestHash(t, dir)))
			writeHCW(t, dir, orchPriv, w)

			rep, err := playground.VerifyRun(dir, orchPubHex)
			if err == nil && rep.OK {
				t.Fatal("non-enforced host-containment witness must fail closed")
			}
			if present, ok := hasCheck(rep, "host-containment-enforced"); present && ok {
				t.Error("enforced check should not pass")
			}
		})
	}
}

// TestVerify_Contained_FlagStripAttempt_FailsClosed proves an attacker cannot
// drop the containment requirement by editing the signed manifest's Contained
// flag: the edit breaks the manifest signature, so verification fails at step 1.
func TestVerify_Contained_FlagStripAttempt_FailsClosed(t *testing.T) {
	t.Parallel()
	dir, orchPubHex, _ := buildRunDir(t, true)

	// Try to flip Contained:true -> false in the manifest JSON (and delete the
	// witness as an attacker would when trying to skip the containment checks).
	mp := filepath.Clean(filepath.Join(dir, "launch-manifest.json"))
	data, err := os.ReadFile(mp)
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unmarshal manifest: %v", err)
	}
	raw["contained"] = false
	out, err := json.Marshal(raw)
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	if err := os.WriteFile(mp, out, 0o600); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	_ = os.Remove(filepath.Join(dir, hcwFile))

	rep, err := playground.VerifyRun(dir, orchPubHex)
	if err == nil && rep.OK {
		t.Fatal("stripping the signed Contained flag must fail closed")
	}
}
