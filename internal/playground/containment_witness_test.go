// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package playground_test

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/playground"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

const (
	testCtrlTarget = "127.0.0.1:54321"
	testRunNonce   = "run-abc"
	testManHash    = "deadbeef"
)

// blockedDirectProbes returns one blocked probe for every direct-egress target
// in the production suite. The verifier requires the exact suite, not just an
// arbitrary non-empty list of blocked probes.
func blockedDirectProbes() []playground.ProbeResult {
	targets := playground.DirectEgressTargets()
	probes := make([]playground.ProbeResult, 0, len(targets))
	for _, target := range targets {
		probes = append(probes, playground.ProbeResult{
			Target:  target,
			Open:    false,
			Blocked: true,
			Detail:  "blocked",
		})
	}
	return probes
}

// validWitness returns a fully-enforced, unsigned witness for the happy path.
func validWitness() playground.HostContainmentWitness {
	return playground.HostContainmentWitness{
		RunNonce:             testRunNonce,
		LaunchManifestHash:   testManHash,
		AgentUser:            "pipelock-agent",
		AgentUID:             966,
		ControlTarget:        testCtrlTarget,
		ControlOperatorProbe: playground.ProbeResult{Target: testCtrlTarget, Open: true, Blocked: false, Detail: "connected"},
		ControlAgentProbe:    playground.ProbeResult{Target: testCtrlTarget, Open: false, Blocked: true, Detail: "blocked: timeout"},
		AgentProbes:          blockedDirectProbes(),
		ProbedAt:             time.Unix(1_700_000_000, 0).UTC(),
	}
}

func mustKeys(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	return pub, priv
}

func TestHostContainmentWitness_SignVerifyRoundTrip(t *testing.T) {
	t.Parallel()
	pub, priv := mustKeys(t)

	signed := playground.SignHostContainmentWitness(priv, validWitness())
	if signed.Signature == "" {
		t.Fatal("signature not set after signing")
	}
	if !playground.VerifyHostContainmentWitness(hex.EncodeToString(pub), signed) {
		t.Fatal("valid witness failed verification under its own key")
	}
}

func TestHostContainmentWitness_Verify_FailsClosed(t *testing.T) {
	t.Parallel()
	pub, priv := mustKeys(t)
	otherPub, _ := mustKeys(t)

	tests := []struct {
		name   string
		pubHex string
		mutate func(w playground.HostContainmentWitness) playground.HostContainmentWitness
	}{
		{
			name:   "wrong orchestrator key",
			pubHex: hex.EncodeToString(otherPub),
			mutate: func(w playground.HostContainmentWitness) playground.HostContainmentWitness { return w },
		},
		{
			name:   "malformed key hex",
			pubHex: "not-hex",
			mutate: func(w playground.HostContainmentWitness) playground.HostContainmentWitness { return w },
		},
		{
			name:   "short key",
			pubHex: hex.EncodeToString(pub[:16]),
			mutate: func(w playground.HostContainmentWitness) playground.HostContainmentWitness { return w },
		},
		{
			name:   "tampered field after signing",
			pubHex: hex.EncodeToString(pub),
			mutate: func(w playground.HostContainmentWitness) playground.HostContainmentWitness {
				// Flip an agent probe to Open WITHOUT re-signing: the cached
				// signature no longer matches the canonical bytes.
				w.AgentProbes[0].Open = true
				return w
			},
		},
		{
			name:   "tampered signature bytes",
			pubHex: hex.EncodeToString(pub),
			mutate: func(w playground.HostContainmentWitness) playground.HostContainmentWitness {
				sig, err := hex.DecodeString(w.Signature)
				if err != nil || len(sig) == 0 {
					panic("test signed witness has invalid signature")
				}
				sig[0] ^= 0xff
				w.Signature = hex.EncodeToString(sig)
				return w
			},
		},
		{
			name:   "malformed signature hex",
			pubHex: hex.EncodeToString(pub),
			mutate: func(w playground.HostContainmentWitness) playground.HostContainmentWitness {
				w.Signature = "zz"
				return w
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			// Sign a fresh witness per subtest so parallel mutations never
			// touch a shared slice backing array.
			w := tc.mutate(playground.SignHostContainmentWitness(priv, validWitness()))
			if playground.VerifyHostContainmentWitness(tc.pubHex, w) {
				t.Fatal("expected verification to fail closed, but it passed")
			}
		})
	}
}

// TestHostContainmentWitness_AttackerResign proves an attacker who edits the
// witness and re-signs with THEIR OWN key cannot pass verification under the
// real orchestrator key.
func TestHostContainmentWitness_AttackerResign(t *testing.T) {
	t.Parallel()
	pub, _ := mustKeys(t)
	_, attackerPriv := mustKeys(t)

	forged := validWitness()
	forged.AgentProbes[0].Open = true // pretend a route was open but claim enforced
	forged = playground.SignHostContainmentWitness(attackerPriv, forged)

	if playground.VerifyHostContainmentWitness(hex.EncodeToString(pub), forged) {
		t.Fatal("attacker-resigned witness verified under the real orchestrator key")
	}
}

func TestHostContainmentWitness_BindsRun(t *testing.T) {
	t.Parallel()
	w := validWitness()
	if !playground.HostContainmentBindsRun(w, testRunNonce, testManHash) {
		t.Fatal("witness should bind its own run")
	}
	if playground.HostContainmentBindsRun(w, "other-nonce", testManHash) {
		t.Fatal("witness must not bind a different nonce")
	}
	if playground.HostContainmentBindsRun(w, testRunNonce, "other-hash") {
		t.Fatal("witness must not bind a different manifest hash")
	}
}

func TestHostContainmentWitness_Enforced(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		mutate func(w playground.HostContainmentWitness) playground.HostContainmentWitness
		want   bool
	}{
		{
			name:   "valid differential + all blocked",
			mutate: func(w playground.HostContainmentWitness) playground.HostContainmentWitness { return w },
			want:   true,
		},
		{
			name: "leak: a real agent probe is open",
			mutate: func(w playground.HostContainmentWitness) playground.HostContainmentWitness {
				w.AgentProbes[1].Open = true
				return w
			},
			want: false,
		},
		{
			name: "control agent probe open (no block)",
			mutate: func(w playground.HostContainmentWitness) playground.HostContainmentWitness {
				w.ControlAgentProbe.Open = true
				w.ControlAgentProbe.Blocked = false
				return w
			},
			want: false,
		},
		{
			name: "control agent probe refused is reachable not blocked",
			mutate: func(w playground.HostContainmentWitness) playground.HostContainmentWitness {
				w.ControlAgentProbe.Open = false
				w.ControlAgentProbe.Blocked = false
				w.ControlAgentProbe.Detail = "reachable: connection refused"
				return w
			},
			want: false,
		},
		{
			name: "control operator probe blocked (broken probe / unreachable control)",
			mutate: func(w playground.HostContainmentWitness) playground.HostContainmentWitness {
				w.ControlOperatorProbe.Open = false
				w.ControlOperatorProbe.Blocked = true
				return w
			},
			want: false,
		},
		{
			name: "empty control target",
			mutate: func(w playground.HostContainmentWitness) playground.HostContainmentWitness {
				w.ControlTarget = ""
				return w
			},
			want: false,
		},
		{
			name: "control probe target mismatch",
			mutate: func(w playground.HostContainmentWitness) playground.HostContainmentWitness {
				w.ControlAgentProbe.Target = "127.0.0.1:9999"
				return w
			},
			want: false,
		},
		{
			name: "empty agent probe suite cannot pass vacuously",
			mutate: func(w playground.HostContainmentWitness) playground.HostContainmentWitness {
				w.AgentProbes = nil
				return w
			},
			want: false,
		},
		{
			name: "missing direct-egress suite target",
			mutate: func(w playground.HostContainmentWitness) playground.HostContainmentWitness {
				w.AgentProbes = w.AgentProbes[:len(w.AgentProbes)-1]
				return w
			},
			want: false,
		},
		{
			name: "substituted direct-egress suite target",
			mutate: func(w playground.HostContainmentWitness) playground.HostContainmentWitness {
				w.AgentProbes[0].Target = "127.0.0.1:1"
				return w
			},
			want: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := tc.mutate(validWitness()).Enforced(); got != tc.want {
				t.Fatalf("Enforced()=%v want %v", got, tc.want)
			}
		})
	}
}

// TestHostContainmentWitness_SignedBytesDeterministic guards the no-maps
// determinism invariant: two marshals of the same witness are byte-identical.
func TestHostContainmentWitness_SignedBytesDeterministic(t *testing.T) {
	t.Parallel()
	w := validWitness()
	a := w.SignedBytes()
	b := w.SignedBytes()
	if string(a) != string(b) {
		t.Fatal("SignedBytes not deterministic")
	}
	// Signature field must be excluded from signed bytes.
	w.Signature = "abcd"
	if string(w.SignedBytes()) != string(a) {
		t.Fatal("SignedBytes must exclude the Signature field")
	}
	// Sanity: it is valid JSON.
	var probe map[string]any
	if err := json.Unmarshal(a, &probe); err != nil {
		t.Fatalf("SignedBytes is not valid JSON: %v", err)
	}
}
