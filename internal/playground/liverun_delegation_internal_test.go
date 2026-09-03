// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package playground

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/signing"
)

// testRunRoot generates a root and makes it the trusted delegation root for
// the duration of the test. Production always trusts the compiled published
// identity; this only lets the tests mint delegations that verify.
func testRunRoot(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	pub, priv, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	prev := trustedDelegationRoot
	trustedDelegationRoot = func() (ed25519.PublicKey, error) { return pub, nil }
	t.Cleanup(func() { trustedDelegationRoot = prev })
	return priv
}

const testRunImageDigest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"

// A delegated run signs with the broker-minted session key, and the launch
// manifest records which delegation authorized it and which image it ran on.
// Without that binding a captured run could be replayed as though it came from
// a different image.
func TestStartLiveRun_DelegatedSessionBindsManifest(t *testing.T) {
	root := testRunRoot(t)
	const nonce = "delegated-run-nonce"

	minted, err := MintSessionDelegation(root, nonce, testRunImageDigest, time.Now().UTC(), 0)
	if err != nil {
		t.Fatalf("MintSessionDelegation: %v", err)
	}

	lr, err := StartLiveRun(t.Context(), LiveRunOpts{
		ScenarioID:        LiveDemoScenarioID,
		RunNonce:          nonce,
		SessionPrivateKey: minted.PrivateKey,
		Delegation:        &minted.Delegation,
	})
	if err != nil {
		t.Fatalf("StartLiveRun: %v", err)
	}
	defer lr.Close()

	if hex.EncodeToString(lr.orchestratorPriv) != hex.EncodeToString(minted.PrivateKey) {
		t.Fatal("the run must sign with the broker-minted session key")
	}
	if hex.EncodeToString(lr.orchestratorPriv) == hex.EncodeToString(root) {
		t.Fatal("the run must never sign with the durable root")
	}
	if lr.manifest.DelegationID != minted.Delegation.DelegationID {
		t.Fatalf("manifest delegation id = %q, want %q", lr.manifest.DelegationID, minted.Delegation.DelegationID)
	}
	if lr.manifest.ImageDigest != testRunImageDigest {
		t.Fatalf("manifest image digest = %q, want %q", lr.manifest.ImageDigest, testRunImageDigest)
	}
}

// The delegation travels with the run directory, so an offline verifier can
// walk session key back to the published root without contacting anything.
func TestLiveRun_DelegatedRunWritesDelegationArtifact(t *testing.T) {
	root := testRunRoot(t)
	const nonce = "delegated-artifact-nonce"

	minted, err := MintSessionDelegation(root, nonce, testRunImageDigest, time.Now().UTC(), 0)
	if err != nil {
		t.Fatalf("MintSessionDelegation: %v", err)
	}

	lr, err := StartLiveRun(t.Context(), LiveRunOpts{
		ScenarioID:        LiveDemoScenarioID,
		RunNonce:          nonce,
		SessionPrivateKey: minted.PrivateKey,
		Delegation:        &minted.Delegation,
	})
	if err != nil {
		t.Fatalf("StartLiveRun: %v", err)
	}
	defer lr.Close()

	// This run executes no steps, so the verify report itself does not pass;
	// a fully-verifying delegated run is covered by the end-to-end live test.
	// What matters here is that assembly writes the delegation alongside the
	// manifest, because that file is what an offline verifier reads.
	runDir := t.TempDir()
	_, _ = lr.AssembleAndVerify(runDir)

	raw, err := os.ReadFile(filepath.Clean(filepath.Join(runDir, orchestratorDelegationFile)))
	if err != nil {
		t.Fatalf("delegation artifact missing: %v", err)
	}
	var got OrchestratorDelegation
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("delegation artifact does not parse: %v", err)
	}
	if got.DelegationID != minted.Delegation.DelegationID {
		t.Fatalf("written delegation id = %q, want %q", got.DelegationID, minted.Delegation.DelegationID)
	}
	if got.SessionPublicKey != minted.Delegation.SessionPublicKey {
		t.Fatal("written delegation does not authorize the key the run signed with")
	}
}

// A session key without its delegation, or one the delegation does not name,
// must refuse to start. Either would produce a run nothing can trace to the
// published root.
func TestStartLiveRun_RefusesUnauthorizedSessionKey(t *testing.T) {
	root := testRunRoot(t)
	const nonce = "refusal-nonce"

	minted, err := MintSessionDelegation(root, nonce, testRunImageDigest, time.Now().UTC(), 0)
	if err != nil {
		t.Fatalf("MintSessionDelegation: %v", err)
	}
	other, err := MintSessionDelegation(root, nonce, testRunImageDigest, time.Now().UTC(), 0)
	if err != nil {
		t.Fatalf("MintSessionDelegation: %v", err)
	}

	for _, tc := range []struct {
		name string
		opts LiveRunOpts
		want string
	}{
		{
			name: "key_without_delegation",
			opts: LiveRunOpts{SessionPrivateKey: minted.PrivateKey},
			want: "requires a root-signed delegation",
		},
		{
			name: "key_not_named_by_delegation",
			opts: LiveRunOpts{SessionPrivateKey: minted.PrivateKey, Delegation: &other.Delegation},
			want: "does not authorize this session signing key",
		},
		{
			name: "malformed_key",
			opts: LiveRunOpts{SessionPrivateKey: ed25519.PrivateKey("short"), Delegation: &minted.Delegation},
			want: "session signing key",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts := tc.opts
			opts.ScenarioID = LiveDemoScenarioID
			opts.RunNonce = nonce
			lr, err := StartLiveRun(t.Context(), opts)
			if err == nil {
				lr.Close()
				t.Fatal("an unauthorized session key must be refused")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want it to mention %q", err, tc.want)
			}
		})
	}
}

// A delegation signed by a root the deployment does not trust must be refused
// even when it is internally consistent. Without this an invite-code holder
// could sign its own delegation and start an authorized-looking session.
func TestStartLiveRun_RefusesUntrustedRoot(t *testing.T) {
	trusted := testRunRoot(t)
	_ = trusted

	_, foreign, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	const nonce = "foreign-root-nonce"
	minted, err := MintSessionDelegation(foreign, nonce, testRunImageDigest, time.Now().UTC(), 0)
	if err != nil {
		t.Fatalf("MintSessionDelegation: %v", err)
	}

	lr, err := StartLiveRun(t.Context(), LiveRunOpts{
		ScenarioID:        LiveDemoScenarioID,
		RunNonce:          nonce,
		SessionPrivateKey: minted.PrivateKey,
		Delegation:        &minted.Delegation,
	})
	if err == nil {
		lr.Close()
		t.Fatal("a delegation from an untrusted root must be refused")
	}
	if !strings.Contains(err.Error(), "root") {
		t.Fatalf("error = %v, want it to name the root mismatch", err)
	}
}

// A run nonce that the delegation does not name must be refused, and an absent
// nonce must be refused rather than silently skipping the binding.
func TestStartLiveRun_RequiresBoundRunNonce(t *testing.T) {
	root := testRunRoot(t)
	minted, err := MintSessionDelegation(root, "authorized-run", testRunImageDigest, time.Now().UTC(), 0)
	if err != nil {
		t.Fatalf("MintSessionDelegation: %v", err)
	}

	for _, tc := range []struct {
		name  string
		nonce string
	}{
		{name: "different_run", nonce: "some-other-run"},
		{name: "absent_run_nonce", nonce: ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lr, err := StartLiveRun(t.Context(), LiveRunOpts{
				ScenarioID:        LiveDemoScenarioID,
				RunNonce:          tc.nonce,
				SessionPrivateKey: minted.PrivateKey,
				Delegation:        &minted.Delegation,
			})
			if err == nil {
				lr.Close()
				t.Fatal("a delegation not bound to this run must be refused")
			}
		})
	}
}

// A zero lifetime takes the default window rather than minting a delegation
// that is already expired.
func TestMintSessionDelegation_ZeroLifetimeUsesDefault(t *testing.T) {
	root := testRunRoot(t)
	minted, err := MintSessionDelegation(root, "n", testRunImageDigest, time.Now().UTC(), 0)
	if err != nil {
		t.Fatalf("MintSessionDelegation: %v", err)
	}
	window := minted.Delegation.ExpiresAtUnix - minted.Delegation.NotBeforeUnix
	if want := int64(DefaultSessionDelegationLifetime / time.Second); window != want {
		t.Fatalf("delegation window = %ds, want %ds", window, want)
	}
}

// A sub-second lifetime truncates to a zero-length window in a second-precision
// format, so it is refused rather than minted already-expired.
func TestMintSessionDelegation_RejectsSubSecondLifetime(t *testing.T) {
	root := testRunRoot(t)
	if _, err := MintSessionDelegation(root, "n", testRunImageDigest, time.Now().UTC(), 500*time.Millisecond); err == nil {
		t.Fatal("a sub-second delegation lifetime must be refused")
	}
}

// The hex parser fails closed on every malformed shape rather than handing back
// a key that cannot produce verifiable signatures.
func TestParseOrchestratorPrivateKeyHex_RejectsMalformedShapes(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   string
	}{
		{name: "not_hex", in: "zz"},
		{name: "wrong_size", in: hex.EncodeToString([]byte("short"))},
		{name: "seed_public_mismatch", in: strings.Repeat("ab", ed25519.PrivateKeySize)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseOrchestratorPrivateKeyHex(tc.in); err == nil {
				t.Fatalf("%q must be refused", tc.name)
			}
		})
	}
}
