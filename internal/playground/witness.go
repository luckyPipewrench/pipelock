// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package playground

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"
)

// Errors returned by the collector seal protocol.
var (
	// ErrNoDrainWindow is returned when SealAndSign is called with a
	// non-positive drain window. A final witness MUST NOT be signed without a
	// real drain wait, because "0 observed" cannot be honestly attested while a
	// delayed in-flight request could still land. This is the
	// cannot-seal-while-accepting guarantee.
	ErrNoDrainWindow = errors.New("playground: cannot seal witness without a positive drain window")

	// ErrRunNotOpen is returned when SealAndSign targets a run nonce that was
	// never opened with OpenRun.
	ErrRunNotOpen = errors.New("playground: run was never opened")

	// ErrDrainIncomplete is returned when SealAndSign's drain deadline expires
	// before all in-flight requests have completed. The timeout branch REFUSES
	// to seal (fail-closed): signing a witness while a request is still in
	// progress could produce "0 observed" when the real count is 1.
	ErrDrainIncomplete = errors.New("playground: drain deadline expired with in-flight requests still active")

	// ErrRunSealed is returned when OpenRun is called on a nonce that has
	// already been sealed. Sealing is terminal for a nonce: the witness bound
	// it to a specific manifest hash, so re-opening would mix observations
	// across different launch manifests. Use a fresh nonce per run.
	ErrRunSealed = errors.New("playground: run already sealed, use a fresh nonce")
)

// canonicalLaunchManifestBytes marshals a manifest deterministically with the
// Signature field cleared, producing stable bytes to sign and verify.
func canonicalLaunchManifestBytes(lm LaunchManifest) []byte {
	lm.Signature = ""
	// Go's encoding/json emits struct fields in declaration order, so this is
	// deterministic without an explicit sort.
	b, _ := json.Marshal(lm)
	return b
}

// SignLaunchManifest signs lm with priv over its canonical (signature-excluded)
// bytes and returns a copy with the hex-encoded Signature set. This is the
// orchestrator-side, pre-run signing step that pins the whole run.
func SignLaunchManifest(priv ed25519.PrivateKey, lm LaunchManifest) LaunchManifest {
	sig := ed25519.Sign(priv, canonicalLaunchManifestBytes(lm))
	lm.Signature = hex.EncodeToString(sig)
	return lm
}

// VerifyLaunchManifest reports whether lm carries a valid signature under pub.
func VerifyLaunchManifest(pub ed25519.PublicKey, lm LaunchManifest) bool {
	if len(pub) != ed25519.PublicKeySize {
		return false
	}
	sig, err := hex.DecodeString(lm.Signature)
	if err != nil {
		return false
	}
	return ed25519.Verify(pub, canonicalLaunchManifestBytes(lm), sig)
}

// Hash returns the sha256 hex digest over the canonical JSON of the manifest
// INCLUDING its signature. The signed artifact (signature and all) is what gets
// pinned into the witness, so a witness can only bind to the exact manifest that
// was launched.
func (lm LaunchManifest) Hash() string {
	b, _ := json.Marshal(lm)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// RedCaseResult is a forward-declared stub for Task 3's red-case proof. The
// collector going "red" (observing the canary) under a deliberately-misconfigured
// or attacker control run proves the witness is not a rubber stamp. Task 3 fills
// in the production use; Task 2 only carries it through the Witness.
type RedCaseResult struct {
	WitnessWentRed bool      `json:"witness_went_red"`
	ObservedCount  int       `json:"observed_count"`
	At             time.Time `json:"at"`
}

// Witness is the collector's signed, drain-sealed attestation for one run. It is
// honestly framed as target-side lab instrumentation: it proves what THIS
// collector observed for a specific, orchestrator-pinned run, not independent
// third-party evidence.
//
// It is intrinsically bound to (RunNonce, LaunchManifestHash) so it cannot be
// replayed against a different run, and it is only sealed after the collector
// stops accepting traffic for the run AND in-flight requests drain.
//
// INVARIANT: no map-typed fields. SignedBytes determinism depends on
// struct-declaration-order JSON marshaling, which is only stable for structs.
type Witness struct {
	RunNonce         string `json:"run_nonce"`
	CanaryID         string `json:"canary_id"`
	ObservedCount    int    `json:"observed_count"`
	TotalCount       int    `json:"total_count"`
	RequestLogDigest string `json:"request_log_digest"`

	RunClosedAt   time.Time `json:"run_closed_at"`
	DrainDeadline time.Time `json:"drain_deadline"`

	LaunchManifestHash string `json:"launch_manifest_hash"`

	RedCaseResult *RedCaseResult `json:"red_case_result,omitempty"`

	Signature string `json:"signature,omitempty"`
}

// SignedBytes returns the canonical JSON of the witness with the Signature field
// cleared. These are the exact bytes the collector signs and a verifier checks.
// It excludes Signature and is deterministic (struct declaration order).
func (w Witness) SignedBytes() []byte {
	w.Signature = ""
	b, _ := json.Marshal(w)
	return b
}

// WitnessBindsRun reports whether w is intrinsically bound to the given run
// nonce and launch-manifest hash. A witness from one run does NOT satisfy this
// for another run, which is what makes the witness non-replayable. The Task 4
// verify command uses this after checking the signature.
func WitnessBindsRun(w Witness, nonce, manifestHash string) bool {
	return w.RunNonce == nonce && w.LaunchManifestHash == manifestHash
}
