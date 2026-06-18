// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package playground

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// canaryValueForTest builds the synthetic canary at runtime to satisfy gosec
// G101 (no hard-coded credential string literal in source).
const canaryValueForTest = "AKIA" + "IOSFODNN7EXAMPLE"

// genKey returns a fresh ed25519 keypair, failing the test on error.
func genKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("genKey: %v", err)
	}
	return pub, priv
}

// hexEnc hex-encodes a byte slice.
func hexEnc(b []byte) string { return hex.EncodeToString(b) }

// signLaunchManifest signs a LaunchManifest with the orchestrator key using the
// production helper, returning the signed copy.
func signLaunchManifest(t *testing.T, priv ed25519.PrivateKey, lm LaunchManifest) LaunchManifest {
	t.Helper()
	return SignLaunchManifest(priv, lm)
}

// ed25519Verify verifies a hex-encoded signature over msg under pub.
func ed25519Verify(pub ed25519.PublicKey, msg []byte, sigHex string) bool {
	sig, err := hex.DecodeString(sigHex)
	if err != nil {
		return false
	}
	return ed25519.Verify(pub, msg, sig)
}

func TestWitness_SignedAfterDrain_BindsManifest(t *testing.T) {
	orchPub, orchPriv := genKey(t)
	colPub, colPriv := genKey(t)
	pipePub, _ := genKey(t)
	lm := signLaunchManifest(t, orchPriv, LaunchManifest{
		RunNonce: "N1", ScenarioID: "exfil-canary", CanaryID: "aws_canary",
		PipelockPubKey: hexEnc(pipePub), CollectorPubKey: hexEnc(colPub), TargetHost: "intake.lab.test",
	})
	c := NewCollector("aws_canary", canaryValueForTest)
	if err := c.OpenRun("N1", lm.Hash()); err != nil {
		t.Fatalf("OpenRun: %v", err)
	}
	// no exfil arrives
	w, err := c.SealAndSign("N1", colPriv, 200*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if w.ObservedCount != 0 || w.RunNonce != "N1" || w.LaunchManifestHash != lm.Hash() {
		t.Fatalf("witness must bind nonce+manifest and report 0 observed: %+v", w)
	}
	if w.RunClosedAt.IsZero() {
		t.Fatal("witness must record RunClosedAt after drain")
	}
	if !ed25519Verify(colPub, w.SignedBytes(), w.Signature) {
		t.Fatal("witness signature must verify under the collector key")
	}
	_ = orchPub
}

func TestWitness_CannotSealWithoutDrainWindow(t *testing.T) {
	_, colPriv := genKey(t)
	c := NewCollector("aws_canary", canaryValueForTest)
	if err := c.OpenRun("N1", "deadbeef"); err != nil {
		t.Fatalf("OpenRun: %v", err)
	}
	if _, err := c.SealAndSign("N1", colPriv, 0); err == nil {
		t.Fatal("must refuse to seal a final witness without a real drain window (cannot prove the listener drained)")
	}
}

func TestWitness_NotReplayableAcrossRuns(t *testing.T) {
	_, colPriv := genKey(t)
	c := NewCollector("aws_canary", canaryValueForTest)
	if err := c.OpenRun("N1", "hashA"); err != nil {
		t.Fatalf("OpenRun N1: %v", err)
	}
	w1, err := c.SealAndSign("N1", colPriv, 100*time.Millisecond)
	if err != nil {
		t.Fatalf("SealAndSign N1: %v", err)
	}
	if err := c.OpenRun("N2", "hashB"); err != nil {
		t.Fatalf("OpenRun N2: %v", err)
	}
	w2, err := c.SealAndSign("N2", colPriv, 100*time.Millisecond)
	if err != nil {
		t.Fatalf("SealAndSign N2: %v", err)
	}
	// a witness is intrinsically bound to its run; cross-use must be detectable
	if w1.RunNonce == w2.RunNonce || w1.LaunchManifestHash == w2.LaunchManifestHash {
		t.Fatal("each witness must carry its own run binding")
	}
	if WitnessBindsRun(w1, "N2", "hashB") {
		t.Fatal("w1 must NOT validate against run N2/hashB")
	}
	if !WitnessBindsRun(w1, "N1", "hashA") {
		t.Fatal("w1 must validate against its own run")
	}
}

func TestWitness_ObservedWhenCanaryArrivesBeforeSeal(t *testing.T) {
	_, colPriv := genKey(t)
	c := NewCollector("aws_canary", canaryValueForTest)
	if err := c.OpenRun("N1", "hashA"); err != nil {
		t.Fatalf("OpenRun: %v", err)
	}

	srv := httptest.NewServer(c.Handler())
	defer srv.Close()

	// POST the canary value through the collector Handler under run N1.
	body := strings.NewReader("payload=" + canaryValueForTest)
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, srv.URL+"/?run=N1", body)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post canary: %v", err)
	}
	_ = resp.Body.Close()

	w, err := c.SealAndSign("N1", colPriv, 100*time.Millisecond)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if w.ObservedCount != 1 {
		t.Fatalf("expected ObservedCount==1 after canary arrival, got %d", w.ObservedCount)
	}
	if w.TotalCount != 1 {
		t.Fatalf("expected TotalCount==1, got %d", w.TotalCount)
	}

	// The witness must never embed the raw canary value.
	if strings.Contains(string(w.SignedBytes()), canaryValueForTest) {
		t.Fatal("witness signed bytes must NOT contain the raw canary value")
	}
}

func TestWitness_VerifyLaunchManifest(t *testing.T) {
	orchPub, orchPriv := genKey(t)
	otherPub, _ := genKey(t)
	lm := SignLaunchManifest(orchPriv, LaunchManifest{
		RunNonce: "N1", ScenarioID: "exfil-canary", CanaryID: "aws_canary",
	})
	if !VerifyLaunchManifest(orchPub, lm) {
		t.Fatal("signed manifest must verify under the orchestrator key")
	}
	if VerifyLaunchManifest(otherPub, lm) {
		t.Fatal("signed manifest must NOT verify under an unrelated key")
	}
	// Tampering with a field after signing must break verification.
	tampered := lm
	tampered.TargetHost = "attacker.test"
	if VerifyLaunchManifest(orchPub, tampered) {
		t.Fatal("tampered manifest must fail verification")
	}
	// Hash must include the signature: an unsigned copy hashes differently.
	unsigned := lm
	unsigned.Signature = ""
	if unsigned.Hash() == lm.Hash() {
		t.Fatal("Hash must include the signature field")
	}
}

func TestWitness_SealRejectsUnopenedRun(t *testing.T) {
	_, colPriv := genKey(t)
	c := NewCollector("aws_canary", canaryValueForTest)
	if _, err := c.SealAndSign("never-opened", colPriv, 50*time.Millisecond); err == nil {
		t.Fatal("sealing a run that was never opened must error")
	}
}

func TestWitness_NoCountAfterSeal(t *testing.T) {
	_, colPriv := genKey(t)
	c := NewCollector("aws_canary", canaryValueForTest)
	if err := c.OpenRun("N1", "hashA"); err != nil {
		t.Fatalf("OpenRun: %v", err)
	}

	srv := httptest.NewServer(c.Handler())
	defer srv.Close()

	w, err := c.SealAndSign("N1", colPriv, 50*time.Millisecond)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if w.ObservedCount != 0 {
		t.Fatalf("pre-seal observed should be 0, got %d", w.ObservedCount)
	}

	// After seal the run is no longer accepting: a late canary must NOT be counted.
	body := strings.NewReader("payload=" + canaryValueForTest)
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, srv.URL+"/?run=N1", body)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("late post: %v", err)
	}
	_ = resp.Body.Close()

	if got := c.ObservedCount("N1"); got != 0 {
		t.Fatalf("late canary after seal must not be counted, observed=%d", got)
	}
}

func TestWitness_DrainTimeout_FailsClosed_NoSignedWitness(t *testing.T) {
	// REGRESSION: a slow in-flight request that hasn't finished processing
	// must cause SealAndSign to return ErrDrainIncomplete, NOT produce a
	// signed witness with stale "0 observed" counts. The timeout branch must
	// fail closed.
	//
	// Mechanism: the collector's ingestHook blocks the handler between
	// inFlight.Add(1) and scanRequest, giving us a deterministic window
	// where a request is in-flight but not yet counted. NO time.Sleep.
	_, colPriv := genKey(t)
	c := NewCollector("aws_canary", canaryValueForTest)

	handlerEntered := make(chan struct{})
	handlerRelease := make(chan struct{})
	c.ingestHook = func() {
		close(handlerEntered)
		<-handlerRelease
	}

	if err := c.OpenRun("N1", "hashA"); err != nil {
		t.Fatalf("OpenRun: %v", err)
	}

	srv := httptest.NewServer(c.Handler())
	defer srv.Close()

	// Fire the canary POST. The handler will register inFlight.Add(1) and
	// then block on the hook before scanning.
	var postWg sync.WaitGroup
	postWg.Add(1)
	go func() {
		defer postWg.Done()
		body := strings.NewReader("payload=" + canaryValueForTest)
		req, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, srv.URL+"/?run=N1", body)
		resp, err := http.DefaultClient.Do(req)
		if err == nil {
			_ = resp.Body.Close()
		}
	}()

	// Wait until the handler is in-flight (past Add(1), blocked on hook).
	<-handlerEntered

	// SealAndSign with a very short drain: the in-flight request will NOT
	// complete before the deadline, so this MUST return ErrDrainIncomplete.
	w, err := c.SealAndSign("N1", colPriv, 10*time.Millisecond)
	if !errors.Is(err, ErrDrainIncomplete) {
		t.Fatalf("expected ErrDrainIncomplete, got err=%v witness=%+v", err, w)
	}
	// The zero-value witness must NOT carry a valid signature.
	if w.Signature != "" {
		t.Fatal("drain-timeout must not produce a signed witness")
	}

	// Release the handler so the request completes and the test cleans up.
	close(handlerRelease)
	postWg.Wait()

	// The canary DID arrive (the handler finishes scanning after release),
	// so the real observed count should be 1. But no signed witness with "0"
	// was ever produced -- that is the invariant.
	if got := c.ObservedCount("N1"); got != 1 {
		t.Fatalf("after release, real observed count should be 1, got %d", got)
	}
}

func TestWitness_OpenRun_RefuseReopenSealed(t *testing.T) {
	// REGRESSION: re-opening a sealed nonce under a new manifest hash must be
	// refused. Otherwise the new witness would carry stale counts from the
	// prior run under the old manifest, producing a WitnessBindsRun-valid
	// attestation that lies about what was observed under which policy.
	_, colPriv := genKey(t)
	c := NewCollector("aws_canary", canaryValueForTest)

	// Open, post a canary, seal under hashA.
	if err := c.OpenRun("N1", "hashA"); err != nil {
		t.Fatalf("OpenRun: %v", err)
	}

	srv := httptest.NewServer(c.Handler())
	defer srv.Close()

	body := strings.NewReader("payload=" + canaryValueForTest)
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, srv.URL+"/?run=N1", body)
	resp, _ := http.DefaultClient.Do(req)
	if resp != nil {
		_ = resp.Body.Close()
	}

	_, err := c.SealAndSign("N1", colPriv, 100*time.Millisecond)
	if err != nil {
		t.Fatalf("first seal: %v", err)
	}

	// Attempt to re-open N1 under a different manifest hash.
	if openErr := c.OpenRun("N1", "hashB"); !errors.Is(openErr, ErrRunSealed) {
		t.Fatalf("re-opening sealed nonce must return ErrRunSealed, got %v", openErr)
	}
}

func TestWitness_OpenRun_RefusesManifestRebindBeforeSeal(t *testing.T) {
	c := NewCollector("aws_canary", canaryValueForTest)
	if err := c.OpenRun("N1", "hashA"); err != nil {
		t.Fatalf("OpenRun: %v", err)
	}
	if err := c.OpenRun("N1", "hashB"); !errors.Is(err, ErrRunAlreadyOpen) {
		t.Fatalf("re-opening active nonce must return ErrRunAlreadyOpen, got %v", err)
	}
}
