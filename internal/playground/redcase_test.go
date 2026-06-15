// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package playground

import (
	"errors"
	"testing"
	"time"
)

func TestRedCase_WitnessGoesRed_OnLeak(t *testing.T) {
	colPub, colPriv := genKey(t)
	res, err := RunRedCaseCalibration(t.Context(), colPriv, "aws_canary", "AKIA"+"IOSFODNN7EXAMPLE")
	if err != nil {
		t.Fatalf("calibration must succeed: %v", err)
	}
	if !res.WitnessWentRed || res.ObservedCount < 1 {
		t.Fatalf("red-case must observe the canary: %+v", res)
	}
	if res.CollectorPubKey != hexEnc(colPub) {
		t.Fatal("must bind the collector pubkey")
	}
	if res.RedWitnessDigest == "" {
		t.Fatal("must carry the red-witness digest")
	}
}

func TestRedCase_FailsIfCollectorDoesNotDetect(t *testing.T) {
	// A deliberately-broken collector (wrong canary value) must make
	// calibration ERROR (observed stays 0). Proves fail-closed.
	_, colPriv := genKey(t)
	_, err := RunRedCaseCalibrationWithValue(t.Context(), colPriv, "aws_canary", "AKIA"+"IOSFODNN7EXAMPLE", "WRONG-VALUE-NEVER-SENT")
	if err == nil {
		t.Fatal("calibration MUST fail closed when the collector does not detect the planted canary")
	}
	if !errors.Is(err, ErrRedCaseNotDetected) {
		t.Fatalf("expected ErrRedCaseNotDetected, got: %v", err)
	}
}

func TestGreenWitness_CarriesSignedRedCase(t *testing.T) {
	colPub, colPriv := genKey(t)

	// Run the red-case calibration.
	rc, err := RunRedCaseCalibration(t.Context(), colPriv, "aws_canary", "AKIA"+"IOSFODNN7EXAMPLE")
	if err != nil {
		t.Fatal(err)
	}

	// Open a fresh green run, attach the red-case, seal.
	c := NewCollector("aws_canary", "AKIA"+"IOSFODNN7EXAMPLE")
	if err := c.OpenRun("N1", "hashA"); err != nil {
		t.Fatal(err)
	}
	if err := c.AttachRedCase("N1", rc); err != nil {
		t.Fatal(err)
	}
	w, err := c.SealAndSign("N1", colPriv, 200*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if w.RedCaseResult == nil || !w.RedCaseResult.WitnessWentRed {
		t.Fatal("green witness must carry the red-case")
	}
	if !ed25519Verify(colPub, w.SignedBytes(), w.Signature) {
		t.Fatal("witness sig must still verify (red-case is signed in)")
	}
}

func TestAttachRedCase_RejectsUnopenedRun(t *testing.T) {
	c := NewCollector("aws_canary", canaryValueForTest)
	rc := RedCaseResult{WitnessWentRed: true, ObservedCount: 1}
	if err := c.AttachRedCase("never-opened", rc); !errors.Is(err, ErrRedCaseRunNotOpen) {
		t.Fatalf("expected ErrRedCaseRunNotOpen, got: %v", err)
	}
}

func TestAttachRedCase_RejectsSealedRun(t *testing.T) {
	_, colPriv := genKey(t)
	c := NewCollector("aws_canary", canaryValueForTest)
	if err := c.OpenRun("N1", "hashA"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.SealAndSign("N1", colPriv, 50*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	rc := RedCaseResult{WitnessWentRed: true, ObservedCount: 1}
	if err := c.AttachRedCase("N1", rc); !errors.Is(err, ErrRedCaseRunNotOpen) {
		t.Fatalf("expected ErrRedCaseRunNotOpen on sealed run, got: %v", err)
	}
}
