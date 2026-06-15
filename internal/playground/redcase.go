// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package playground

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"
)

// calibrationNoncePrefix is the run-nonce prefix used for red-case calibration
// runs. It is distinct from production run nonces to avoid collisions.
const calibrationNoncePrefix = "redcase-calib-"

// RunRedCaseCalibration performs a red-case calibration: it stands up a fresh
// collector, POSTs the canary value DIRECTLY (no proxy -- this is the
// "Pipelock OFF" leak), seals a witness, and confirms the collector went red.
//
// If the collector does NOT observe the canary (observed == 0), the function
// returns ErrRedCaseNotDetected. This is the fail-closed guarantee: a broken
// collector build cannot produce a green-looking RedCaseResult.
//
// The returned RedCaseResult carries the collector's public key and the sha256
// digest of the signed red witness's SignedBytes(), so the offline verifier
// can confirm a real signed witness existed and was produced by the same
// collector key as the green witness.
func RunRedCaseCalibration(ctx context.Context, colPriv ed25519.PrivateKey, canaryID, canaryValue string) (RedCaseResult, error) {
	res, _, err := runRedCaseCalibrationCore(ctx, colPriv, canaryID, canaryValue, canaryValue)
	return res, err
}

// RunRedCaseCalibrationWithWitness is the artifact-producing form used by live
// runs. It returns both the signed summary embedded in the green witness and the
// signed red witness artifact the offline verifier can independently check.
func RunRedCaseCalibrationWithWitness(ctx context.Context, colPriv ed25519.PrivateKey, canaryID, canaryValue string) (RedCaseResult, Witness, error) {
	return runRedCaseCalibrationCore(ctx, colPriv, canaryID, canaryValue, canaryValue)
}

// RunRedCaseCalibrationWithValue is the same as RunRedCaseCalibration but lets
// the caller specify a different value to POST vs what the collector scans for.
// This is used in tests to prove fail-closed: when the posted value does not
// match the collector's canary, observed stays 0 and the function returns
// ErrRedCaseNotDetected.
func RunRedCaseCalibrationWithValue(ctx context.Context, colPriv ed25519.PrivateKey, canaryID, collectorExpectsValue, actuallySentValue string) (RedCaseResult, error) {
	res, _, err := runRedCaseCalibrationCore(ctx, colPriv, canaryID, collectorExpectsValue, actuallySentValue)
	return res, err
}

// runRedCaseCalibrationCore is the shared implementation for both public
// calibration functions. collectorCanary is what the collector scans for;
// sentValue is what gets POSTed.
func runRedCaseCalibrationCore(ctx context.Context, colPriv ed25519.PrivateKey, canaryID, collectorCanary, sentValue string) (RedCaseResult, Witness, error) {
	calibNonce := calibrationNoncePrefix + canaryID

	// Stand up a fresh collector scanning for collectorCanary.
	c := NewCollector(canaryID, collectorCanary)
	if err := c.OpenRun(calibNonce, "redcase"); err != nil {
		return RedCaseResult{}, Witness{}, fmt.Errorf("red-case calibration: open run: %w", err)
	}

	// Spin up an httptest server so we can POST through the real Handler.
	srv := httptest.NewServer(c.Handler())
	defer srv.Close()

	// POST the canary value DIRECTLY to the collector (no proxy -- this is
	// the deliberate "Pipelock OFF" leak that makes the witness go red).
	body := strings.NewReader("payload=" + sentValue)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, srv.URL+"/?run="+calibNonce, body)
	if err != nil {
		return RedCaseResult{}, Witness{}, fmt.Errorf("red-case calibration: build request: %w", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return RedCaseResult{}, Witness{}, fmt.Errorf("red-case calibration: POST canary: %w", err)
	}
	_ = resp.Body.Close()

	// Seal the witness with a real drain window.
	const drainWindow = 200 * time.Millisecond
	witness, err := c.SealAndSign(calibNonce, colPriv, drainWindow)
	if err != nil {
		return RedCaseResult{}, Witness{}, fmt.Errorf("red-case calibration: seal: %w", err)
	}

	// Fail closed: the collector MUST have observed the canary.
	if witness.ObservedCount < 1 {
		return RedCaseResult{}, Witness{}, ErrRedCaseNotDetected
	}

	// Build the verifiable result.
	colPub := colPriv.Public().(ed25519.PublicKey)
	digest := sha256.Sum256(witness.SignedBytes())

	return RedCaseResult{
		WitnessWentRed:   true,
		ObservedCount:    witness.ObservedCount,
		At:               witness.RunClosedAt,
		CollectorPubKey:  hex.EncodeToString(colPub),
		RedWitnessDigest: hex.EncodeToString(digest[:]),
	}, witness, nil
}
