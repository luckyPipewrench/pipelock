// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !js

package playground

import (
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	liveCanaryPrefix = "AKIA"
	// awsAccessKeyBodyLen is the random tail after the AKIA prefix; an AWS access
	// key id is exactly 20 chars (AKIA + 16).
	awsAccessKeyBodyLen = 16
	awsAccessKeyIDLen   = len(liveCanaryPrefix) + awsAccessKeyBodyLen
	// awsSecretKeyLen is the length of a generated dead secret-access-key.
	awsSecretKeyLen = 40
	// awsKeyIDCharset is the AWS access-key-id alphabet (base32, [A-Z2-7]). Its
	// length (32) divides 256, so charset[b%32] has no modulo bias.
	awsKeyIDCharset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	// awsSecretCharset is a base64-url-ish alphabet for the secret-access-key. Its
	// length (64) divides 256, so there is no modulo bias either.
	awsSecretCharset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
)

// liveCanaryValue generates the dead, AWS-access-key-shaped value planted for a
// run: "AKIA" + 16 random base32 chars. It is dead BY CONSTRUCTION -- generated
// locally with crypto/rand and NEVER provisioned against AWS, so it matches no
// issued key (a collision with a real key is astronomically unlikely). An access
// key id is exactly 20 chars, so the run nonce is not appended; rotation comes
// from fresh randomness on every run.
func liveCanaryValue() (string, error) {
	body, err := randFromCharset(awsAccessKeyBodyLen, awsKeyIDCharset)
	if err != nil {
		return "", fmt.Errorf("generate canary access key id: %w", err)
	}
	return liveCanaryPrefix + body, nil
}

// liveSecretAccessKey generates a dead, secret-access-key-shaped value (40 random
// chars). Dead by construction, same as liveCanaryValue.
func liveSecretAccessKey() (string, error) {
	return randFromCharset(awsSecretKeyLen, awsSecretCharset)
}

// randFromCharset returns n random characters drawn from charset using
// crypto/rand. Both charsets used here have lengths that divide 256, so the
// modulo mapping is unbiased.
func randFromCharset(n int, charset string) (string, error) {
	if n <= 0 || charset == "" {
		return "", fmt.Errorf("randFromCharset: invalid parameters")
	}
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("read random bytes: %w", err)
	}
	out := make([]byte, n)
	for i, b := range buf {
		out[i] = charset[int(b)%len(charset)]
	}
	return string(out), nil
}

// isCanaryShape reports whether v is the synthetic AWS-access-key shape this demo
// plants: the AKIA prefix, exactly 20 chars total, with the 16-char tail drawn
// from the base32 access-key-id alphabet. The guard ensures the planted value is
// the synthetic shape produced by liveCanaryValue, never an externally supplied
// real key.
func isCanaryShape(v string) bool {
	if len(v) != awsAccessKeyIDLen || !strings.HasPrefix(v, liveCanaryPrefix) {
		return false
	}
	for _, r := range v[len(liveCanaryPrefix):] {
		if !strings.ContainsRune(awsKeyIDCharset, r) {
			return false
		}
	}
	return true
}

// Preflight runs cheap stage-hygiene checks before a demo run. It confirms:
//   - the canary value looks synthetic (not a real-looking secret),
//   - the run directory is writable,
//   - if contained mode is requested, the containment hook is wired.
func Preflight(opts DemoOpts) error {
	// --- Canary shape check ---
	// The demo plants a credential-shaped but DEAD value (AKIA + random, generated
	// locally with crypto/rand, never provisioned against AWS). It is deliberately
	// AWS-shaped so normal DLP catches the class; Pipelock is not configured with
	// the exact value as a canary token. The guard confirms the generator produces
	// the synthetic shape, so a real externally-supplied key shape is never planted.
	canary, err := liveCanaryValue()
	if err != nil {
		return fmt.Errorf("preflight: generate canary: %w", err)
	}
	if !isCanaryShape(canary) {
		return fmt.Errorf("preflight: canary value is not the expected synthetic AWS access-key shape")
	}

	// --- RunDir writable check ---
	cleanDir := filepath.Clean(opts.RunDir)
	if err := os.MkdirAll(cleanDir, 0o750); err != nil {
		return fmt.Errorf("preflight: run dir %q not writable: %w", opts.RunDir, err)
	}
	// Probe write by creating and removing a sentinel file.
	probe := filepath.Join(cleanDir, ".preflight-probe")
	if err := os.WriteFile(probe, []byte("probe"), 0o600); err != nil {
		return fmt.Errorf("preflight: cannot write to run dir %q: %w", opts.RunDir, err)
	}
	_ = os.Remove(probe)

	// --- Containment hook check ---
	if opts.Contained {
		if getContainmentHook() == nil {
			return ErrContainmentNotWired
		}
	}

	return nil
}
