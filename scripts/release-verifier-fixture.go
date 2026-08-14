// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

// release-verifier-fixture emits the signed v1 receipt used by the release
// installer gate. Keeping the generator in this module is intentional: the
// receipt is produced by the exact candidate code being released, rather than
// copied from a fixture created by some earlier version.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/receipt"
)

const (
	receiptFileName  = "candidate-receipt.json"
	tamperedFileName = "candidate-receipt-tampered.json"
	keyFileName      = "candidate-receipt-public-key.txt"
)

var (
	generateSigningKey = ed25519.GenerateKey
	signReceipt        = receipt.Sign
	marshalReceipt     = receipt.Marshal
)

func main() {
	os.Exit(releaseVerifierFixtureMain(os.Args[1:], os.Stderr))
}

func releaseVerifierFixtureMain(args []string, stderr io.Writer) int {
	if err := runReleaseVerifierFixture(args); err != nil {
		_, _ = fmt.Fprintf(stderr, "release verifier fixture: %v\n", err)
		return 2
	}
	return 0
}

func runReleaseVerifierFixture(args []string) error {
	var outDir string
	flags := flag.NewFlagSet("release-verifier-fixture", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&outDir, "out-dir", "", "directory to write the receipt, tampered copy, and public key")
	if err := flags.Parse(args); err != nil {
		return fmt.Errorf("parse arguments: %w", err)
	}

	if strings.TrimSpace(outDir) == "" {
		return fmt.Errorf("--out-dir is required")
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected positional arguments")
	}

	if err := os.MkdirAll(outDir, 0o750); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}
	if err := writeFixture(outDir); err != nil {
		return fmt.Errorf("write fixture: %w", err)
	}
	return nil
}

func writeFixture(outDir string) error {
	publicKey, privateKey, err := generateSigningKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generate signing key: %w", err)
	}

	r, err := signReceipt(receipt.ActionRecord{
		Version:         receipt.ActionRecordVersion,
		ActionID:        receipt.NewActionID(),
		ActionType:      receipt.ActionRead,
		Timestamp:       time.Now().UTC(),
		Principal:       "org:release-verifier-install-gate",
		Actor:           "agent:release-candidate",
		DelegationChain: []string{"release-candidate"},
		Target:          "https://api.vendor.example/release-verifier-install-gate",
		SideEffectClass: receipt.SideEffectExternalRead,
		Reversibility:   receipt.ReversibilityFull,
		PolicyHash:      "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		Verdict:         "allow",
		Transport:       "https",
		Method:          "GET",
		ChainPrevHash:   receipt.GenesisHash,
		ChainSeq:        0,
	}, privateKey)
	if err != nil {
		return fmt.Errorf("sign receipt: %w", err)
	}

	raw, err := marshalReceipt(r)
	if err != nil {
		return fmt.Errorf("marshal receipt: %w", err)
	}
	tampered := strings.Replace(string(raw), "api.vendor.example", "tampered.vendor.example", 1)
	if tampered == string(raw) {
		return fmt.Errorf("replace signed target in receipt")
	}

	if err := os.WriteFile(filepath.Join(outDir, receiptFileName), raw, 0o600); err != nil {
		return fmt.Errorf("write receipt: %w", err)
	}
	if err := os.WriteFile(filepath.Join(outDir, tamperedFileName), []byte(tampered), 0o600); err != nil {
		return fmt.Errorf("write tampered receipt: %w", err)
	}
	if err := os.WriteFile(filepath.Join(outDir, keyFileName), []byte(hex.EncodeToString(publicKey)+"\n"), 0o600); err != nil {
		return fmt.Errorf("write public key: %w", err)
	}
	return nil
}
