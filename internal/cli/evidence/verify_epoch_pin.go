// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package evidence

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/recorder"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

type verifyEpochPinOptions struct {
	receiptDir, locationID, sessionID, publicKey, pinFile, pinSHA256 string
}

func verifyEpochPinCmd() *cobra.Command {
	opts := verifyEpochPinOptions{}
	cmd := &cobra.Command{Use: "verify-epoch-pin", Short: "Verify an exact epoch inspection pin", Long: "Verify that a canonical inspect-epochs document and its checksum still match one stopped recorder session. This consistency check does not authorize or perform evidence retirement.", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error { return runVerifyEpochPin(cmd, opts) }}
	cmd.Flags().StringVar(&opts.receiptDir, "receipt-dir", "", "flight-recorder evidence directory")
	cmd.Flags().StringVar(&opts.locationID, "location", "", "location path relative to the evidence directory")
	cmd.Flags().StringVar(&opts.sessionID, "session", "", "session ID to verify")
	cmd.Flags().StringVar(&opts.publicKey, "key", "", "trusted receipt signing public key (inline or file)")
	cmd.Flags().StringVar(&opts.pinFile, "pin", "", "inspect-epochs JSON approved by the operator")
	cmd.Flags().StringVar(&opts.pinSHA256, "pin-sha256", "", "expected SHA-256 of the exact pin bytes")
	for _, name := range []string{"receipt-dir", "session", "key", "pin", "pin-sha256"} {
		_ = cmd.MarkFlagRequired(name)
	}
	return cmd
}

func runVerifyEpochPin(cmd *cobra.Command, opts verifyEpochPinOptions) error {
	if strings.TrimSpace(opts.sessionID) == "" {
		return errors.New("--session is required")
	}
	expectedDigest, err := parseEpochPinDigest(opts.pinSHA256)
	if err != nil {
		return err
	}
	pinBytes, pin, err := readEpochPin(opts.pinFile, expectedDigest)
	if err != nil {
		return err
	}
	if pin.SessionID != opts.sessionID {
		return fmt.Errorf("epoch pin session %q does not match --session %q", pin.SessionID, opts.sessionID)
	}
	if len(pin.RecorderEpochs) < 2 {
		return fmt.Errorf("epoch pin contains %d recorder epoch(s); verification requires a multi-epoch history", len(pin.RecorderEpochs))
	}
	var signedReceipts uint64
	for _, epoch := range pin.RecorderEpochs {
		if epoch.V1Degraded || epoch.V1FirstGap || epoch.V1TailGap {
			return fmt.Errorf("epoch pin receipt proof is degraded in legacy epoch %d; a clean per-epoch receipt proof is required", epoch.Epoch)
		}
		signedReceipts += epoch.V1Count
	}
	if pin.ReceiptVerification.Status != "verified_per_epoch" || signedReceipts == 0 {
		return fmt.Errorf("epoch pin receipt proof is %q with %d signed receipt(s); a clean per-epoch receipt proof is required", pin.ReceiptVerification.Status, signedReceipts)
	}
	if len(pin.CheckpointVerification.Unsigned) != 0 {
		return fmt.Errorf("epoch pin contains %d unsigned checkpoint(s); a fully signed checkpoint proof is required", len(pin.CheckpointVerification.Unsigned))
	}
	root, err := validateReceiptDir(opts.receiptDir)
	if err != nil {
		return err
	}
	location, err := recorder.ResolveEvidenceLocation(root, opts.locationID)
	if err != nil {
		return fmt.Errorf("resolve evidence location: %w", err)
	}
	key, err := signing.LoadPublicKey(strings.TrimSpace(opts.publicKey))
	if err != nil {
		return fmt.Errorf("load --key: %w", err)
	}
	lock, err := compactAcquireLock(location.Dir)
	if err != nil {
		return fmt.Errorf("lock stopped evidence directory: %w", err)
	}
	defer func() { _ = lock.Close() }()
	names, err := inspectEpochSourceNames(location, opts.sessionID)
	if err != nil {
		return err
	}
	proof, err := compactVerifyStream(location, names, opts.sessionID, key, func(compactStreamFile, []byte, recorder.Entry) error { return nil })
	if err != nil {
		return fmt.Errorf("re-verify epoch source: %w", err)
	}
	currentBytes, err := json.Marshal(inspectEpochsDocumentFromProof(opts.sessionID, proof))
	if err != nil {
		return fmt.Errorf("encode current epoch boundaries: %w", err)
	}
	currentBytes = append(currentBytes, '\n')
	if !bytes.Equal(pinBytes, currentBytes) {
		return errors.New("epoch source no longer matches the supplied inspection pin")
	}
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "epoch inspection pin verified: %s  %s\nconsistency check only; no evidence changed and retirement is not authorized\n", hex.EncodeToString(expectedDigest), opts.pinFile)
	return nil
}

func parseEpochPinDigest(raw string) ([]byte, error) {
	decoded, err := hex.DecodeString(strings.TrimSpace(raw))
	if err != nil || len(decoded) != sha256.Size {
		return nil, errors.New("--pin-sha256 must be exactly 64 hexadecimal characters")
	}
	return decoded, nil
}

func readEpochPin(path string, expectedDigest []byte) ([]byte, inspectEpochsDocument, error) {
	// #nosec G304 -- --pin is an explicit operator-selected input.
	f, err := os.Open(strings.TrimSpace(path))
	if err != nil {
		return nil, inspectEpochsDocument{}, fmt.Errorf("open --pin: %w", err)
	}
	data, readErr := io.ReadAll(io.LimitReader(f, (8<<20)+1))
	closeErr := f.Close()
	if readErr != nil {
		return nil, inspectEpochsDocument{}, fmt.Errorf("read --pin: %w", readErr)
	}
	if closeErr != nil {
		return nil, inspectEpochsDocument{}, fmt.Errorf("close --pin: %w", closeErr)
	}
	if len(data) > 8<<20 {
		return nil, inspectEpochsDocument{}, errors.New("--pin exceeds 8 MiB")
	}
	digest := sha256.Sum256(data)
	if !bytes.Equal(digest[:], expectedDigest) {
		return nil, inspectEpochsDocument{}, errors.New("--pin SHA-256 does not match --pin-sha256")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var document inspectEpochsDocument
	if err := decoder.Decode(&document); err != nil {
		return nil, inspectEpochsDocument{}, fmt.Errorf("decode --pin: %w", err)
	}
	if document.Version != 1 {
		return nil, inspectEpochsDocument{}, fmt.Errorf("unsupported epoch pin version %d", document.Version)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, inspectEpochsDocument{}, errors.New("decode --pin: trailing JSON value")
	}
	canonical, err := json.Marshal(document)
	if err != nil {
		return nil, inspectEpochsDocument{}, fmt.Errorf("encode --pin canonically: %w", err)
	}
	canonical = append(canonical, '\n')
	if !bytes.Equal(data, canonical) {
		return nil, inspectEpochsDocument{}, errors.New("--pin is not canonical inspect-epochs output")
	}
	return data, document, nil
}
