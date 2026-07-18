// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/capture"
	"github.com/luckyPipewrench/pipelock/internal/contract"
)

func TestCaptureCommandPrintsOnlyOperationalInstructions(t *testing.T) {
	cmd := captureCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{
		"--output", "/tmp/session-output",
		"--config", "/tmp/config.yaml",
		"--duration", "1s",
		"--sign",
		"--redact",
		"--raw-escrow",
		"--escrow-public-key", "private-material-must-not-print",
		"--checkpoint-interval", "2",
		"--retention-days", "3",
		"--max-entries-per-file", "4",
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("capture command: %v", err)
	}
	got := out.String()
	if !strings.Contains(got, "pipelock run --capture-output /tmp/session-output") {
		t.Fatalf("missing operational instruction: %q", got)
	}
	if strings.Contains(got, "private-material-must-not-print") {
		t.Fatalf("capture output exposed key material: %q", got)
	}
}

func TestReplayRejectsMalformedContractsBeforeSessionAccess(t *testing.T) {
	tests := []struct {
		name string
		body string
		key  string
		want string
	}{
		{name: "malformed document", body: "body: [", want: "loading contract"},
		{name: "unknown field", body: "unknown: true\n", want: "loading contract"},
		{name: "invalid body", body: "body: {}\nsignature: ed25519:00\n", want: "validating contract"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "contract.yaml")
			if err := os.WriteFile(path, []byte(tt.body), 0o600); err != nil {
				t.Fatal(err)
			}
			_, _, err := loadReplayContract(path, tt.key, false)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want substring %q", err, tt.want)
			}
		})
	}

	_, _, err := loadReplayContract(filepath.Join(t.TempDir(), "missing.yaml"), "", false)
	if err == nil || !strings.Contains(err.Error(), "loading contract") {
		t.Fatalf("missing contract error = %v", err)
	}
}

func TestContractEnvelopeVerificationFailsClosed(t *testing.T) {
	validBody := validReplayContractBody(t)
	_, publicKey := writeSignedReplayContract(t)
	pub, err := hex.DecodeString(publicKey)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		env  contract.ContractEnvelope
		want string
	}{
		{
			name: "wrong key purpose",
			env: contract.ContractEnvelope{
				Body:      contract.Contract{KeyPurpose: "general-signing"},
				Signature: "ed25519:" + strings.Repeat("00", ed25519.SignatureSize),
			},
			want: "key_purpose",
		},
		{
			name: "wrong signature scheme",
			env: contract.ContractEnvelope{
				Body:      validBody,
				Signature: "rsa:" + strings.Repeat("00", ed25519.SignatureSize),
			},
			want: "must use ed25519",
		},
		{
			name: "non hex signature",
			env: contract.ContractEnvelope{
				Body:      validBody,
				Signature: "ed25519:not-hex",
			},
			want: "decode signature",
		},
		{
			name: "short signature",
			env: contract.ContractEnvelope{
				Body:      validBody,
				Signature: "ed25519:00",
			},
			want: "signature length",
		},
		{
			name: "invalid signature",
			env: contract.ContractEnvelope{
				Body:      validBody,
				Signature: "ed25519:" + strings.Repeat("00", ed25519.SignatureSize),
			},
			want: "signature verification failed",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := verifyContractEnvelope(tt.env, pub)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want substring %q", err, tt.want)
			}
		})
	}

	badPreimage := validBody
	badPreimage.Defaults.Confidence = map[string]any{"bad": func() {}}
	err = verifyContractEnvelope(contract.ContractEnvelope{
		Body:      badPreimage,
		Signature: "ed25519:" + strings.Repeat("00", ed25519.SignatureSize),
	}, pub)
	if err == nil || !strings.Contains(err.Error(), "build preimage") {
		t.Fatalf("preimage error = %v", err)
	}
}

func TestLoadReplayContractRejectsBadVerificationKey(t *testing.T) {
	path, _ := writeSignedReplayContract(t)
	_, _, err := loadReplayContract(path, "not-a-public-key", false)
	if err == nil || !strings.Contains(err.Error(), "loading contract verification key") {
		t.Fatalf("key error = %v", err)
	}
}

func TestReplayRejectsEscrowKeyBeforeReadingSessions(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	err := runReplay(cmd, replayOpts{
		configFile:    writeCandidateConfig(t),
		sessionsDir:   filepath.Join(t.TempDir(), "missing"),
		escrowPrivKey: "not-hex",
	})
	if err == nil || !strings.Contains(err.Error(), "invalid --escrow-private-key") {
		t.Fatalf("escrow error = %v", err)
	}
}

func TestReplayReportFailuresDoNotCreatePartialRegularFiles(t *testing.T) {
	sessions := t.TempDir()
	configPath := writeCandidateConfig(t)

	for _, tt := range []struct {
		name string
		opts replayOpts
		want string
	}{
		{
			name: "HTML destination is directory",
			opts: replayOpts{
				configFile:  configPath,
				sessionsDir: sessions,
				reportPath:  t.TempDir(),
			},
			want: "writing HTML report",
		},
		{
			name: "JSON destination is directory",
			opts: replayOpts{
				configFile:     configPath,
				sessionsDir:    sessions,
				reportJSONPath: t.TempDir(),
			},
			want: "writing JSON report",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cmd := &cobra.Command{}
			cmd.SetOut(io.Discard)
			cmd.SetErr(io.Discard)
			err := runReplay(cmd, tt.opts)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want substring %q", err, tt.want)
			}
		})
	}
}

func TestWriteReportPropagatesRendererFailureAndUsesPrivateMode(t *testing.T) {
	sentinel := errors.New("render failed")
	path := filepath.Join(t.TempDir(), "report.json")
	original := []byte("previous complete report\n")
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatal(err)
	}
	err := writeReport(path, &capture.DiffReport{}, func(io.Writer, *capture.DiffReport) error {
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("render error = %v", err)
	}
	data, readErr := os.ReadFile(path) // #nosec G304 -- path is inside t.TempDir.
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(data) != string(original) {
		t.Fatalf("failed render replaced complete report: %q", data)
	}

	err = writeReport(path, &capture.DiffReport{}, func(w io.Writer, _ *capture.DiffReport) error {
		_, writeErr := io.WriteString(w, "complete report\n")
		return writeErr
	})
	if err != nil {
		t.Fatalf("writeReport success path: %v", err)
	}
	info, statErr := os.Stat(path)
	if statErr != nil {
		t.Fatal(statErr)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("report mode = %o, want 600", got)
	}
}

func validReplayContractBody(t *testing.T) contract.Contract {
	t.Helper()
	path, _ := writeSignedReplayContract(t)
	data, err := os.ReadFile(path) // #nosec G304 -- path comes from this test's temp fixture.
	if err != nil {
		t.Fatal(err)
	}
	var env contract.ContractEnvelope
	if err := contract.DecodeStrictYAML(data, &env); err != nil {
		t.Fatal(err)
	}
	return env.Body
}

func TestReplayContractKeyHexIsAcceptedOnlyWhenSignatureMatches(t *testing.T) {
	path, publicKey := writeSignedReplayContract(t)
	decoded, err := hex.DecodeString(publicKey)
	if err != nil || len(decoded) != ed25519.PublicKeySize {
		t.Fatalf("test public key: len=%d err=%v", len(decoded), err)
	}
	body, verified, err := loadReplayContract(path, publicKey, false)
	if err != nil || body == nil || !verified {
		t.Fatalf("verified contract = body:%v verified:%v err:%v", body != nil, verified, err)
	}
}
