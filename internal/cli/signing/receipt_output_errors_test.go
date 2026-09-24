// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package signing

import (
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

type receiptOutputFailWriter struct {
	err    error
	writes int
}

func (w *receiptOutputFailWriter) Write([]byte) (int, error) {
	w.writes++
	return 0, w.err
}

type receiptOutputShortWriter struct {
	writes int
}

func (w *receiptOutputShortWriter) Write(p []byte) (int, error) {
	w.writes++
	return len(p) - 1, nil
}

func executeReceiptCommand(t *testing.T, out io.Writer, args ...string) error {
	t.Helper()
	cmd := VerifyReceiptCmd()
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	cmd.SetOut(out)
	cmd.SetErr(io.Discard)
	cmd.SetArgs(args)
	return cmd.Execute()
}

func TestVerifyReceiptCmdOutputFailureEverySelector(t *testing.T) {
	singleReceipt, singleKey := writeReceiptFailureFixture(t)
	chainFile, chainPublicKey := buildChainJSONL(t, 1)
	chainDir, chainDirPublicKey := buildRestartChainDir(t, 1)
	wholeRecorder, wholeRecorderPublicKey := buildSealedRecorderJSONL(t)
	wholeRecorderDir, wholeRecorderDirPublicKey := buildSealedRestartRecorderDir(t, 1)
	fleetPublicKey, fleetReport := writeFleetReportFixture(t)

	tests := []struct {
		name string
		args func(t *testing.T) []string
	}{
		{
			name: "single receipt",
			args: func(*testing.T) []string {
				return []string{singleReceipt, "--key", singleKey}
			},
		},
		{
			name: "fleet report",
			args: func(*testing.T) []string {
				return []string{fleetReport, "--fleet-report", "--key", hex.EncodeToString(fleetPublicKey)}
			},
		},
		{
			name: "resolved session chain",
			args: func(*testing.T) []string {
				return []string{"--chain", chainDir, "--key", hex.EncodeToString(chainDirPublicKey)}
			},
		},
		{
			name: "resolved session clean report",
			args: func(t *testing.T) []string {
				report := filepath.Join(t.TempDir(), "clean-report.json")
				return []string{"--chain", chainDir, "--key", hex.EncodeToString(chainDirPublicKey), "--clean-report", report}
			},
		},
		{
			name: "resolved session whole recorder",
			args: func(*testing.T) []string {
				return []string{"--chain", wholeRecorderDir, "--whole-recorder", "--key", hex.EncodeToString(wholeRecorderDirPublicKey)}
			},
		},
		{
			name: "JSONL chain",
			args: func(*testing.T) []string {
				return []string{chainFile, "--key", hex.EncodeToString(chainPublicKey)}
			},
		},
		{
			name: "JSONL clean report",
			args: func(t *testing.T) []string {
				return []string{chainFile, "--key", hex.EncodeToString(chainPublicKey), "--clean-report", filepath.Join(t.TempDir(), "clean-report.json")}
			},
		},
		{
			name: "JSONL whole recorder",
			args: func(*testing.T) []string {
				return []string{wholeRecorder, "--whole-recorder", "--key", hex.EncodeToString(wholeRecorderPublicKey)}
			},
		},
	}

	sentinel := errors.New("output unavailable")
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			writer := &receiptOutputFailWriter{err: sentinel}
			err := executeReceiptCommand(t, writer, tc.args(t)...)
			if !errors.Is(err, sentinel) {
				t.Fatalf("Execute error = %v, want output error %v", err, sentinel)
			}
			if writer.writes == 0 {
				t.Fatal("command did not attempt to deliver its report")
			}
		})
	}
}

func TestVerifyReceiptCmdCleanReportWrittenBeforeOutputFailure(t *testing.T) {
	chainFile, publicKey := buildChainJSONL(t, 1)
	report := filepath.Join(t.TempDir(), "clean-report.json")
	sentinel := errors.New("stdout unavailable")

	err := executeReceiptCommand(t, &receiptOutputFailWriter{err: sentinel}, chainFile, "--key", hex.EncodeToString(publicKey), "--clean-report", report)
	if !errors.Is(err, sentinel) {
		t.Fatalf("Execute error = %v, want output error %v", err, sentinel)
	}
	data, readErr := os.ReadFile(filepath.Clean(report))
	if readErr != nil || len(data) == 0 {
		t.Fatalf("clean report was not written before output failure: read=%v data=%q", readErr, data)
	}
}

func TestVerifyReceiptCmdOutputShortWriteAndSemanticErrorPrecedence(t *testing.T) {
	receiptPath, trustedKey := writeReceiptFailureFixture(t)

	t.Run("short write without writer error", func(t *testing.T) {
		writer := &receiptOutputShortWriter{}
		err := executeReceiptCommand(t, writer, receiptPath, "--key", trustedKey)
		if !errors.Is(err, io.ErrShortWrite) {
			t.Fatalf("Execute error = %v, want io.ErrShortWrite", err)
		}
		if writer.writes == 0 {
			t.Fatal("command did not attempt output")
		}
	})

	t.Run("verification error remains primary", func(t *testing.T) {
		writer := &receiptOutputFailWriter{err: errors.New("output unavailable")}
		err := executeReceiptCommand(t, writer, receiptPath, "--key", strings.Repeat("00", 32))
		if err == nil || !strings.Contains(err.Error(), "verification failed") {
			t.Fatalf("Execute error = %v, want receipt verification failure", err)
		}
		if errors.Is(err, writer.err) {
			t.Fatalf("semantic error %v was masked by output failure %v", err, writer.err)
		}
		if writer.writes == 0 {
			t.Fatal("semantic failure case did not attempt its diagnostic output")
		}
	})

	t.Run("discard succeeds", func(t *testing.T) {
		if err := executeReceiptCommand(t, io.Discard, receiptPath, "--key", trustedKey); err != nil {
			t.Fatalf("Execute with io.Discard: %v", err)
		}
	})
}

func TestTranscriptRootCmdOutputErrors(t *testing.T) {
	chainFile, publicKey := buildChainJSONL(t, 1)
	args := []string{chainFile, "--key", hex.EncodeToString(publicKey)}

	run := func(t *testing.T, out io.Writer) error {
		t.Helper()
		cmd := TranscriptRootCmd()
		cmd.SilenceUsage = true
		cmd.SilenceErrors = true
		cmd.SetOut(out)
		cmd.SetErr(io.Discard)
		cmd.SetArgs(args)
		return cmd.Execute()
	}

	t.Run("total write failure", func(t *testing.T) {
		sentinel := errors.New("output unavailable")
		writer := &receiptOutputFailWriter{err: sentinel}
		if err := run(t, writer); !errors.Is(err, sentinel) {
			t.Fatalf("Execute error = %v, want output error %v", err, sentinel)
		}
	})
	t.Run("short write without writer error", func(t *testing.T) {
		if err := run(t, &receiptOutputShortWriter{}); !errors.Is(err, io.ErrShortWrite) {
			t.Fatalf("Execute error = %v, want io.ErrShortWrite", err)
		}
	})
	t.Run("discard succeeds", func(t *testing.T) {
		if err := run(t, io.Discard); err != nil {
			t.Fatalf("Execute with io.Discard: %v", err)
		}
	})
}

func TestReceiptCommandsUseCobraOutputFallback(t *testing.T) {
	for _, cmd := range []*cobra.Command{VerifyReceiptCmd(), TranscriptRootCmd()} {
		cmd.SetOut(nil)
		if cmd.OutOrStdout() == nil {
			t.Fatalf("%s OutOrStdout returned nil after SetOut(nil)", cmd.Name())
		}
	}
}

func TestVerifyReceiptCmdHelpDescribesOutputContract(t *testing.T) {
	if !strings.Contains(VerifyReceiptCmd().Long, "Exit 0 = the receipt is valid and the requested report was delivered") {
		t.Fatal("verify-receipt help does not describe successful report delivery")
	}
}
