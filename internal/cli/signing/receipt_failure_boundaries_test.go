// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package signing

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/fleetreceipt"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	domsigning "github.com/luckyPipewrench/pipelock/internal/signing"
)

func writeReceiptFailureFixture(t *testing.T) (string, string) {
	t.Helper()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	record := receipt.ActionRecord{
		Version:         receipt.ActionRecordVersion,
		ActionID:        receipt.NewActionID(),
		ActionType:      receipt.ActionRead,
		Timestamp:       time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC),
		Target:          "https://api.vendor.example/data",
		Verdict:         config.ActionBlock,
		Transport:       "fetch",
		SideEffectClass: receipt.SideEffectExternalRead,
		Reversibility:   receipt.ReversibilityFull,
		Actor:           "agent-a",
		PolicyHash:      strings.Repeat("a", 64),
	}
	signed, err := receipt.Sign(record, priv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	data, err := receipt.Marshal(signed)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	path := filepath.Join(t.TempDir(), "receipt.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return path, hex.EncodeToString(pub)
}

func executeReceiptFailureCase(t *testing.T, args ...string) (string, error) {
	t.Helper()

	var out bytes.Buffer
	cmd := VerifyReceiptCmd()
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	cmd.SetOut(&out)
	cmd.SetErr(io.Discard)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return out.String(), err
}

func TestVerifyReceiptRejectsAmbiguousOrUntrustedSources(t *testing.T) {
	receiptPath, _ := writeReceiptFailureFixture(t)

	tests := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{
			name:    "blank pin cannot silently enable unpinned mode",
			args:    []string{receiptPath, "--key", ""},
			wantErr: "no valid signer keys were resolved",
		},
		{
			name:    "fleet input and chain selector are mutually exclusive",
			args:    []string{"--fleet-report", "--chain", t.TempDir()},
			wantErr: "--fleet-report cannot be combined with --chain",
		},
		{
			name:    "fleet input and explicit session selector are mutually exclusive",
			args:    []string{receiptPath, "--fleet-report", "--session", "other"},
			wantErr: "--fleet-report cannot be combined with --session",
		},
		{
			name:    "file and chain sources are mutually exclusive",
			args:    []string{receiptPath, "--chain", t.TempDir()},
			wantErr: "cannot pass a file argument together with --chain",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			output, err := executeReceiptFailureCase(t, tc.args...)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("Execute error = %v, want containing %q", err, tc.wantErr)
			}
			if strings.Contains(output, "OK:") || strings.Contains(output, "VALID:") {
				t.Fatalf("rejected input emitted success output: %q", output)
			}
		})
	}
}

func TestVerifyReceiptFailsClosedOnUnreadableAndMalformedArtifacts(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing.json")
	malformed := filepath.Join(t.TempDir(), "malformed.json")
	if err := os.WriteFile(malformed, []byte(`{"receipt":`), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	tests := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{
			name:    "missing single receipt",
			args:    []string{missing},
			wantErr: "reading receipt",
		},
		{
			name:    "malformed single receipt",
			args:    []string{malformed},
			wantErr: "parsing receipt",
		},
		{
			name:    "missing fleet report",
			args:    []string{missing, "--fleet-report"},
			wantErr: "reading fleet receipt",
		},
		{
			name:    "malformed fleet report",
			args:    []string{malformed, "--fleet-report"},
			wantErr: "fleet receipt verification failed",
		},
		{
			name:    "missing session directory",
			args:    []string{"--chain", filepath.Join(t.TempDir(), "missing")},
			wantErr: "extracting session receipts",
		},
		{
			name:    "missing session directory for clean report",
			args:    []string{"--chain", filepath.Join(t.TempDir(), "missing"), "--clean-report", filepath.Join(t.TempDir(), "report.json")},
			wantErr: "extracting session receipts",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			output, err := executeReceiptFailureCase(t, tc.args...)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("Execute error = %v, want containing %q", err, tc.wantErr)
			}
			if strings.Contains(output, "OK:") || strings.Contains(output, "VALID:") {
				t.Fatalf("rejected artifact emitted success output: %q", output)
			}
		})
	}
}

func TestVerifyReceiptRejectsTamperingBeforeUnpinnedOptIn(t *testing.T) {
	path, _ := writeReceiptFailureFixture(t)
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	signed, err := receipt.Unmarshal(data)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	signed.Signature = strings.Repeat("00", ed25519.SignatureSize)
	tampered, err := receipt.Marshal(signed)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if err := os.WriteFile(path, tampered, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	output, err := executeReceiptFailureCase(t, path, "--allow-unpinned")
	if err == nil || !strings.Contains(err.Error(), "verification failed") {
		t.Fatalf("Execute error = %v, want verification failure", err)
	}
	if !strings.Contains(output, "FAILED:") {
		t.Fatalf("output = %q, want failure diagnostic", output)
	}
	if strings.Contains(output, "UNPINNED:") || strings.Contains(output, "OK:") {
		t.Fatalf("tampered receipt emitted success-like output: %q", output)
	}
}

func TestVerifyReceiptPostureInputsFailClosed(t *testing.T) {
	receiptPath, pubHex := writeReceiptFailureFixture(t)
	malformedCapsule := filepath.Join(t.TempDir(), "posture.json")
	if err := os.WriteFile(malformedCapsule, []byte(`{"schema":`), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	tests := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{
			name:    "posture requires a pin",
			args:    []string{receiptPath, "--key", pubHex, "--posture", malformedCapsule},
			wantErr: "--posture-key is required",
		},
		{
			name:    "posture file must exist",
			args:    []string{receiptPath, "--key", pubHex, "--posture", filepath.Join(t.TempDir(), "missing"), "--posture-key", pubHex},
			wantErr: "reading posture capsule",
		},
		{
			name:    "posture JSON must parse",
			args:    []string{receiptPath, "--key", pubHex, "--posture", malformedCapsule, "--posture-key", pubHex},
			wantErr: "parsing posture capsule",
		},
		{
			name:    "posture pin must be a public key",
			args:    []string{receiptPath, "--key", pubHex, "--posture", filepath.Join(t.TempDir(), "missing"), "--posture-key", "not-hex"},
			wantErr: "reading posture capsule",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			output, err := executeReceiptFailureCase(t, tc.args...)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("Execute error = %v, want containing %q", err, tc.wantErr)
			}
			if strings.Contains(output, "Containment: KERNEL") {
				t.Fatalf("invalid posture input claimed containment: %q", output)
			}
		})
	}

	validJSON := filepath.Join(t.TempDir(), "posture.json")
	if err := os.WriteFile(validJSON, []byte(`{}`), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	output, err := executeReceiptFailureCase(t, receiptPath, "--key", pubHex, "--posture", validJSON, "--posture-key", "not-hex")
	if err == nil || !strings.Contains(err.Error(), "decode posture key") {
		t.Fatalf("Execute error = %v, want posture key decode failure", err)
	}
	if strings.Contains(output, "Containment: KERNEL") {
		t.Fatalf("invalid posture pin claimed containment: %q", output)
	}
}

func TestFleetTrustedKeyMapRejectsMalformedKeys(t *testing.T) {
	env := fleetreceipt.Envelope{
		Signatures: []fleetreceipt.Signature{{KeyID: "operator-key"}},
	}
	tests := []struct {
		name    string
		key     string
		wantErr string
	}{
		{name: "invalid hex", key: "zz", wantErr: "decode trusted fleet report key"},
		{name: "wrong length", key: "00", wantErr: "key length=1"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			keyMap, err := fleetTrustedKeyMap(env, []string{tc.key})
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("fleetTrustedKeyMap error = %v, want containing %q", err, tc.wantErr)
			}
			if keyMap != nil {
				t.Fatalf("fleetTrustedKeyMap returned keys for invalid input: %#v", keyMap)
			}
		})
	}
}

func TestVerifyCleanReportRejectsUnsafeOutputAndTrust(t *testing.T) {
	path, pub := buildChainJSONL(t, 1)
	keyHex := hex.EncodeToString(pub)

	receipts, err := receipt.ExtractReceipts(path)
	if err != nil {
		t.Fatalf("ExtractReceipts: %v", err)
	}

	t.Run("unpinned report is rejected", func(t *testing.T) {
		err := verifyCleanReport(io.Discard, "session", receipts, nil, false, filepath.Join(t.TempDir(), "report.json"))
		if err == nil || !strings.Contains(err.Error(), "verification unpinned") {
			t.Fatalf("verifyCleanReport error = %v, want unpinned rejection", err)
		}
	})

	t.Run("broken chain is rejected", func(t *testing.T) {
		broken := append([]receipt.Receipt(nil), receipts...)
		broken[len(broken)-1].Signature = "00"
		err := verifyCleanReport(io.Discard, "session", broken, []string{keyHex}, false, filepath.Join(t.TempDir(), "report.json"))
		if err == nil || !strings.Contains(err.Error(), "chain verification failed") {
			t.Fatalf("verifyCleanReport error = %v, want chain rejection", err)
		}
	})

	t.Run("output directory is rejected", func(t *testing.T) {
		err := verifyCleanReport(io.Discard, "session", receipts, []string{keyHex}, false, t.TempDir())
		if err == nil || !strings.Contains(err.Error(), "write clean report") {
			t.Fatalf("verifyCleanReport error = %v, want write failure", err)
		}
	})
}

func TestReceiptDisplayAndWindowBounds(t *testing.T) {
	var out bytes.Buffer
	printReceiptDetails(&out, receipt.Receipt{ActionRecord: receipt.ActionRecord{
		ActionID:   "action-a",
		ActionType: receipt.ActionRead,
		Timestamp:  time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC),
		Target:     "target",
		Verdict:    config.ActionBlock,
		Transport:  "fetch",
		Actor:      "agent-a",
		PolicyHash: "policy-a",
	}}, receiptPrintOptions{ShowRaw: true})
	for _, want := range []string{"Actor:", "agent-a", "Policy Hash:", "policy-a", `raw: "target"`} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("output = %q, want containing %q", out.String(), want)
		}
	}

	sanitizeDisplayStrings(reflect.Value{})
	value := "safe"
	sanitizeDisplayStrings(reflect.ValueOf(&value))
	if value != "safe" {
		t.Fatalf("sanitizeDisplayStrings changed safe value to %q", value)
	}
	values := []string{"left", "right"}
	sanitizeDisplayStrings(reflect.ValueOf(&values).Elem())
	if strings.Join(values, ",") != "left,right" {
		t.Fatalf("sanitizeDisplayStrings changed safe slice: %#v", values)
	}

	start, end := receiptWindow(nil)
	if !start.IsZero() || !end.IsZero() {
		t.Fatalf("receiptWindow(nil) = (%v, %v), want zero bounds", start, end)
	}
	early := time.Date(2026, 7, 17, 10, 0, 0, 0, time.UTC)
	middle := early.Add(time.Hour)
	late := middle.Add(time.Hour)
	start, end = receiptWindow([]receipt.Receipt{
		{ActionRecord: receipt.ActionRecord{Timestamp: middle}},
		{ActionRecord: receipt.ActionRecord{Timestamp: early}},
		{ActionRecord: receipt.ActionRecord{Timestamp: late}},
	})
	if !start.Equal(early) || !end.Equal(late) {
		t.Fatalf("receiptWindow = (%v, %v), want (%v, %v)", start, end, early, late)
	}
}

func TestTranscriptRootRejectsBadKeysAndArtifacts(t *testing.T) {
	validPath, _ := buildChainJSONL(t, 1)
	emptyPath := filepath.Join(t.TempDir(), "empty.jsonl")
	if err := os.WriteFile(emptyPath, nil, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	tests := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{name: "malformed key", args: []string{validPath, "--key", "not-hex"}, wantErr: "loading public key"},
		{name: "blank key", args: []string{validPath, "--key", ""}, wantErr: "--key is required"},
		{name: "missing directory", args: []string{"--chain", filepath.Join(t.TempDir(), "missing"), "--key", strings.Repeat("00", ed25519.PublicKeySize)}, wantErr: "extracting session receipts"},
		{name: "missing file", args: []string{filepath.Join(t.TempDir(), "missing.jsonl"), "--key", strings.Repeat("00", ed25519.PublicKeySize)}, wantErr: "extracting receipts"},
		{name: "empty file", args: []string{emptyPath, "--key", strings.Repeat("00", ed25519.PublicKeySize)}, wantErr: "no receipts found"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			cmd := TranscriptRootCmd()
			cmd.SilenceUsage = true
			cmd.SilenceErrors = true
			cmd.SetOut(&out)
			cmd.SetErr(io.Discard)
			cmd.SetArgs(tc.args)
			err := cmd.Execute()
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("Execute error = %v, want containing %q", err, tc.wantErr)
			}
			if strings.Contains(out.String(), "Transcript Root:") {
				t.Fatalf("rejected input emitted transcript root: %q", out.String())
			}
		})
	}
}

func TestSigningArtifactReadersRejectMalformedFiles(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing")
	if _, _, _, err := loadKeyFile(missing, ""); err == nil || !strings.Contains(err.Error(), "read key file") {
		t.Fatalf("loadKeyFile error = %v, want read failure", err)
	}
	if _, _, err := readPublicKeyForRoster(missing); err == nil || !strings.Contains(err.Error(), "read public key") {
		t.Fatalf("readPublicKeyForRoster error = %v, want read failure", err)
	}
	if _, err := ReadKeyFileBytes(missing, true); err == nil {
		t.Fatal("ReadKeyFileBytes accepted a missing file")
	}
	if _, err := readPubkeyFile(missing); err == nil || !strings.Contains(err.Error(), "stat public key file") {
		t.Fatalf("readPubkeyFile error = %v, want stat failure", err)
	}
	if _, err := resolvePubkey("root", "", missing); err == nil || !strings.Contains(err.Error(), "invalid root") {
		t.Fatalf("resolvePubkey file error = %v, want wrapped failure", err)
	}
	if _, err := resolvePubkey("root", "not-hex", ""); err == nil || !strings.Contains(err.Error(), "invalid root") {
		t.Fatalf("resolvePubkey inline error = %v, want wrapped failure", err)
	}

	malformed := filepath.Join(t.TempDir(), "key.json")
	if err := os.WriteFile(malformed, []byte(`{"schema_version":`), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, _, _, err := loadKeyFile(malformed, ""); err == nil || !strings.Contains(err.Error(), "decode key file") {
		t.Fatalf("loadKeyFile malformed error = %v, want decode failure", err)
	}

	trailing := []byte(`{"schema_version":1,"purpose":"receipt-signing","key_id":"a","public":"","private":"","created_at":""} {`)
	if _, err := decodeKeyFile(trailing); err == nil || !strings.Contains(err.Error(), "trailing JSON") {
		t.Fatalf("decodeKeyFile trailing error = %v, want trailing JSON rejection", err)
	}
	if _, err := validateKeyFileMetadata(keyFile{SchemaVersion: keyFileSchemaVersion, Purpose: "unknown"}); err == nil || !strings.Contains(err.Error(), "invalid key file purpose") {
		t.Fatalf("validateKeyFileMetadata error = %v, want purpose rejection", err)
	}
	if _, err := decodeKeyFilePublic(keyFile{Public: "zz"}); err == nil || !strings.Contains(err.Error(), "decode public key hex") {
		t.Fatalf("decodeKeyFilePublic hex error = %v, want decode rejection", err)
	}
	if _, err := decodeKeyFilePublic(keyFile{Public: "00"}); err == nil || !strings.Contains(err.Error(), "wrong size") {
		t.Fatalf("decodeKeyFilePublic size error = %v, want size rejection", err)
	}

	rawPublic := filepath.Join(t.TempDir(), "agent.pub")
	if err := os.WriteFile(rawPublic, []byte("not-a-public-key"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, _, err := readPublicKeyForRoster(rawPublic); err == nil || !strings.Contains(err.Error(), "decode agent keystore") {
		t.Fatalf("readPublicKeyForRoster error = %v, want public key rejection", err)
	}
}

func TestLoadKeyFileRejectsMalformedPrivateMaterial(t *testing.T) {
	fx := newRosterBuildFixture(t)
	raw, err := os.ReadFile(filepath.Clean(fx.rootPath))
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	var base keyFile
	if err := json.Unmarshal(raw, &base); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	tests := []struct {
		name       string
		privateHex string
		wantErr    string
	}{
		{name: "invalid hex", privateHex: "zz", wantErr: "decode private key hex"},
		{name: "wrong size", privateHex: "00", wantErr: "private key has wrong size"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			kf := base
			kf.Private = tc.privateHex
			data, err := json.Marshal(kf)
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			path := filepath.Join(t.TempDir(), "key.json")
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatalf("WriteFile: %v", err)
			}
			if _, _, _, err := loadKeyFile(path, domsigning.PurposeRosterRoot); err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("loadKeyFile error = %v, want containing %q", err, tc.wantErr)
			}
		})
	}
}

func TestRosterInputParsingAndFilesystemFailures(t *testing.T) {
	if _, err := parseIncludeSpecs(nil); err == nil || !strings.Contains(err.Error(), "at least one") {
		t.Fatalf("parseIncludeSpecs nil error = %v, want required input rejection", err)
	}
	if _, err := parseIncludeSpecs([]string{"broken"}); err == nil || !strings.Contains(err.Error(), "--include[0]") {
		t.Fatalf("parseIncludeSpecs malformed error = %v, want indexed rejection", err)
	}
	if _, err := parseIncludeSpec(" , "); err == nil || !strings.Contains(err.Error(), "missing required field") {
		t.Fatalf("parseIncludeSpec blank error = %v, want required field rejection", err)
	}
	if _, err := parseIncludeSpec("broken"); err == nil || !strings.Contains(err.Error(), "expected key=value") {
		t.Fatalf("parseIncludeSpec malformed error = %v, want key-value rejection", err)
	}

	fx := newRosterBuildFixture(t)
	validPurpose := string(domsigning.PurposeContractActivationSigning)
	tests := []struct {
		name    string
		include string
		out     string
		wantErr string
	}{
		{
			name:    "unknown include purpose",
			include: "id=child,key=" + fx.activationPath + ",purpose=unknown",
			out:     filepath.Join(t.TempDir(), "roster.json"),
			wantErr: "--include id=\"child\"",
		},
		{
			name:    "missing include key",
			include: "id=child,key=" + filepath.Join(t.TempDir(), "missing") + ",purpose=" + validPurpose,
			out:     filepath.Join(t.TempDir(), "roster.json"),
			wantErr: "--include id=\"child\"",
		},
		{
			name:    "output cannot be a directory",
			include: "id=child,key=" + fx.activationPath + ",purpose=" + validPurpose,
			out:     t.TempDir(),
			wantErr: "write roster",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cmd := rosterBuildCmd()
			cmd.SilenceUsage = true
			cmd.SilenceErrors = true
			cmd.SetOut(io.Discard)
			cmd.SetErr(io.Discard)
			cmd.SetArgs([]string{
				"--root", fx.rootPath,
				"--include", tc.include,
				"--out", tc.out,
				"--force",
			})
			err := cmd.Execute()
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("Execute error = %v, want containing %q", err, tc.wantErr)
			}
		})
	}

	loop := filepath.Join(t.TempDir(), "loop")
	if err := os.Symlink(loop, loop); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	cmd := rosterBuildCmd()
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{
		"--root", fx.rootPath,
		"--include", "id=child,key=" + fx.activationPath + ",purpose=" + validPurpose,
		"--out", loop,
	})
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "stat output file") {
		t.Fatalf("Execute symlink-loop error = %v, want stat failure", err)
	}
}
