// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// gen-shadow-example produces a reproducible verifiable-shadow-rollout example
// bundle. It exercises the real capture, shadow analysis, receipt emission, and
// receipt verification code paths with deterministic timestamps and keys so the
// output is byte-reproducible.
//
// Usage:
//
//	go run ./tools/gen-shadow-example --out examples/verifiable-shadow-rollout
package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/capture"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/contract"
	contractreceipt "github.com/luckyPipewrench/pipelock/internal/contract/receipt"
	"github.com/luckyPipewrench/pipelock/internal/contract/shadow"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

const outFlag = "--out"

// Frozen timestamps for reproducibility.
var (
	captureTime  = time.Date(2026, 4, 30, 11, 30, 0, 0, time.UTC)
	analysisTime = time.Date(2026, 4, 30, 12, 0, 0, 0, time.UTC)
)

func main() {
	outDir := "examples/verifiable-shadow-rollout"
	for i, arg := range os.Args[1:] {
		if arg == outFlag {
			if i+1 >= len(os.Args)-1 {
				_, _ = fmt.Fprintf(os.Stderr, "gen-shadow-example: %s requires a value\n", outFlag)
				os.Exit(2)
			}
			outDir = os.Args[i+2]
		}
	}
	if err := run(outDir); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "gen-shadow-example: %v\n", err)
		os.Exit(1)
	}
}

func run(outDir string) error {
	absOut, err := filepath.Abs(outDir)
	if err != nil {
		return fmt.Errorf("resolve output: %w", err)
	}
	if err := os.MkdirAll(absOut, 0o750); err != nil {
		return fmt.Errorf("mkdir output: %w", err)
	}
	if err := cleanGeneratedArtifacts(absOut); err != nil {
		return err
	}

	// ---- Step 1: Deterministic keys ----

	contractSeed := sha256.Sum256([]byte("pipelock example contract signer"))
	contractPriv := ed25519.NewKeyFromSeed(contractSeed[:])
	contractPub := contractPriv.Public().(ed25519.PublicKey)

	receiptSeed := sha256.Sum256([]byte("pipelock deterministic shadow receipt signer"))
	receiptPriv := ed25519.NewKeyFromSeed(receiptSeed[:])
	receiptPub := receiptPriv.Public().(ed25519.PublicKey)

	receiptPubHex := hex.EncodeToString(receiptPub)
	if err := writeFile(filepath.Join(absOut, "receipt-signing.pub"), []byte(receiptPubHex+"\n")); err != nil {
		return err
	}

	contractPubHex := hex.EncodeToString(contractPub)
	if err := writeFile(filepath.Join(absOut, "contract-signing.pub"), []byte(contractPubHex+"\n")); err != nil {
		return err
	}

	// ---- Step 2: Write deterministic capture JSONL ----

	sessionsDir := filepath.Join(absOut, "sessions")
	sessionDir := filepath.Join(sessionsDir, "session-a")
	if err := os.MkdirAll(sessionDir, 0o750); err != nil {
		return fmt.Errorf("mkdir session: %w", err)
	}

	captureEntry := buildCaptureEntry()
	captureJSONL, err := marshalEntry(captureEntry)
	if err != nil {
		return fmt.Errorf("marshal capture entry: %w", err)
	}
	if err := writeFile(filepath.Join(sessionDir, "evidence-session-a-0.jsonl"), captureJSONL); err != nil {
		return err
	}

	// ---- Step 3: Create signed candidate contract ----

	body := buildContractBody()
	preimage, err := body.SignablePreimage()
	if err != nil {
		return fmt.Errorf("contract preimage: %w", err)
	}
	env := contract.ContractEnvelope{
		Body:      body,
		Signature: "ed25519:" + hex.EncodeToString(ed25519.Sign(contractPriv, preimage)),
	}
	contractData, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal contract: %w", err)
	}
	if err := writeFile(filepath.Join(absOut, "candidate-contract.json"), contractData); err != nil {
		return err
	}

	// ---- Step 4: Shadow replay ----

	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false

	records, _, _, _, err := capture.LoadAndReplayWithOptions(cfg, sessionsDir, capture.ReplayOptions{
		Contract: &env.Body,
	})
	if err != nil {
		return fmt.Errorf("replay captures: %w", err)
	}
	records = filterDuration(records, analysisTime, 365*24*time.Hour)

	report, err := shadow.Analyze(records, shadow.AnalyzeOptions{
		ContractHash: body.ContractHash,
		GeneratedAt:  analysisTime,
		Aggregation:  shadow.DefaultAggregateConfig(),
		Quarantine:   shadow.DefaultQuarantineConfig(),
	})
	if err != nil {
		return fmt.Errorf("analyze shadow: %w", err)
	}

	// Write shadow reports.
	var mdWriter, jsWriter strings.Builder
	if err := shadow.RenderMarkdown(&mdWriter, report); err != nil {
		return fmt.Errorf("render markdown: %w", err)
	}
	if err := shadow.RenderJSON(&jsWriter, report); err != nil {
		return fmt.Errorf("render json: %w", err)
	}
	if err := writeFile(filepath.Join(absOut, "shadow.md"), []byte(mdWriter.String())); err != nil {
		return err
	}
	if err := writeFile(filepath.Join(absOut, "shadow.json"), []byte(jsWriter.String())); err != nil {
		return err
	}

	// ---- Step 5: Emit shadow_delta receipts deterministically ----

	recorderDir := filepath.Join(absOut, "recorder")
	if err := os.MkdirAll(recorderDir, 0o750); err != nil {
		return fmt.Errorf("mkdir recorder: %w", err)
	}
	rec, err := recorder.New(recorder.Config{
		Enabled:            true,
		Dir:                recorderDir,
		CheckpointInterval: 1000,
		MaxEntriesPerFile:  10000,
		Redact:             true,
	}, nil, nil)
	if err != nil {
		return fmt.Errorf("open recorder: %w", err)
	}

	eventIdx := 0
	signer := deterministicSigner{
		keyID: "deterministic-receipt-signing",
		key:   receiptPriv,
	}
	emitter := shadow.NewEmitter(shadow.EmitterConfig{
		Recorder:   rec,
		Signer:     signer,
		Principal:  "learn",
		Actor:      "shadow",
		SelectorID: body.Selector.SelectorID,
		Clock:      func() time.Time { return analysisTime },
		EventID: func() (string, error) {
			eventIdx++
			return fmt.Sprintf("019e0000-0000-7000-8000-%012d", eventIdx), nil
		},
	})
	for _, batch := range report.Batches {
		if err := emitter.EmitBatch(batch); err != nil {
			_ = rec.Close()
			return fmt.Errorf("emit batch: %w", err)
		}
	}
	if err := rec.Close(); err != nil {
		return fmt.Errorf("close recorder: %w", err)
	}

	// ---- Step 6: Extract the shadow_delta receipt ----

	receiptJSON, err := extractReceipt(recorderDir)
	if err != nil {
		return err
	}
	prettyReceipt, _ := indentJSON(receiptJSON)
	if err := writeFile(filepath.Join(absOut, "shadow-delta-receipt.json"), prettyReceipt); err != nil {
		return err
	}

	// ---- Step 7: Verify the receipt ----

	var rcpt contractreceipt.EvidenceReceipt
	if err := json.Unmarshal(receiptJSON, &rcpt); err != nil {
		return fmt.Errorf("unmarshal receipt for verification: %w", err)
	}
	if err := contractreceipt.VerifyWithKey(rcpt, receiptPub, "deterministic-receipt-signing"); err != nil {
		return fmt.Errorf("receipt verification FAILED: %w", err)
	}
	fmt.Println("receipt verification: PASS")

	summary := map[string]any{
		"receipt_path":      "shadow-delta-receipt.json",
		"signer_key_id":     rcpt.Signature.SignerKeyID,
		"signer_public_key": receiptPubHex,
		"payload_kind":      string(rcpt.PayloadKind),
		"event_id":          rcpt.EventID,
		"timestamp":         rcpt.Timestamp.Format(time.RFC3339Nano),
		"verification":      "PASS",
	}
	summaryJSON, _ := json.MarshalIndent(summary, "", "  ")
	if err := writeFile(filepath.Join(absOut, "verification-result.json"), summaryJSON); err != nil {
		return err
	}

	fmt.Println("All artifacts generated and verified successfully.")
	return nil
}

func cleanGeneratedArtifacts(absOut string) error {
	for _, name := range []string{
		"candidate-contract.json",
		"contract-signing.pub",
		"receipt-signing.pub",
		"shadow-delta-receipt.json",
		"shadow.json",
		"shadow.md",
		"verification-result.json",
		"sessions",
		"recorder",
	} {
		path := filepath.Join(absOut, name)
		if err := os.RemoveAll(path); err != nil {
			return fmt.Errorf("remove generated artifact %s: %w", name, err)
		}
	}
	return nil
}

// buildCaptureEntry creates a deterministic recorder entry with a capture
// summary, matching the format that capture.LoadAndReplay expects.
func buildCaptureEntry() recorder.Entry {
	summary := capture.CaptureSummary{
		CaptureSchemaVersion: capture.CaptureSchemaV1,
		Surface:              capture.SurfaceURL,
		Subsurface:           "url",
		ConfigHash:           "sha256:example-config",
		BuildVersion:         "example",
		BuildSHA:             "example",
		Agent:                "agent-a",
		Profile:              "default",
		TransformKind:        capture.TransformRaw,
		Request: capture.CaptureRequest{
			Method: http.MethodGet,
			URL:    "https://api.vendor.example/repos/bar",
		},
		EffectiveAction: config.ActionAllow,
		Outcome:         capture.OutcomeClean,
	}

	detailJSON, _ := json.Marshal(summary)
	var detail any
	_ = json.Unmarshal(detailJSON, &detail)

	entry := recorder.Entry{
		Version:   recorder.EntryVersion,
		Sequence:  0,
		Timestamp: captureTime,
		SessionID: "session-a",
		Type:      capture.EntryTypeCapture,
		EventKind: capture.SurfaceURL,
		Transport: "http",
		Summary:   "url: GET https://api.vendor.example/repos/bar -> allow",
		Detail:    detail,
		PrevHash:  recorder.GenesisHash,
	}
	entry.Hash = recorder.ComputeHash(entry)
	return entry
}

func buildContractBody() contract.Contract {
	return contract.Contract{
		SchemaVersion:    contract.SchemaVersionContract,
		ContractKind:     contract.ContractKind,
		ContractHash:     "sha256:example-contract",
		SignerKeyID:      "example-signer",
		KeyPurpose:       signing.PurposeContractCompileSigning.String(),
		DataClassRoot:    string(contract.DataClassInternal),
		FieldDataClasses: map[string]string{},
		Selector:         contract.Selector{Agent: "agent-a", SelectorID: "selector-a"},
		ObservationWindow: contract.ObservationWindow{
			Start:                 time.Date(2026, 4, 30, 11, 0, 0, 0, time.UTC),
			End:                   time.Date(2026, 4, 30, 12, 0, 0, 0, time.UTC),
			EventCount:            1,
			SessionCount:          1,
			ObservationWindowRoot: "sha256:example-window",
		},
		Compile: contract.ContractCompile{
			PipelockVersion:        "example",
			PipelockBuildSHA:       "example",
			GoVersion:              "example",
			ModuleDigestRoot:       "sha256:example-modules",
			CompileConfigHash:      "sha256:example-compile-config",
			InferenceAlgorithm:     "example",
			NormalizationAlgorithm: "example",
		},
		Defaults: contract.ContractDefaults{
			Fidelity:   "full",
			Confidence: map[string]any{},
			Privacy: contract.ContractDefaultsPrivacy{
				DefaultDataClass: contract.DataClassInternal,
				ForbidClasses:    []contract.DataClass{},
			},
		},
		Rules: []contract.Rule{{
			RuleID:               "rule-api",
			DisplayName:          "API access rule",
			RuleKind:             "http_destination",
			LifecycleState:       "enforce",
			RequiredCaptureGrade: contract.CaptureGradeFull,
			ObservedCaptureGrade: contract.CaptureGradeFull,
			Confidence:           "stable",
			WilsonLower:          "0.99",
			Observation:          map[string]any{},
			Selector: map[string]any{
				"host": map[string]any{"value": "api.vendor.example"},
				"paths": []any{
					map[string]any{"value": "/repos/foo"},
				},
			},
			Rationale:         map[string]any{},
			RecurringSupport:  map[string]any{},
			OpportunityHealth: map[string]any{},
		}},
	}
}

func extractReceipt(recorderDir string) ([]byte, error) {
	var receiptJSON []byte
	err := filepath.WalkDir(recorderDir, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil || d.IsDir() {
			return walkErr
		}
		if !strings.HasSuffix(d.Name(), ".jsonl") {
			return nil
		}
		entries, readErr := recorder.ReadEntries(path)
		if readErr != nil {
			return readErr
		}
		for _, entry := range entries {
			if entry.Type != "evidence_receipt" {
				continue
			}
			detailBytes, marshalErr := json.Marshal(entry.Detail)
			if marshalErr != nil {
				return fmt.Errorf("marshal evidence_receipt detail: %w", marshalErr)
			}
			var rcpt contractreceipt.EvidenceReceipt
			if unmarshalErr := json.Unmarshal(detailBytes, &rcpt); unmarshalErr != nil {
				return fmt.Errorf("unmarshal evidence_receipt detail: %w", unmarshalErr)
			}
			if rcpt.PayloadKind == contractreceipt.PayloadShadowDelta {
				receiptJSON = detailBytes
			}
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk recorder: %w", err)
	}
	if receiptJSON == nil {
		return nil, fmt.Errorf("no shadow_delta receipt found in recorder output")
	}
	return receiptJSON, nil
}

type deterministicSigner struct {
	keyID string
	key   ed25519.PrivateKey
}

func (s deterministicSigner) KeyID() string                   { return s.keyID }
func (s deterministicSigner) Sign(msg []byte) ([]byte, error) { return ed25519.Sign(s.key, msg), nil }

func filterDuration(records []capture.ReplayedRecord, now time.Time, duration time.Duration) []capture.ReplayedRecord {
	cutoff := now.Add(-duration)
	filtered := records[:0]
	for _, record := range records {
		if record.Timestamp.IsZero() || !record.Timestamp.Before(cutoff) {
			filtered = append(filtered, record)
		}
	}
	return filtered
}

func marshalEntry(e recorder.Entry) ([]byte, error) {
	data, err := json.Marshal(e)
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func writeFile(path string, data []byte) error {
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", filepath.Base(path), err)
	}
	fmt.Printf("wrote %s\n", path)
	return nil
}

func indentJSON(data []byte) ([]byte, error) {
	var raw json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return data, err
	}
	return json.MarshalIndent(raw, "", "  ")
}
