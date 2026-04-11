// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package posture emits signed posture capsules for the current pipelock state.
package posture

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/atomicfile"
	"github.com/luckyPipewrench/pipelock/internal/cli/audit"
	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/discover"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

const (
	// SchemaVersion is the posture capsule schema version.
	SchemaVersion = "1"

	// DefaultExpirationDays is the default validity period for posture capsules.
	DefaultExpirationDays = 30

	// DefaultOutputDir is the default output directory for posture artifacts.
	DefaultOutputDir = ".pipelock/posture"

	// ProofFilename is the JSON artifact written by posture emit.
	ProofFilename = "proof.json"
)

// Capsule is the signed posture artifact emitted by pipelock posture emit.
type Capsule struct {
	SchemaVersion string         `json:"schema_version"`
	GeneratedAt   time.Time      `json:"generated_at"`
	ExpiresAt     time.Time      `json:"expires_at"`
	ToolVersion   string         `json:"tool_version"`
	ConfigHash    string         `json:"config_hash"`
	Evidence      EvidenceBundle `json:"evidence"`
	Signature     string         `json:"signature"`
	SignerKeyID   string         `json:"signer_key_id"`
}

// EvidenceBundle contains the raw posture evidence collected at emit time.
type EvidenceBundle struct {
	Discover       DiscoverEvidence      `json:"discover"`
	VerifyInstall  VerifyInstallEvidence `json:"verify_install"`
	Simulate       audit.SimulateResult  `json:"simulate"`
	FlightRecorder FlightRecorderCounts  `json:"flight_recorder"`
}

// DiscoverEvidence captures high-level MCP protection counts.
type DiscoverEvidence struct {
	TotalClients      int `json:"total_clients"`
	TotalServers      int `json:"total_servers"`
	ProtectedPipelock int `json:"protected_pipelock"`
	ProtectedOther    int `json:"protected_other"`
	Unprotected       int `json:"unprotected"`
	Unknown           int `json:"unknown"`
	HighRisk          int `json:"high_risk"`
	ParseErrors       int `json:"parse_errors"`
}

// VerifyInstallEvidence captures whether pipelock appears to be actively proxying.
type VerifyInstallEvidence struct {
	FlightRecorderActive bool `json:"flight_recorder_active"`
	ReceiptCount         int  `json:"receipt_count"`
	Proxying             bool `json:"proxying"`
}

// FlightRecorderCounts summarizes signed receipt activity.
type FlightRecorderCounts struct {
	ReceiptCount   int                     `json:"receipt_count"`
	LastReceiptAt  *time.Time              `json:"last_receipt_at,omitempty"`
	ScannerVerdict map[string]VerdictCount `json:"scanner_verdict"`
}

// VerdictCount tracks allow/block/warn verdicts for one scanner layer.
type VerdictCount struct {
	Allow int `json:"allow"`
	Block int `json:"block"`
	Warn  int `json:"warn"`
}

// Options configures posture capsule emission.
type Options struct {
	ExpirationDays int
	SigningKey     ed25519.PrivateKey
	EvidenceBundle *EvidenceBundle
}

type signableCapsule struct {
	SchemaVersion string         `json:"schema_version"`
	GeneratedAt   time.Time      `json:"generated_at"`
	ExpiresAt     time.Time      `json:"expires_at"`
	ToolVersion   string         `json:"tool_version"`
	ConfigHash    string         `json:"config_hash"`
	Evidence      EvidenceBundle `json:"evidence"`
	// SignerKeyID is intentionally excluded: the signature cannot cover its own
	// verification key identifier. Verify() pins the trusted public key and
	// separately checks SignerKeyID as a defense-in-depth consistency check.
}

// Emit builds and signs a posture capsule from the current state.
func Emit(cfg *config.Config, opts Options) (*Capsule, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config is required")
	}

	opts = opts.withDefaults()

	privKey, err := resolveSigningKey(cfg, opts.SigningKey)
	if err != nil {
		return nil, err
	}

	evidence, err := resolveEvidence(cfg, opts.EvidenceBundle)
	if err != nil {
		return nil, err
	}

	configHash, err := hashConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("hash config: %w", err)
	}

	now := time.Now().UTC()
	capsule := &Capsule{
		SchemaVersion: SchemaVersion,
		GeneratedAt:   now,
		ExpiresAt:     now.AddDate(0, 0, opts.ExpirationDays),
		ToolVersion:   cliutil.Version,
		ConfigHash:    configHash,
		Evidence:      evidence,
		SignerKeyID:   hex.EncodeToString(privKey.Public().(ed25519.PublicKey)),
	}

	payload, err := capsule.signableJSON()
	if err != nil {
		return nil, fmt.Errorf("marshal signable capsule: %w", err)
	}

	capsule.Signature = hex.EncodeToString(ed25519.Sign(privKey, payload))
	return capsule, nil
}

// Verify validates the capsule signature, expiration, and schema version.
func Verify(capsule *Capsule, trustedKey ed25519.PublicKey) error {
	if capsule == nil {
		return fmt.Errorf("capsule is required")
	}
	if capsule.SchemaVersion != SchemaVersion {
		return fmt.Errorf("unsupported schema_version %q", capsule.SchemaVersion)
	}
	if len(trustedKey) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid trusted key length: got %d, want %d", len(trustedKey), ed25519.PublicKeySize)
	}
	if capsule.ExpiresAt.Before(time.Now().UTC()) {
		return fmt.Errorf("capsule expired at %s", capsule.ExpiresAt.Format(time.RFC3339))
	}
	if capsule.Signature == "" {
		return fmt.Errorf("capsule signature is required")
	}

	expectedKeyID := hex.EncodeToString(trustedKey)
	if capsule.SignerKeyID != expectedKeyID {
		return fmt.Errorf("signer_key_id %q does not match trusted key", capsule.SignerKeyID)
	}

	sig, err := hex.DecodeString(capsule.Signature)
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}
	if len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("invalid signature length: got %d, want %d", len(sig), ed25519.SignatureSize)
	}

	payload, err := capsule.signableJSON()
	if err != nil {
		return fmt.Errorf("marshal signable capsule: %w", err)
	}
	if !ed25519.Verify(trustedKey, payload, sig) {
		return fmt.Errorf("signature verification failed")
	}
	return nil
}

// WriteProofJSON writes proof.json atomically into the output directory.
func WriteProofJSON(outputDir string, capsule *Capsule) (string, error) {
	if capsule == nil {
		return "", fmt.Errorf("capsule is required")
	}

	cleanDir := filepath.Clean(outputDir)
	if err := os.MkdirAll(cleanDir, 0o750); err != nil {
		return "", fmt.Errorf("create output directory: %w", err)
	}

	data, err := json.Marshal(capsule)
	if err != nil {
		return "", fmt.Errorf("marshal capsule: %w", err)
	}
	data = append(data, '\n')

	path := filepath.Join(cleanDir, ProofFilename)
	if err := atomicfile.Write(path, data, 0o600); err != nil {
		return "", fmt.Errorf("write %s: %w", ProofFilename, err)
	}
	return path, nil
}

// MarshalJSON emits deterministic canonical JSON for signature stability.
func (c Capsule) MarshalJSON() ([]byte, error) {
	type alias Capsule
	return canonicalJSON(alias(c))
}

// UnmarshalJSON decodes a posture capsule from JSON.
func (c *Capsule) UnmarshalJSON(data []byte) error {
	type alias Capsule
	var raw alias
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	*c = Capsule(raw)
	return nil
}

func (o Options) withDefaults() Options {
	if o.ExpirationDays <= 0 {
		o.ExpirationDays = DefaultExpirationDays
	}
	return o
}

func resolveSigningKey(cfg *config.Config, key ed25519.PrivateKey) (ed25519.PrivateKey, error) {
	if len(key) == ed25519.PrivateKeySize {
		return key, nil
	}

	keyPath := filepath.Clean(cfg.FlightRecorder.SigningKeyPath)
	if keyPath == "." || cfg.FlightRecorder.SigningKeyPath == "" {
		return nil, fmt.Errorf("flight_recorder.signing_key_path is required")
	}

	privKey, err := signing.LoadPrivateKeyFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("load signing key: %w", err)
	}
	return privKey, nil
}

func resolveEvidence(cfg *config.Config, preload *EvidenceBundle) (EvidenceBundle, error) {
	if preload != nil {
		return *preload, nil
	}
	return collectEvidence(cfg)
}

func collectEvidence(cfg *config.Config) (EvidenceBundle, error) {
	discoverEvidence, err := collectDiscoverEvidence()
	if err != nil {
		return EvidenceBundle{}, err
	}

	simulateEvidence, err := collectSimulateEvidence(cfg)
	if err != nil {
		return EvidenceBundle{}, err
	}

	flightRecorderEvidence, err := collectFlightRecorderEvidence(cfg)
	if err != nil {
		return EvidenceBundle{}, err
	}

	verifyInstallEvidence := VerifyInstallEvidence{
		FlightRecorderActive: cfg.FlightRecorder.Enabled && cfg.FlightRecorder.Dir != "" && flightRecorderEvidence.ScannerVerdict != nil,
		ReceiptCount:         flightRecorderEvidence.ReceiptCount,
		Proxying:             cfg.FlightRecorder.Enabled && flightRecorderEvidence.ReceiptCount > 0,
	}

	return EvidenceBundle{
		Discover:       discoverEvidence,
		VerifyInstall:  verifyInstallEvidence,
		Simulate:       simulateEvidence,
		FlightRecorder: flightRecorderEvidence,
	}, nil
}

func collectDiscoverEvidence() (DiscoverEvidence, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return DiscoverEvidence{}, fmt.Errorf("resolve home directory: %w", err)
	}

	report, err := discover.Discover(home)
	if err != nil {
		return DiscoverEvidence{}, fmt.Errorf("discover: %w", err)
	}

	return DiscoverEvidence{
		TotalClients:      report.Summary.TotalClients,
		TotalServers:      report.Summary.TotalServers,
		ProtectedPipelock: report.Summary.ProtectedPipelock,
		ProtectedOther:    report.Summary.ProtectedOther,
		Unprotected:       report.Summary.Unprotected,
		Unknown:           report.Summary.Unknown,
		HighRisk:          report.Summary.HighRisk,
		ParseErrors:       report.Summary.ParseErrors,
	}, nil
}

func collectSimulateEvidence(cfg *config.Config) (audit.SimulateResult, error) {
	sc := scanner.New(cfg)
	defer sc.Close()

	scenarios := audit.BuildSimScenarios(cfg, sc)
	return audit.RunSimulation(scenarios, "", cfg.Mode), nil
}

func collectFlightRecorderEvidence(cfg *config.Config) (FlightRecorderCounts, error) {
	result := FlightRecorderCounts{
		ScannerVerdict: make(map[string]VerdictCount),
	}

	if cfg.FlightRecorder.Dir == "" {
		return result, nil
	}

	dir := filepath.Clean(cfg.FlightRecorder.Dir)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return result, nil
		}
		return FlightRecorderCounts{}, fmt.Errorf("read flight recorder dir: %w", err)
	}

	var files []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if filepath.Ext(name) == ".jsonl" && len(name) >= len("evidence-") && name[:len("evidence-")] == "evidence-" {
			files = append(files, filepath.Join(dir, name))
		}
	}
	sort.Strings(files)

	var lastReceipt time.Time
	for _, file := range files {
		records, err := recorder.ReadEntries(file)
		if err != nil {
			return FlightRecorderCounts{}, fmt.Errorf("read recorder file %s: %w", filepath.Base(file), err)
		}
		for _, record := range records {
			if record.Type != "action_receipt" {
				continue
			}

			detailJSON, err := json.Marshal(record.Detail)
			if err != nil {
				return FlightRecorderCounts{}, fmt.Errorf("marshal receipt detail: %w", err)
			}
			rcpt, err := receipt.Unmarshal(detailJSON)
			if err != nil {
				return FlightRecorderCounts{}, fmt.Errorf("decode receipt detail: %w", err)
			}

			result.ReceiptCount++
			if rcpt.ActionRecord.Timestamp.After(lastReceipt) {
				lastReceipt = rcpt.ActionRecord.Timestamp
			}

			layer := rcpt.ActionRecord.Layer
			if layer == "" {
				layer = "unknown"
			}
			counts := result.ScannerVerdict[layer]
			switch rcpt.ActionRecord.Verdict {
			case config.ActionAllow:
				counts.Allow++
			case config.ActionBlock:
				counts.Block++
			case config.ActionWarn:
				counts.Warn++
			}
			result.ScannerVerdict[layer] = counts
		}
	}

	if !lastReceipt.IsZero() {
		lastReceipt = lastReceipt.UTC()
		result.LastReceiptAt = &lastReceipt
	}

	return result, nil
}

func hashConfig(cfg *config.Config) (string, error) {
	canonical, err := canonicalJSON(cfg)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}

func (c Capsule) signableJSON() ([]byte, error) {
	return canonicalJSON(signableCapsule{
		SchemaVersion: c.SchemaVersion,
		GeneratedAt:   c.GeneratedAt,
		ExpiresAt:     c.ExpiresAt,
		ToolVersion:   c.ToolVersion,
		ConfigHash:    c.ConfigHash,
		Evidence:      c.Evidence,
	})
}

func canonicalJSON(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}

	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()

	var parsed any
	if err := dec.Decode(&parsed); err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	if err := appendCanonical(&buf, parsed); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func appendCanonical(buf *bytes.Buffer, v any) error {
	switch value := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if value {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case string:
		data, err := json.Marshal(value)
		if err != nil {
			return err
		}
		buf.Write(data)
	case json.Number:
		buf.WriteString(value.String())
	case float64:
		data, err := json.Marshal(value)
		if err != nil {
			return err
		}
		buf.Write(data)
	case []any:
		buf.WriteByte('[')
		for i, item := range value {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := appendCanonical(buf, item); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case map[string]any:
		buf.WriteByte('{')
		keys := make([]string, 0, len(value))
		for key := range value {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for i, key := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			keyJSON, err := json.Marshal(key)
			if err != nil {
				return err
			}
			buf.Write(keyJSON)
			buf.WriteByte(':')
			if err := appendCanonical(buf, value[key]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		data, err := json.Marshal(value)
		if err != nil {
			return err
		}
		buf.Write(data)
	}
	return nil
}
