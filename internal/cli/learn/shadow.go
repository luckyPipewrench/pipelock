// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package learn

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/atomicfile"
	"github.com/luckyPipewrench/pipelock/internal/capture"
	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/contract"
	"github.com/luckyPipewrench/pipelock/internal/contract/shadow"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

const defaultReceiptKeyAgent = "receipt-signing"

type shadowFlags struct {
	contractPath  string
	contractKey   string
	allowUnsigned bool
	configPath    string
	sessionsDir   string
	agent         string
	duration      time.Duration
	outPath       string
	outJSONPath   string
	recorderDir   string
	escrowKeyHex  string
	keystore      string
	receiptKey    string
	deterministic bool
}

func shadowCmd() *cobra.Command {
	var flags shadowFlags
	flags.duration = 7 * 24 * time.Hour
	cmd := &cobra.Command{
		Use:   "shadow",
		Short: "Replay observations against a candidate contract and emit shadow deltas",
		Long: `Replay captured observations against a signed candidate contract, summarize
candidate-vs-original verdict deltas, and optionally persist signed shadow_delta
receipts into a recorder chain.

Use --sessions for an explicit capture sessions directory. Without --sessions,
provide --agent and configure learn.capture_dir; the command reads
<capture_dir>/<agent>.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runShadow(cmd, flags)
		},
	}
	cmd.Flags().StringVar(&flags.contractPath, "contract", "", "signed candidate contract YAML (required, absolute)")
	cmd.Flags().StringVar(&flags.contractKey, "contract-key", "", "trusted Ed25519 public key (hex or file) used to verify --contract")
	cmd.Flags().BoolVar(&flags.allowUnsigned, "allow-unsigned-contract-for-diagnostics", false, "allow unverified --contract input for diagnostics only (unsafe)")
	cmd.Flags().StringVar(&flags.configPath, "config", "", "path to pipelock config file")
	cmd.Flags().StringVar(&flags.sessionsDir, "sessions", "", "capture sessions directory (absolute)")
	cmd.Flags().StringVar(&flags.agent, "agent", "", "agent name used with learn.capture_dir when --sessions is omitted")
	cmd.Flags().DurationVar(&flags.duration, "duration", flags.duration, "lookback duration for captured observations")
	cmd.Flags().StringVar(&flags.outPath, "out", "", "markdown report output path; empty writes markdown to stdout")
	cmd.Flags().StringVar(&flags.outJSONPath, "out-json", "", "JSON report output path")
	cmd.Flags().StringVar(&flags.recorderDir, "recorder-dir", "", "recorder directory for signed shadow_delta receipts")
	cmd.Flags().StringVar(&flags.escrowKeyHex, "escrow-private-key", "", "X25519 hex private key for sidecar decryption")
	cmd.Flags().StringVar(&flags.keystore, "keystore", "", "keystore directory for receipt signing")
	cmd.Flags().StringVar(&flags.receiptKey, "receipt-key-agent", defaultReceiptKeyAgent, "keystore agent name for receipt signing")
	cmd.Flags().BoolVar(&flags.deterministic, "deterministic", false, "use deterministic fixtures for reproducible reports")
	_ = cmd.MarkFlagRequired("contract")
	return cmd
}

func runShadow(cmd *cobra.Command, flags shadowFlags) error {
	if flags.duration <= 0 {
		return fmt.Errorf("learn shadow: --duration must be positive")
	}
	cfg, err := loadConfig(flags.configPath)
	if err != nil {
		return err
	}
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false

	env, contractPath, verified, err := loadShadowContract(flags.contractPath, flags.contractKey, flags.allowUnsigned)
	if err != nil {
		return err
	}
	if !verified {
		_, _ = fmt.Fprintln(cmd.ErrOrStderr(), "warning: unverified contract accepted because --allow-unsigned-contract-for-diagnostics is set; shadow replay is diagnostic only")
	}
	sessionsDir, err := resolveShadowSessions(cfg, flags)
	if err != nil {
		return err
	}
	escrow, err := decodeOptionalHex(flags.escrowKeyHex)
	if err != nil {
		return err
	}
	records, _, _, _, err := capture.LoadAndReplayWithOptions(cfg, sessionsDir, capture.ReplayOptions{
		EscrowPrivateKey: escrow,
		Contract:         &env.Body,
		SessionFilter:    shadowSessionFilter(flags),
	})
	if err != nil {
		return fmt.Errorf("learn shadow: replay captures: %w", err)
	}
	now := time.Now().UTC()
	if flags.deterministic {
		now = time.Date(2026, 4, 30, 12, 0, 0, 0, time.UTC)
	}
	records = filterShadowDuration(records, now, flags.duration)
	report, err := shadow.Analyze(records, shadow.AnalyzeOptions{
		ContractHash: contractHash(env.Body),
		GeneratedAt:  now,
		Aggregation:  shadow.DefaultAggregateConfig(),
		Quarantine:   shadow.DefaultQuarantineConfig(),
	})
	if err != nil {
		return err
	}
	if err := writeShadowReports(cmd, report, flags); err != nil {
		return err
	}
	receiptsEmitted, err := emitShadowReceipts(flags, env.Body, report, now)
	if err != nil {
		return err
	}

	emitAuditEvent(cmd, auditEvent{
		Event:           "learn_shadow",
		Candidate:       contractPath,
		Agent:           flags.agent,
		Sessions:        sessionsDir,
		Output:          flags.outPath,
		Review:          flags.outJSONPath,
		RecorderDir:     flags.recorderDir,
		EventsIngested:  report.TotalRecords,
		RulesEmitted:    len(report.Batches),
		Quarantines:     len(report.Quarantines),
		ReceiptsEmitted: receiptsEmitted,
		NoOp:            report.Changed == 0,
	})
	return nil
}

func loadShadowContract(path, publicKey string, allowUnsigned bool) (contract.ContractEnvelope, string, bool, error) {
	clean, doc, err := loadCandidate(path)
	if err != nil {
		return contract.ContractEnvelope{}, "", false, err
	}
	raw, err := yamlBytes(doc)
	if err != nil {
		return contract.ContractEnvelope{}, "", false, err
	}
	var env contract.ContractEnvelope
	if err := contract.DecodeStrictYAML(raw, &env); err != nil {
		return contract.ContractEnvelope{}, "", false, fmt.Errorf("learn shadow: decode contract: %w", err)
	}
	if err := env.Body.Validate(); err != nil {
		return contract.ContractEnvelope{}, "", false, fmt.Errorf("learn shadow: validate contract: %w", err)
	}
	if publicKey == "" {
		if !allowUnsigned {
			return contract.ContractEnvelope{}, "", false,
				fmt.Errorf("learn shadow: --contract-key is required for --contract (or use --allow-unsigned-contract-for-diagnostics)")
		}
		return env, clean, false, nil
	}
	pubKey, err := signing.LoadPublicKey(publicKey)
	if err != nil {
		return contract.ContractEnvelope{}, "", false, fmt.Errorf("learn shadow: load contract verification key: %w", err)
	}
	if err := verifyShadowContractEnvelope(env, pubKey); err != nil {
		return contract.ContractEnvelope{}, "", false, fmt.Errorf("learn shadow: verify contract: %w", err)
	}
	return env, clean, true, nil
}

func verifyShadowContractEnvelope(env contract.ContractEnvelope, pubKey ed25519.PublicKey) error {
	if env.Body.KeyPurpose != signing.PurposeContractCompileSigning.String() {
		return fmt.Errorf("key_purpose must be %q, got %q", signing.PurposeContractCompileSigning.String(), env.Body.KeyPurpose)
	}
	if !strings.HasPrefix(env.Signature, "ed25519:") {
		return fmt.Errorf("signature must use ed25519:<hex>")
	}
	sig, err := hex.DecodeString(strings.TrimPrefix(env.Signature, "ed25519:"))
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}
	if len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("signature length=%d, want %d", len(sig), ed25519.SignatureSize)
	}
	preimage, err := env.Body.SignablePreimage()
	if err != nil {
		return fmt.Errorf("build preimage: %w", err)
	}
	if !ed25519.Verify(pubKey, preimage, sig) {
		return fmt.Errorf("signature verification failed")
	}
	return nil
}

func resolveShadowSessions(cfg *config.Config, flags shadowFlags) (string, error) {
	if flags.sessionsDir != "" {
		return checkedReadDir(flags.sessionsDir)
	}
	if err := validateCompileAgent(flags.agent); err != nil {
		return "", err
	}
	if cfg.Learn.CaptureDir == "" {
		return "", errNoCaptureDir
	}
	if !filepath.IsAbs(filepath.Clean(cfg.Learn.CaptureDir)) {
		return "", errRelativeCaptureDir
	}
	root, err := checkedReadDir(cfg.Learn.CaptureDir)
	if err != nil {
		return "", err
	}
	matched, err := hasMatchingCaptureSession(root, flags.agent)
	if err != nil {
		return "", fmt.Errorf("%w: scan capture sessions: %w", ErrInvalidCandidate, err)
	}
	if !matched {
		return "", fmt.Errorf("%w: no capture sessions matched agent %q", ErrInvalidCandidate, flags.agent)
	}
	return root, nil
}

func shadowSessionFilter(flags shadowFlags) func(name, sessionDir string) bool {
	if flags.sessionsDir != "" {
		return nil
	}
	return func(sessionName, sessionDir string) bool {
		if !captureSessionNameMatchesAgent(sessionName, flags.agent) {
			return false
		}
		// Defense in depth: name-prefix match alone lets a planted sibling
		// directory poison shadow replay. Require the first capture entry's
		// self-attested agent to match before the session is replayed against
		// the candidate contract.
		return validateCaptureSessionDir(sessionDir, flags.agent)
	}
}

func hasMatchingCaptureSession(root, agent string) (bool, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return false, err
	}
	for _, entry := range entries {
		if !entry.IsDir() || !captureSessionNameMatchesAgent(entry.Name(), agent) {
			continue
		}
		if !validateCaptureSessionDir(filepath.Join(root, entry.Name()), agent) {
			continue
		}
		return true, nil
	}
	return false, nil
}

func checkedReadDir(path string) (string, error) {
	clean := filepath.Clean(path)
	if !filepath.IsAbs(clean) {
		return "", fmt.Errorf("%w: sessions dir must be absolute: %s", ErrInvalidCandidate, path)
	}
	info, err := os.Lstat(clean)
	if err != nil {
		return "", fmt.Errorf("%w: inspect sessions dir: %w", ErrInvalidCandidate, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("%w: sessions dir must not be a symlink: %s", ErrInvalidCandidate, clean)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("%w: sessions dir must be a directory: %s", ErrInvalidCandidate, clean)
	}
	return clean, nil
}

func filterShadowDuration(records []capture.ReplayedRecord, now time.Time, duration time.Duration) []capture.ReplayedRecord {
	cutoff := now.Add(-duration)
	filtered := records[:0]
	for _, record := range records {
		if record.Timestamp.IsZero() || !record.Timestamp.Before(cutoff) {
			filtered = append(filtered, record)
		}
	}
	return filtered
}

func emitShadowReceipts(flags shadowFlags, body contract.Contract, report shadow.Report, now time.Time) (int, error) {
	if flags.recorderDir == "" || len(report.Batches) == 0 {
		return 0, nil
	}
	recorderDir, err := checkedWriteDir(flags.recorderDir)
	if err != nil {
		return 0, err
	}
	signer, err := resolveShadowSigner(flags)
	if err != nil {
		return 0, err
	}
	rec, err := recorder.New(recorder.Config{
		Enabled:            true,
		Dir:                recorderDir,
		CheckpointInterval: 1000,
		MaxEntriesPerFile:  10000,
		Redact:             true,
	}, nil, nil)
	if err != nil {
		return 0, fmt.Errorf("learn shadow: open recorder: %w", err)
	}
	defer func() { _ = rec.Close() }()
	emitter := shadow.NewEmitter(shadow.EmitterConfig{
		Recorder:           rec,
		Signer:             signer,
		Principal:          "learn",
		Actor:              "shadow",
		ActiveManifestHash: body.ContractHash,
		SelectorID:         body.Selector.SelectorID,
		Clock: func() time.Time {
			return now
		},
	})
	for i, batch := range report.Batches {
		if err := emitter.EmitBatch(batch); err != nil {
			return i, err
		}
	}
	return len(report.Batches), nil
}

func checkedWriteDir(path string) (string, error) {
	clean := filepath.Clean(path)
	if !filepath.IsAbs(clean) {
		return "", fmt.Errorf("%w: recorder dir must be absolute: %s", ErrInvalidCandidate, path)
	}
	if err := os.MkdirAll(clean, 0o750); err != nil {
		return "", fmt.Errorf("learn shadow: mkdir recorder dir: %w", err)
	}
	info, err := os.Lstat(clean)
	if err != nil {
		return "", fmt.Errorf("%w: inspect recorder dir: %w", ErrInvalidCandidate, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("%w: recorder dir must not be a symlink: %s", ErrInvalidCandidate, clean)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("%w: recorder dir must be a directory: %s", ErrInvalidCandidate, clean)
	}
	return clean, nil
}

func resolveShadowSigner(flags shadowFlags) (privateKeySigner, error) {
	if flags.deterministic {
		seed := sha256.Sum256([]byte("pipelock deterministic shadow receipt signer"))
		return privateKeySigner{keyID: "deterministic-receipt-signing", key: ed25519.NewKeyFromSeed(seed[:])}, nil
	}
	keyAgent := flags.receiptKey
	if keyAgent == "" {
		keyAgent = defaultReceiptKeyAgent
	}
	dir, err := cliutil.ResolveKeystoreDir(flags.keystore)
	if err != nil {
		return privateKeySigner{}, err
	}
	priv, err := signing.NewKeystore(dir).LoadPrivateKey(keyAgent)
	if err != nil {
		return privateKeySigner{}, fmt.Errorf("load receipt signing key for %q: %w", keyAgent, err)
	}
	return privateKeySigner{keyID: keyAgent, key: priv}, nil
}

func writeShadowReports(cmd *cobra.Command, report shadow.Report, flags shadowFlags) error {
	var markdown strings.Builder
	if err := shadow.RenderMarkdown(&markdown, report); err != nil {
		return err
	}
	if flags.outPath == "" {
		_, _ = fmt.Fprint(cmd.OutOrStdout(), markdown.String())
	} else {
		dest, err := checkedWritePath(filepath.Clean(flags.outPath))
		if err != nil {
			return err
		}
		if err := atomicfile.Write(dest, []byte(markdown.String()), 0o600); err != nil {
			return fmt.Errorf("learn shadow: write markdown report: %w", err)
		}
	}
	if flags.outJSONPath != "" {
		var data strings.Builder
		if err := shadow.RenderJSON(&data, report); err != nil {
			return err
		}
		dest, err := checkedWritePath(filepath.Clean(flags.outJSONPath))
		if err != nil {
			return err
		}
		if err := atomicfile.Write(dest, []byte(data.String()), 0o600); err != nil {
			return fmt.Errorf("learn shadow: write JSON report: %w", err)
		}
	}
	return nil
}

func contractHash(body contract.Contract) string {
	if body.ContractHash != "" {
		return body.ContractHash
	}
	preimage, err := body.SignablePreimage()
	if err != nil {
		return "sha256:unknown"
	}
	sum := sha256.Sum256(preimage)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func readShadowReport(path string) (shadow.Report, error) {
	clean := filepath.Clean(path)
	if !filepath.IsAbs(clean) {
		return shadow.Report{}, fmt.Errorf("%w: report path must be absolute: %s", ErrInvalidCandidate, path)
	}
	data, err := safeReadCandidate(clean)
	if err != nil {
		return shadow.Report{}, err
	}
	var report shadow.Report
	if err := json.Unmarshal(data, &report); err != nil {
		return shadow.Report{}, fmt.Errorf("learn diff: decode report: %w", err)
	}
	return report, nil
}
