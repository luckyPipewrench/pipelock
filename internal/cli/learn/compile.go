// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package learn

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/atomicfile"
	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/contract"
	"github.com/luckyPipewrench/pipelock/internal/contract/inference"
	contractcompile "github.com/luckyPipewrench/pipelock/internal/contract/inference/compile"
	"github.com/luckyPipewrench/pipelock/internal/contract/inference/normalize"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

var (
	errCompileInput = errors.New("learn compile: invalid input")
	errCompileWrite = errors.New("learn compile: invalid output path")
)

type compileFlags struct {
	since           time.Duration
	agent           string
	inputGlob       string
	output          string
	review          string
	manifest        string
	configPath      string
	escrowKeyHex    string
	deterministic   bool
	keystore        string
	compileKeyAgent string
}

func compileCmd() *cobra.Command {
	var flags compileFlags
	flags.since = 14 * 24 * time.Hour
	cmd := &cobra.Command{
		Use:   "compile",
		Short: "Compile recorder observations into a signed candidate contract",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runCompile(cmd, flags)
		},
	}
	cmd.Flags().DurationVar(&flags.since, "since", flags.since, "lookback duration for capture-dir discovery")
	cmd.Flags().StringVar(&flags.agent, "agent", "", "agent name to compile (required)")
	cmd.Flags().StringVar(&flags.inputGlob, "input", "", "explicit recorder JSONL glob")
	cmd.Flags().StringVar(&flags.output, "output", "", "candidate YAML output path")
	cmd.Flags().StringVar(&flags.review, "review", "", "review markdown output path")
	cmd.Flags().StringVar(&flags.manifest, "compile-manifest", "", "compile manifest output path")
	cmd.Flags().StringVar(&flags.configPath, "config", "", "path to pipelock config file")
	cmd.Flags().StringVar(&flags.escrowKeyHex, "escrow-private-key", "", "hex escrow private key for full-fidelity dimensions")
	cmd.Flags().BoolVar(&flags.deterministic, "deterministic", false, "use deterministic fixtures for reproducible recompile")
	cmd.Flags().StringVar(&flags.keystore, "keystore", "", "keystore directory for compile signing")
	cmd.Flags().StringVar(&flags.compileKeyAgent, "compile-key-agent", "", "keystore agent name for compile signing; defaults to --agent")
	_ = cmd.MarkFlagRequired("agent")
	return cmd
}

func runCompile(cmd *cobra.Command, flags compileFlags) error {
	if flags.deterministic {
		ensureEnvDefault("TZ", "UTC")
		ensureEnvDefault("LC_ALL", "C")
	}

	cfg, err := loadConfig(flags.configPath)
	if err != nil {
		return err
	}
	inputs, err := resolveCompileInputs(cfg, flags)
	if err != nil {
		return err
	}
	stream, refs, err := readCompileInputs(inputs)
	if err != nil {
		return err
	}
	output, reviewPath, manifestPath, err := resolveCompileOutputs(flags)
	if err != nil {
		return err
	}
	escrow, err := decodeOptionalHex(flags.escrowKeyHex)
	if err != nil {
		return err
	}
	signer, err := resolveCompileSigner(flags)
	if err != nil {
		return err
	}

	result, err := contractcompile.Compile(contractcompile.CompileInput{
		Stream:           stream,
		Config:           compileConfig(flags.agent, cfg, refs),
		EscrowPrivateKey: escrow,
	}, contractcompile.CompileOptions{
		Deterministic: flags.deterministic,
		Signer:        signer,
	})
	if err != nil {
		return err
	}

	if err := atomicfile.Write(output, result.YAML, 0o600); err != nil {
		return fmt.Errorf("write candidate: %w", err)
	}
	if err := atomicfile.Write(reviewPath, []byte(result.Review), 0o600); err != nil {
		return fmt.Errorf("write review: %w", err)
	}
	if err := atomicfile.Write(manifestPath, result.ManifestJSON, 0o600); err != nil {
		return fmt.Errorf("write compile manifest: %w", err)
	}

	emitAuditEvent(cmd, auditEvent{
		Event:          "learn_compile",
		Agent:          flags.agent,
		Since:          flags.since.String(),
		Inputs:         inputs,
		Output:         output,
		Review:         reviewPath,
		Manifest:       manifestPath,
		EventsIngested: result.Stats.EventsIngested,
		EventsDropped:  result.Stats.EventsDropped + result.Stats.EventsMalformed,
		RulesEmitted:   result.Stats.RulesEmitted,
		NoOp:           result.Stats.NoOp,
	})
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "compile: %d events, %d rules, written to %s\n", result.Stats.EventsIngested, result.Stats.RulesEmitted, output)
	return nil
}

func resolveCompileInputs(cfg *config.Config, flags compileFlags) ([]string, error) {
	var paths []string
	var err error
	if flags.inputGlob != "" {
		paths, err = filepath.Glob(flags.inputGlob)
		if err != nil {
			return nil, fmt.Errorf("%w: bad --input glob: %w", errCompileInput, err)
		}
	} else {
		if cfg.Learn.CaptureDir == "" {
			return nil, fmt.Errorf("%w: --input or learn.capture_dir is required", errCompileInput)
		}
		if !filepath.IsAbs(filepath.Clean(cfg.Learn.CaptureDir)) {
			return nil, fmt.Errorf("%w: learn.capture_dir must be absolute", errCompileInput)
		}
		paths, err = filepath.Glob(filepath.Join(cfg.Learn.CaptureDir, flags.agent, "*.jsonl"))
		if err != nil {
			return nil, fmt.Errorf("%w: capture glob: %w", errCompileInput, err)
		}
		cutoff := time.Now().Add(-flags.since)
		filtered := paths[:0]
		for _, path := range paths {
			info, statErr := os.Stat(filepath.Clean(path))
			if statErr == nil && !info.ModTime().Before(cutoff) {
				filtered = append(filtered, path)
			}
		}
		paths = filtered
	}
	sort.Strings(paths)
	if len(paths) == 0 {
		return nil, fmt.Errorf("%w: no recorder JSONL inputs matched", errCompileInput)
	}
	for _, path := range paths {
		clean := filepath.Clean(path)
		if !filepath.IsAbs(clean) {
			return nil, fmt.Errorf("%w: input path must be absolute: %s", errCompileInput, path)
		}
	}
	return paths, nil
}

func readCompileInputs(paths []string) (*bytes.Reader, []contract.InputRef, error) {
	var buf bytes.Buffer
	refs := make([]contract.InputRef, 0, len(paths))
	for _, path := range paths {
		data, err := safeReadCandidate(filepath.Clean(path))
		if err != nil {
			return nil, nil, err
		}
		if _, err := buf.Write(data); err != nil {
			return nil, nil, fmt.Errorf("buffer input: %w", err)
		}
		if len(data) > 0 && data[len(data)-1] != '\n' {
			if err := buf.WriteByte('\n'); err != nil {
				return nil, nil, fmt.Errorf("buffer newline: %w", err)
			}
		}
		sum := sha256.Sum256(data)
		refs = append(refs, contract.InputRef{
			Path:       path,
			SHA256:     "sha256:" + hex.EncodeToString(sum[:]),
			EventCount: contractcompile.IntToUint64(bytes.Count(data, []byte("\n"))),
		})
	}
	return bytes.NewReader(buf.Bytes()), refs, nil
}

func resolveCompileOutputs(flags compileFlags) (string, string, string, error) {
	output := flags.output
	if output == "" {
		base, err := contractsCandidateDir()
		if err != nil {
			return "", "", "", err
		}
		output = filepath.Join(base, flags.agent+".candidate.yaml")
	}
	cleanOutput, err := checkedWritePath(output)
	if err != nil {
		return "", "", "", err
	}
	review := flags.review
	if review == "" {
		review = strings.TrimSuffix(cleanOutput, filepath.Ext(cleanOutput)) + ".review.md"
	}
	cleanReview, err := checkedWritePath(review)
	if err != nil {
		return "", "", "", err
	}
	manifest := flags.manifest
	if manifest == "" {
		manifest = strings.TrimSuffix(cleanOutput, filepath.Ext(cleanOutput)) + ".manifest.json"
	}
	cleanManifest, err := checkedWritePath(manifest)
	if err != nil {
		return "", "", "", err
	}
	return cleanOutput, cleanReview, cleanManifest, nil
}

func checkedWritePath(path string) (string, error) {
	clean := filepath.Clean(path)
	if !filepath.IsAbs(clean) {
		return "", fmt.Errorf("%w: path must be absolute: %s", errCompileWrite, path)
	}
	if err := os.MkdirAll(filepath.Dir(clean), 0o750); err != nil {
		return "", fmt.Errorf("%w: mkdir parent: %w", errCompileWrite, err)
	}
	if _, err := resolveOut(clean, clean); err != nil {
		return "", err
	}
	return clean, nil
}

func contractsCandidateDir() (string, error) {
	home := cliutil.ResolvedHome()
	if home == "" {
		userHome, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("resolve home: %w", err)
		}
		home = filepath.Join(userHome, signing.DefaultPipelockDir)
	}
	return filepath.Join(home, "contracts", "candidates"), nil
}

func compileConfig(agent string, cfg *config.Config, refs []contract.InputRef) contractcompile.CompileConfig {
	floors := cfg.Learn.Inference.Floors.Resolved()
	norm := cfg.Learn.Inference.Normalization.Resolved()
	return contractcompile.CompileConfig{
		Agent: agent,
		Floors: inference.Floors{
			MinSessions: floors.MinSessions,
			MinEvents:   floors.MinEvents,
			MinWindows:  floors.MinWindows,
		},
		Normalization: normalize.DecideConfig{
			MinEvents:            norm.MinEvents,
			MinDistinctValues:    norm.MinDistinctValues,
			EntropyThresholdBits: norm.EntropyThresholdBits,
			ReservedExtras:       norm.ReservedSegmentsExtra,
		},
		Cardinality: normalize.CapConfig{
			CardinalityCapPerHost: norm.CardinalityCapPerHost,
			TailPromotionBlockPct: norm.TailPromotionBlockPct,
		},
		CompileConfigHash: cfg.CanonicalPolicyHash(),
		InputRefs:         refs,
		Settings: map[string]any{
			"confidence": map[string]any{
				"min_sessions": floors.MinSessions,
				"min_events":   floors.MinEvents,
				"min_windows":  floors.MinWindows,
			},
			"normalization": map[string]any{
				"algorithm": norm.Algorithm,
			},
			"privacy": map[string]any{
				"default_data_class": "internal",
				"forbid_classes":     []any{"regulated"},
			},
		},
	}
}

func decodeOptionalHex(value string) ([]byte, error) {
	if strings.TrimSpace(value) == "" {
		return nil, nil
	}
	out, err := hex.DecodeString(strings.TrimSpace(value))
	if err != nil {
		return nil, fmt.Errorf("%w: --escrow-private-key must be hex: %w", errCompileInput, err)
	}
	if len(out) != 32 {
		return nil, fmt.Errorf("%w: --escrow-private-key must be 64 hex chars (32 bytes)", errCompileInput)
	}
	return out, nil
}

type privateKeySigner struct {
	keyID string
	key   ed25519.PrivateKey
}

func (s privateKeySigner) KeyID() string { return s.keyID }

func (s privateKeySigner) Sign(message []byte) ([]byte, error) {
	return ed25519.Sign(s.key, message), nil
}

func resolveCompileSigner(flags compileFlags) (privateKeySigner, error) {
	if flags.deterministic {
		seed := sha256.Sum256([]byte("pipelock deterministic compile signer"))
		return privateKeySigner{keyID: "deterministic-contract-compile", key: ed25519.NewKeyFromSeed(seed[:])}, nil
	}
	agent := flags.compileKeyAgent
	if agent == "" {
		agent = flags.agent
	}
	dir, err := cliutil.ResolveKeystoreDir(flags.keystore)
	if err != nil {
		return privateKeySigner{}, err
	}
	priv, err := signing.NewKeystore(dir).LoadPrivateKey(agent)
	if err != nil {
		return privateKeySigner{}, fmt.Errorf("load compile signing key for %q: %w", agent, err)
	}
	return privateKeySigner{keyID: agent, key: priv}, nil
}

func ensureEnvDefault(key, value string) {
	if os.Getenv(key) == "" {
		_ = os.Setenv(key, value)
	}
}
