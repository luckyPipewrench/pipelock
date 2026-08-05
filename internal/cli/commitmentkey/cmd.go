// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package commitmentkey

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	domkey "github.com/luckyPipewrench/pipelock/internal/commitmentkey"
	"github.com/luckyPipewrench/pipelock/internal/config"
	contractreceipt "github.com/luckyPipewrench/pipelock/internal/contract/receipt"
	"github.com/luckyPipewrench/pipelock/internal/normalize"
)

type auditEvent struct {
	EventType     string `json:"event_type"`
	Operation     string `json:"operation"`
	Outcome       string `json:"outcome"`
	KeyID         string `json:"key_id,omitempty"`
	Epoch         uint64 `json:"epoch,omitempty"`
	Timestamp     string `json:"timestamp"`
	Reason        string `json:"reason,omitempty"`
	Authorization string `json:"authorization,omitempty"`
}

const (
	capabilityNotice   = "WARNING: commitment keys are not consumed by an evidence producer yet; nothing is currently being committed with this keyring."
	privateViewMaxSize = 64 << 20
)

// ErrCommitmentMismatch reports that a recomputed commitment differs from the
// expected value supplied by the operator.
var ErrCommitmentMismatch = errors.New("commitment mismatch")

// Cmd returns the commitment-key lifecycle command tree.
func Cmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "commitment-key",
		Short: "Manage private evidence commitment keys",
		Long: `Manage the operator-owned symmetric keyring intended to open private
evidence commitments. Commitment keys are not receipt-signing keys and cannot
be used with signing commands.

No evidence producer consumes these keys yet. Nothing is currently being
committed with this keyring.`,
	}
	cmd.AddCommand(initializeCmd(), inspectCmd(), rotateCmd(), retireCmd(), backupCmd(), restoreCmd(), testCmd())
	return cmd
}

func initializeCmd() *cobra.Command {
	var flags pathFlags
	cmd := &cobra.Command{
		Use:   "initialize",
		Short: "Initialize a new commitment keyring",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			emitCapabilityNotice(cmd)
			path, err := flags.resolve()
			if err != nil {
				emitAudit(cmd, "initialize", "denied", "", 0, err)
				return err
			}
			keyring, err := domkey.Initialize(path, time.Now())
			if err != nil {
				emitAudit(cmd, "initialize", "denied", "", 0, err)
				return err
			}
			emitAudit(cmd, "initialize", "succeeded", keyring.ActiveID, keyring.Epoch, nil)
			return writeJSON(cmd, keyring.Metadata())
		},
	}
	flags.bind(cmd)
	return cmd
}

func inspectCmd() *cobra.Command {
	var flags pathFlags
	cmd := &cobra.Command{
		Use:   "inspect",
		Short: "Inspect commitment key metadata without revealing key material",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			emitCapabilityNotice(cmd)
			keyring, err := flags.load()
			if err != nil {
				emitAudit(cmd, "inspect", "denied", "", 0, err)
				return err
			}
			emitAudit(cmd, "inspect", "succeeded", keyring.ActiveID, keyring.Epoch, nil)
			return writeJSON(cmd, keyring.Metadata())
		},
	}
	flags.bind(cmd)
	return cmd
}

func rotateCmd() *cobra.Command {
	var flags pathFlags
	cmd := &cobra.Command{
		Use:   "rotate",
		Short: "Create a new active epoch and retain the prior key for opening",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			emitCapabilityNotice(cmd)
			path, err := flags.resolve()
			if err != nil {
				emitAudit(cmd, "rotate", "denied", "", 0, err)
				return err
			}
			handle, metadata, err := domkey.Rotate(path, time.Now())
			if err != nil {
				emitAudit(cmd, "rotate", "denied", "", 0, err)
				return err
			}
			emitAudit(cmd, "rotate", "succeeded", handle.KeyID, handle.Epoch, nil)
			return writeJSON(cmd, metadata)
		},
	}
	flags.bind(cmd)
	return cmd
}

func retireCmd() *cobra.Command {
	var flags pathFlags
	var keyID string
	var epoch uint64
	var acceptLoss bool
	cmd := &cobra.Command{
		Use:   "retire",
		Short: "Destroy a verify-only key with explicit loss acceptance",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			emitCapabilityNotice(cmd)
			path, err := flags.resolve()
			if err != nil {
				emitAudit(cmd, "retire", "denied", keyID, epoch, err)
				return err
			}
			metadata, err := domkey.Retire(path, keyID, epoch, acceptLoss)
			if err != nil {
				emitAudit(cmd, "retire", "denied", keyID, epoch, err)
				return err
			}
			emitAudit(cmd, "retire", "succeeded", keyID, epoch, nil, "operator_accept_loss")
			return writeJSON(cmd, metadata)
		},
	}
	flags.bind(cmd)
	cmd.Flags().StringVar(&keyID, "key-id", "", "opaque key ID to destroy")
	cmd.Flags().Uint64Var(&epoch, "epoch", 0, "key epoch to destroy")
	cmd.Flags().BoolVar(&acceptLoss, "accept-loss", false, "acknowledge permanent loss of access to retained evidence and destroy the key")
	_ = cmd.MarkFlagRequired("key-id")
	_ = cmd.MarkFlagRequired("epoch")
	return cmd
}

func backupCmd() *cobra.Command {
	var flags pathFlags
	var out string
	cmd := &cobra.Command{
		Use:   "backup",
		Short: "Create a validated 0600 keyring backup",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			emitCapabilityNotice(cmd)
			path, err := flags.resolve()
			if err != nil {
				emitAudit(cmd, "backup", "denied", "", 0, err)
				return err
			}
			keyring, err := domkey.Backup(path, filepath.Clean(out))
			if err != nil {
				emitAudit(cmd, "backup", "denied", "", 0, err)
				return err
			}
			emitAudit(cmd, "backup", "succeeded", keyring.ActiveID, keyring.Epoch, nil)
			return writeJSON(cmd, keyring.Metadata())
		},
	}
	flags.bind(cmd)
	cmd.Flags().StringVar(&out, "out", "", "new backup file path")
	_ = cmd.MarkFlagRequired("out")
	return cmd
}

func restoreCmd() *cobra.Command {
	var flags pathFlags
	var from string
	cmd := &cobra.Command{
		Use:   "restore",
		Short: "Restore a validated backup into an absent keyring path",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			emitCapabilityNotice(cmd)
			path, err := flags.resolve()
			if err != nil {
				emitAudit(cmd, "restore", "denied", "", 0, err)
				return err
			}
			keyring, err := domkey.Restore(filepath.Clean(from), path)
			if err != nil {
				emitAudit(cmd, "restore", "denied", "", 0, err)
				return err
			}
			emitAudit(cmd, "restore", "succeeded", keyring.ActiveID, keyring.Epoch, nil)
			return writeJSON(cmd, keyring.Metadata())
		},
	}
	flags.bind(cmd)
	cmd.Flags().StringVar(&from, "from", "", "backup file path")
	_ = cmd.MarkFlagRequired("from")
	return cmd
}

func testCmd() *cobra.Command {
	var flags pathFlags
	var keyID, sourceID, viewFile, want, recipeJSON string
	var epoch, sourceOrdinal uint64
	cmd := &cobra.Command{
		Use:   "test",
		Short: "Test opening a PR 3 evidence view commitment",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			emitCapabilityNotice(cmd)
			keyring, err := flags.load()
			if err != nil {
				emitAudit(cmd, "test", "denied", keyID, epoch, err)
				return err
			}
			handle, err := keyring.Open(keyID, epoch)
			if err != nil {
				emitAudit(cmd, "test", "denied", keyID, epoch, err)
				return err
			}
			recipe, err := parseRecipe(recipeJSON)
			if err != nil {
				emitAudit(cmd, "test", "denied", keyID, epoch, err)
				return err
			}
			source := contractreceipt.ProvenanceSource{
				SourceOrdinal: sourceOrdinal,
				SourceID:      sourceID,
				Recipe:        recipe,
			}
			view, err := readView(cmd, viewFile)
			if err != nil {
				emitAudit(cmd, "test", "denied", keyID, epoch, err)
				return err
			}
			got, err := contractreceipt.CommitView(handle.Key, source, view)
			if err != nil {
				emitAudit(cmd, "test", "denied", keyID, epoch, err)
				return err
			}
			if got != want {
				err := ErrCommitmentMismatch
				emitAudit(cmd, "test", "denied", keyID, epoch, err)
				return err
			}
			emitAudit(cmd, "test", "succeeded", keyID, epoch, nil)
			return writeJSON(cmd, map[string]any{"key_id": keyID, "epoch": epoch, "opened": true})
		},
	}
	flags.bind(cmd)
	cmd.Flags().StringVar(&keyID, "key-id", "", "opaque key ID named by the receipt")
	cmd.Flags().Uint64Var(&epoch, "epoch", 0, "key epoch named by the receipt")
	cmd.Flags().StringVar(&sourceID, "source-id", "", "source ID bound into the commitment")
	cmd.Flags().Uint64Var(&sourceOrdinal, "source-ordinal", 0, "source ordinal bound into the commitment")
	cmd.Flags().StringVar(&viewFile, "view-file", "-", "read the complete transformed view from this 0600 file, or - for stdin")
	cmd.Flags().StringVar(&want, "commitment", "", "expected hmac-sha256 commitment")
	cmd.Flags().StringVar(&recipeJSON, "recipe-json", "", "PR 3 typed recipe JSON; defaults to the empty v1 recipe")
	for _, name := range []string{"key-id", "epoch", "source-id", "commitment"} {
		_ = cmd.MarkFlagRequired(name)
	}
	return cmd
}

func parseRecipe(raw string) (normalize.Recipe, error) {
	if raw == "" {
		return normalize.Recipe{TransformProfileDigest: normalize.EvidenceProvenanceProfileV1Digest}, nil
	}
	var recipe normalize.Recipe
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&recipe); err != nil {
		return normalize.Recipe{}, fmt.Errorf("decode --recipe-json: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return normalize.Recipe{}, errors.New("decode --recipe-json: trailing JSON")
	}
	if err := recipe.Validate(); err != nil {
		return normalize.Recipe{}, fmt.Errorf("validate --recipe-json: %w", err)
	}
	return recipe, nil
}

type pathFlags struct {
	path       string
	configFile string
}

func (f *pathFlags) bind(cmd *cobra.Command) {
	cmd.Flags().StringVar(&f.path, "keyring", "", "commitment keyring path")
	cmd.Flags().StringVar(&f.configFile, "config", "", "config file containing evidence_provenance.commitment_keyring_path")
}

func (f pathFlags) resolve() (string, error) {
	if f.path != "" && f.configFile != "" {
		return "", errors.New("--keyring and --config are mutually exclusive")
	}
	if f.path != "" {
		return filepath.Clean(f.path), nil
	}
	if f.configFile == "" {
		return "", errors.New("one of --keyring or --config is required")
	}
	cfg, err := config.LoadForInspection(f.configFile)
	if err != nil {
		return "", fmt.Errorf("load config: %w", err)
	}
	if cfg.EvidenceProvenance.CommitmentKeyringPath == "" {
		return "", errors.New("config has no evidence_provenance.commitment_keyring_path")
	}
	path := cfg.EvidenceProvenance.CommitmentKeyringPath
	if !filepath.IsAbs(path) {
		path = filepath.Join(filepath.Dir(filepath.Clean(f.configFile)), path)
	}
	return filepath.Clean(path), nil
}

func (f pathFlags) load() (*domkey.Keyring, error) {
	path, err := f.resolve()
	if err != nil {
		return nil, err
	}
	return domkey.Load(path)
}

func readView(cmd *cobra.Command, path string) (string, error) {
	if path == "-" {
		raw, err := io.ReadAll(io.LimitReader(cmd.InOrStdin(), privateViewMaxSize+1))
		if err != nil {
			return "", fmt.Errorf("read private evidence view from stdin: %w", err)
		}
		if len(raw) > privateViewMaxSize {
			return "", errors.New("private evidence view exceeds 67108864 bytes")
		}
		return string(raw), nil
	}
	raw, err := domkey.ReadPrivateView(filepath.Clean(path))
	if err != nil {
		return "", fmt.Errorf("read --view-file: %w", err)
	}
	return string(raw), nil
}

func emitCapabilityNotice(cmd *cobra.Command) {
	_, _ = fmt.Fprintln(cmd.ErrOrStderr(), capabilityNotice)
}

func emitAudit(cmd *cobra.Command, operation, outcome, keyID string, epoch uint64, operationErr error, authorization ...string) {
	event := auditEvent{EventType: "commitment_key_lifecycle", Operation: operation, Outcome: outcome, KeyID: keyID, Epoch: epoch, Timestamp: time.Now().UTC().Format(time.RFC3339Nano)}
	if len(authorization) != 0 {
		event.Authorization = authorization[0]
	}
	if operationErr != nil {
		event.Reason = operationErr.Error()
	}
	data, err := json.Marshal(event)
	if err == nil {
		_, _ = fmt.Fprintln(cmd.ErrOrStderr(), string(data))
	}
}

func writeJSON(cmd *cobra.Command, value any) error {
	encoder := json.NewEncoder(cmd.OutOrStdout())
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(value); err != nil {
		return fmt.Errorf("write JSON output: %w", err)
	}
	return nil
}
