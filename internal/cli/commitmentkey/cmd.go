// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package commitmentkey

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	domkey "github.com/luckyPipewrench/pipelock/internal/commitmentkey"
	"github.com/luckyPipewrench/pipelock/internal/config"
	contractreceipt "github.com/luckyPipewrench/pipelock/internal/contract/receipt"
	"github.com/luckyPipewrench/pipelock/internal/normalize"
)

type auditEvent struct {
	EventType string `json:"event_type"`
	Operation string `json:"operation"`
	Outcome   string `json:"outcome"`
	KeyID     string `json:"key_id,omitempty"`
	Epoch     uint64 `json:"epoch,omitempty"`
	Timestamp string `json:"timestamp"`
	Reason    string `json:"reason,omitempty"`
}

// Cmd returns the commitment-key lifecycle command tree.
func Cmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "commitment-key",
		Short: "Manage private evidence commitment keys",
		Long: `Manage the operator-owned symmetric keyring used to open private
evidence commitments. Commitment keys are not receipt-signing keys and cannot
be used with signing commands.`,
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
			path, err := flags.resolve()
			if err != nil {
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
			path, err := flags.resolve()
			if err != nil {
				return err
			}
			handle, err := domkey.Rotate(path, time.Now())
			if err != nil {
				emitAudit(cmd, "rotate", "denied", "", 0, err)
				return err
			}
			emitAudit(cmd, "rotate", "succeeded", handle.KeyID, handle.Epoch, nil)
			keyring, err := domkey.Load(path)
			if err != nil {
				return err
			}
			return writeJSON(cmd, keyring.Metadata())
		},
	}
	flags.bind(cmd)
	return cmd
}

func retireCmd() *cobra.Command {
	var flags pathFlags
	var keyID string
	var epoch uint64
	var retained []string
	var acceptLoss bool
	cmd := &cobra.Command{
		Use:   "retire",
		Short: "Destroy a verify-only key after retained-reference checks",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			path, err := flags.resolve()
			if err != nil {
				return err
			}
			references, err := parseReferences(retained)
			if err != nil {
				return err
			}
			if err := domkey.Retire(path, keyID, epoch, references, acceptLoss); err != nil {
				emitAudit(cmd, "retire", "denied", keyID, epoch, err)
				return err
			}
			emitAudit(cmd, "retire", "succeeded", keyID, epoch, nil)
			keyring, err := domkey.Load(path)
			if err != nil {
				return err
			}
			return writeJSON(cmd, keyring.Metadata())
		},
	}
	flags.bind(cmd)
	cmd.Flags().StringVar(&keyID, "key-id", "", "opaque key ID to destroy")
	cmd.Flags().Uint64Var(&epoch, "epoch", 0, "key epoch to destroy")
	cmd.Flags().StringArrayVar(&retained, "retained-reference", nil, "retained receipt reference as KEY_ID:EPOCH; repeat as needed")
	cmd.Flags().BoolVar(&acceptLoss, "accept-loss", false, "destroy the key even when a retained receipt still references it")
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
			path, err := flags.resolve()
			if err != nil {
				return err
			}
			if err := domkey.Backup(path, filepath.Clean(out)); err != nil {
				emitAudit(cmd, "backup", "denied", "", 0, err)
				return err
			}
			keyring, err := domkey.Load(path)
			if err != nil {
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
			path, err := flags.resolve()
			if err != nil {
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
	var keyID, sourceID, view, want string
	var epoch, sourceOrdinal uint64
	cmd := &cobra.Command{
		Use:   "test",
		Short: "Test opening a PR 3 evidence view commitment",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
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
			source := contractreceipt.ProvenanceSource{
				SourceOrdinal: sourceOrdinal,
				SourceID:      sourceID,
				Recipe:        normalize.Recipe{TransformProfileDigest: normalize.EvidenceProvenanceProfileV1Digest},
			}
			got, err := contractreceipt.CommitView(handle.Key, source, view)
			if err != nil {
				emitAudit(cmd, "test", "denied", keyID, epoch, err)
				return err
			}
			if got != want {
				err := errors.New("commitment mismatch")
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
	cmd.Flags().StringVar(&view, "view", "", "complete transformed view to open")
	cmd.Flags().StringVar(&want, "commitment", "", "expected hmac-sha256 commitment")
	for _, name := range []string{"key-id", "epoch", "source-id", "view", "commitment"} {
		_ = cmd.MarkFlagRequired(name)
	}
	return cmd
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

func parseReferences(values []string) ([]domkey.Reference, error) {
	refs := make([]domkey.Reference, 0, len(values))
	for _, value := range values {
		keyID, rawEpoch, ok := strings.Cut(value, ":")
		if !ok || keyID == "" {
			return nil, fmt.Errorf("invalid retained reference %q; want KEY_ID:EPOCH", value)
		}
		epoch, err := strconv.ParseUint(rawEpoch, 10, 64)
		if err != nil || epoch == 0 {
			return nil, fmt.Errorf("invalid retained reference %q; epoch must be positive", value)
		}
		refs = append(refs, domkey.Reference{KeyID: keyID, Epoch: epoch})
	}
	return refs, nil
}

func emitAudit(cmd *cobra.Command, operation, outcome, keyID string, epoch uint64, operationErr error) {
	event := auditEvent{EventType: "commitment_key_lifecycle", Operation: operation, Outcome: outcome, KeyID: keyID, Epoch: epoch, Timestamp: time.Now().UTC().Format(time.RFC3339Nano)}
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
