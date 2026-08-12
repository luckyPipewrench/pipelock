// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package commitmentkey

import (
	"context"
	cryptorand "crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	domkey "github.com/luckyPipewrench/pipelock/internal/commitmentkey"
	"github.com/luckyPipewrench/pipelock/internal/config"
	contractreceipt "github.com/luckyPipewrench/pipelock/internal/contract/receipt"
	"github.com/luckyPipewrench/pipelock/internal/normalize"
)

type auditEvent struct {
	Event         string `json:"event"`
	EventType     string `json:"event_type"`
	Operation     string `json:"operation"`
	Phase         string `json:"phase,omitempty"`
	Outcome       string `json:"outcome"`
	OperationID   string `json:"operation_id,omitempty"`
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
committed with this keyring.

Lifecycle mutations require --config with logging.output set to file or both.
A stdout-only log is a stream, not a file-backed lifecycle record.`,
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
			if err := flags.prepareLifecycleAudit(cmd, true); err != nil {
				err = fmt.Errorf("initialize: file-backed lifecycle audit sink: %w", err)
				return finishLifecycleAudit(cmd, "initialize", "denied", "", 0, err)
			}
			defer closeLifecycleAudit(cmd)
			path, err := flags.resolve()
			if err != nil {
				return finishLifecycleAudit(cmd, "initialize", "denied", "", 0, err)
			}
			if err := beginMutationAudit(cmd, "initialize", "", 0); err != nil {
				err = fmt.Errorf("initialize: durable lifecycle audit intent: %w", err)
				return finishLifecycleAudit(cmd, "initialize", "denied", "", 0, err)
			}
			keyring, err := domkey.Initialize(path, time.Now())
			if err != nil {
				return finishLifecycleAudit(cmd, "initialize", "denied", "", 0, err)
			}
			if err := finishLifecycleAudit(cmd, "initialize", "succeeded", keyring.ActiveID, keyring.Epoch, nil); err != nil {
				return err
			}
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
			flags.prepareReadOnlyLifecycleAudit(cmd)
			defer closeLifecycleAudit(cmd)
			keyring, err := flags.load()
			if err != nil {
				return finishLifecycleAudit(cmd, "inspect", "denied", "", 0, err)
			}
			if err := finishLifecycleAudit(cmd, "inspect", "succeeded", keyring.ActiveID, keyring.Epoch, nil); err != nil {
				return err
			}
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
			if err := flags.prepareLifecycleAudit(cmd, true); err != nil {
				err = fmt.Errorf("rotate: file-backed lifecycle audit sink: %w", err)
				return finishLifecycleAudit(cmd, "rotate", "denied", "", 0, err)
			}
			defer closeLifecycleAudit(cmd)
			path, err := flags.resolve()
			if err != nil {
				return finishLifecycleAudit(cmd, "rotate", "denied", "", 0, err)
			}
			if err := beginMutationAudit(cmd, "rotate", "", 0); err != nil {
				err = fmt.Errorf("rotate: durable lifecycle audit intent: %w", err)
				return finishLifecycleAudit(cmd, "rotate", "denied", "", 0, err)
			}
			handle, metadata, err := domkey.Rotate(path, time.Now())
			if err != nil {
				return finishLifecycleAudit(cmd, "rotate", "denied", "", 0, err)
			}
			if err := finishLifecycleAudit(cmd, "rotate", "succeeded", handle.KeyID, handle.Epoch, nil); err != nil {
				return err
			}
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
			if err := flags.prepareLifecycleAudit(cmd, true); err != nil {
				err = fmt.Errorf("retire: file-backed lifecycle audit sink: %w", err)
				return finishLifecycleAudit(cmd, "retire", "denied", keyID, epoch, err)
			}
			defer closeLifecycleAudit(cmd)
			if err := requireFlags(cmd, "key-id", "epoch"); err != nil {
				return finishLifecycleAudit(cmd, "retire", "denied", keyID, epoch, err)
			}
			path, err := flags.resolve()
			if err != nil {
				return finishLifecycleAudit(cmd, "retire", "denied", keyID, epoch, err)
			}
			if err := beginMutationAudit(cmd, "retire", keyID, epoch, "operator_accept_loss"); err != nil {
				err = fmt.Errorf("retire: durable lifecycle audit intent: %w", err)
				return finishLifecycleAudit(cmd, "retire", "denied", keyID, epoch, err, "operator_accept_loss")
			}
			metadata, err := domkey.Retire(path, keyID, epoch, acceptLoss)
			if err != nil {
				return finishLifecycleAudit(cmd, "retire", "denied", keyID, epoch, err)
			}
			if err := finishLifecycleAudit(cmd, "retire", "succeeded", keyID, epoch, nil, "operator_accept_loss"); err != nil {
				return err
			}
			return writeJSON(cmd, metadata)
		},
	}
	flags.bind(cmd)
	cmd.Flags().StringVar(&keyID, "key-id", "", "opaque key ID to destroy")
	cmd.Flags().Uint64Var(&epoch, "epoch", 0, "key epoch to destroy")
	cmd.Flags().BoolVar(&acceptLoss, "accept-loss", false, "acknowledge permanent loss of access to retained evidence and destroy the key")
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
			if err := flags.prepareLifecycleAudit(cmd, true, out); err != nil {
				err = fmt.Errorf("backup: file-backed lifecycle audit sink: %w", err)
				return finishLifecycleAudit(cmd, "backup", "denied", "", 0, err)
			}
			defer closeLifecycleAudit(cmd)
			if err := requireFlags(cmd, "out"); err != nil {
				return finishLifecycleAudit(cmd, "backup", "denied", "", 0, err)
			}
			path, err := flags.resolve()
			if err != nil {
				return finishLifecycleAudit(cmd, "backup", "denied", "", 0, err)
			}
			if err := beginMutationAudit(cmd, "backup", "", 0); err != nil {
				err = fmt.Errorf("backup: durable lifecycle audit intent: %w", err)
				return finishLifecycleAudit(cmd, "backup", "denied", "", 0, err)
			}
			keyring, err := domkey.Backup(path, filepath.Clean(out))
			if err != nil {
				return finishLifecycleAudit(cmd, "backup", "denied", "", 0, err)
			}
			if err := finishLifecycleAudit(cmd, "backup", "succeeded", keyring.ActiveID, keyring.Epoch, nil); err != nil {
				return err
			}
			return writeJSON(cmd, keyring.Metadata())
		},
	}
	flags.bind(cmd)
	cmd.Flags().StringVar(&out, "out", "", "new backup file path")
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
			if err := flags.prepareLifecycleAudit(cmd, true, from); err != nil {
				err = fmt.Errorf("restore: file-backed lifecycle audit sink: %w", err)
				return finishLifecycleAudit(cmd, "restore", "denied", "", 0, err)
			}
			defer closeLifecycleAudit(cmd)
			if err := requireFlags(cmd, "from"); err != nil {
				return finishLifecycleAudit(cmd, "restore", "denied", "", 0, err)
			}
			path, err := flags.resolve()
			if err != nil {
				return finishLifecycleAudit(cmd, "restore", "denied", "", 0, err)
			}
			if err := beginMutationAudit(cmd, "restore", "", 0); err != nil {
				err = fmt.Errorf("restore: durable lifecycle audit intent: %w", err)
				return finishLifecycleAudit(cmd, "restore", "denied", "", 0, err)
			}
			keyring, err := domkey.Restore(filepath.Clean(from), path)
			if err != nil {
				return finishLifecycleAudit(cmd, "restore", "denied", "", 0, err)
			}
			if err := finishLifecycleAudit(cmd, "restore", "succeeded", keyring.ActiveID, keyring.Epoch, nil); err != nil {
				return err
			}
			return writeJSON(cmd, keyring.Metadata())
		},
	}
	flags.bind(cmd)
	cmd.Flags().StringVar(&from, "from", "", "backup file path")
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
			flags.prepareReadOnlyLifecycleAudit(cmd, viewFile)
			defer closeLifecycleAudit(cmd)
			if err := requireFlags(cmd, "key-id", "epoch", "source-id", "commitment"); err != nil {
				return finishLifecycleAudit(cmd, "test", "denied", keyID, epoch, err)
			}
			keyring, err := flags.load()
			if err != nil {
				return finishLifecycleAudit(cmd, "test", "denied", keyID, epoch, err)
			}
			handle, err := keyring.Open(keyID, epoch)
			if err != nil {
				return finishLifecycleAudit(cmd, "test", "denied", keyID, epoch, err)
			}
			recipe, err := parseRecipe(recipeJSON)
			if err != nil {
				return finishLifecycleAudit(cmd, "test", "denied", keyID, epoch, err)
			}
			source := contractreceipt.ProvenanceSource{
				SourceOrdinal: sourceOrdinal,
				SourceID:      sourceID,
				Recipe:        recipe,
			}
			view, err := readView(cmd, viewFile)
			if err != nil {
				return finishLifecycleAudit(cmd, "test", "denied", keyID, epoch, err)
			}
			got, err := contractreceipt.CommitView(handle.Key, source, view)
			if err != nil {
				return finishLifecycleAudit(cmd, "test", "denied", keyID, epoch, err)
			}
			if got != want {
				err := ErrCommitmentMismatch
				return finishLifecycleAudit(cmd, "test", "denied", keyID, epoch, err)
			}
			if err := finishLifecycleAudit(cmd, "test", "succeeded", keyID, epoch, nil); err != nil {
				return err
			}
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
	path         string
	configFile   string
	config       *config.Config
	configErr    error
	configLoaded bool
}

type lifecycleAuditSinkContextKey struct{}

type lifecycleAuditSink struct {
	logger      *audit.Logger
	operationID string
	writeFailed bool
}

func (f *pathFlags) bind(cmd *cobra.Command) {
	cmd.Flags().StringVar(&f.path, "keyring", "", "commitment keyring path")
	cmd.Flags().StringVar(&f.configFile, "config", "", "config file containing evidence_provenance.commitment_keyring_path")
}

func (f *pathFlags) resolve() (string, error) {
	if f.path != "" && f.configFile != "" {
		return "", errors.New("--keyring and --config are mutually exclusive")
	}
	if f.path != "" {
		return filepath.Clean(f.path), nil
	}
	if f.configFile == "" {
		return "", errors.New("one of --keyring or --config is required")
	}
	cfg, err := f.loadConfig()
	if err != nil {
		return "", err
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

func (f *pathFlags) load() (*domkey.Keyring, error) {
	path, err := f.resolve()
	if err != nil {
		return nil, err
	}
	return domkey.Load(path)
}

// prepareReadOnlyLifecycleAudit attaches a lifecycle sink when one is available
// and warns when it is not. A read-only operation never fails on an unavailable
// sink, so it deliberately returns nothing rather than an error its callers
// could not act on.
func (f *pathFlags) prepareReadOnlyLifecycleAudit(cmd *cobra.Command, protectedPaths ...string) {
	_ = f.prepareLifecycleAudit(cmd, false, protectedPaths...)
}

func (f *pathFlags) prepareLifecycleAudit(cmd *cobra.Command, mutating bool, protectedPaths ...string) error {
	logger, err := f.durableAuditSink(protectedPaths...)
	if err != nil {
		if mutating {
			return err
		}
		_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "WARNING: file-backed lifecycle audit sink unavailable: %v; proceeding because this operation is read-only\n", err)
		return nil
	}
	cmd.SetContext(context.WithValue(cmd.Context(), lifecycleAuditSinkContextKey{}, &lifecycleAuditSink{
		logger:      logger,
		operationID: "cka_" + cryptorand.Text(),
	}))
	return nil
}

// beginMutationAudit durably records intent before the operation can change a
// keyring or lifecycle artifact. An outcome alone cannot account for a crash
// after the mutation but before the command reports its result.
func beginMutationAudit(cmd *cobra.Command, operation, keyID string, epoch uint64, authorization ...string) error {
	sink, ok := lifecycleAuditSinkFromCommand(cmd)
	if !ok {
		return errors.New("durable lifecycle audit sink is not prepared")
	}
	var auth string
	if len(authorization) != 0 {
		auth = authorization[0]
	}
	if err := sink.logger.WriteDurableCommitmentKeyLifecycle(audit.CommitmentKeyLifecycleEvent{
		Operation:     operation,
		Phase:         "intent",
		Outcome:       "pending",
		OperationID:   sink.operationID,
		KeyID:         keyID,
		Epoch:         epoch,
		Authorization: auth,
	}); err != nil {
		sink.writeFailed = true
		return err
	}
	return nil
}

func lifecycleAuditSinkFromCommand(cmd *cobra.Command) (*lifecycleAuditSink, bool) {
	sink, ok := cmd.Context().Value(lifecycleAuditSinkContextKey{}).(*lifecycleAuditSink)
	return sink, ok && sink != nil
}

func closeLifecycleAudit(cmd *cobra.Command) {
	if sink, ok := lifecycleAuditSinkFromCommand(cmd); ok {
		sink.logger.Close()
	}
}

func (f *pathFlags) durableAuditSink(protectedPaths ...string) (*audit.Logger, error) {
	if f.configFile == "" {
		return nil, errors.New("--config is required to configure a file-backed lifecycle audit sink")
	}
	cfg, err := f.loadConfig()
	if err != nil {
		return nil, err
	}
	if cfg.Logging.Output != config.OutputFile && cfg.Logging.Output != config.OutputBoth {
		return nil, fmt.Errorf("logging.output %q is not file-backed; set it to file or both", cfg.Logging.Output)
	}
	if cfg.Logging.Format != config.DefaultLogFormat {
		return nil, fmt.Errorf("logging.format %q is not a JSON Lines durable lifecycle audit sink; set it to json", cfg.Logging.Format)
	}
	if cfg.Logging.File == "" {
		return nil, errors.New("logging.file is required for a file-backed lifecycle audit sink")
	}
	protectedPaths = append(protectedPaths, cfg.EvidenceProvenance.CommitmentKeyringPath)
	if f.path != "" {
		protectedPaths = append(protectedPaths, f.path)
	}
	for _, protectedPath := range protectedPaths {
		if protectedPath == "" || protectedPath == "-" {
			continue
		}
		same, err := sameFilesystemPath(cfg.Logging.File, protectedPath)
		if err != nil {
			return nil, err
		}
		if same {
			return nil, errors.New("logging.file must not refer to the commitment keyring or a lifecycle input/output file")
		}
	}
	logger, err := audit.NewDurableFile(cfg.Logging.Format, cfg.Logging.File, cfg.Logging.IncludeAllowed, cfg.Logging.IncludeBlocked)
	if err != nil {
		return nil, fmt.Errorf("open logging.file: %w", err)
	}
	return logger, nil
}

// loadConfig reads the command config once. In particular, --config - is a
// supported config input and cannot be replayed after the audit sink has read
// it to obtain logging settings.
func (f *pathFlags) loadConfig() (*config.Config, error) {
	if f.configLoaded {
		return f.config, f.configErr
	}
	f.configLoaded = true
	f.config, f.configErr = config.LoadForInspection(f.configFile)
	if f.configErr != nil {
		f.configErr = fmt.Errorf("load config: %w", f.configErr)
		return nil, f.configErr
	}
	return f.config, nil
}

func sameFilesystemPath(left, right string) (bool, error) {
	leftPath, err := normalizedFilesystemPath(left)
	if err != nil {
		return false, fmt.Errorf("resolve logging.file: %w", err)
	}
	rightPath, err := normalizedFilesystemPath(right)
	if err != nil {
		return false, fmt.Errorf("resolve lifecycle file: %w", err)
	}
	if leftPath == rightPath {
		return true, nil
	}
	leftInfo, leftErr := os.Stat(leftPath)
	rightInfo, rightErr := os.Stat(rightPath)
	if leftErr == nil && rightErr == nil {
		return os.SameFile(leftInfo, rightInfo), nil
	}
	if leftErr != nil && !errors.Is(leftErr, os.ErrNotExist) {
		return false, fmt.Errorf("inspect logging.file: %w", leftErr)
	}
	if rightErr != nil && !errors.Is(rightErr, os.ErrNotExist) {
		return false, fmt.Errorf("inspect lifecycle file: %w", rightErr)
	}
	return false, nil
}

func normalizedFilesystemPath(path string) (string, error) {
	abs, err := filepath.Abs(filepath.Clean(path))
	if err != nil {
		return "", err
	}
	resolvedParent, err := filepath.EvalSymlinks(filepath.Dir(abs))
	if err == nil {
		return filepath.Join(resolvedParent, filepath.Base(abs)), nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return abs, nil
	}
	return "", err
}

func requireFlags(cmd *cobra.Command, names ...string) error {
	var missing []string
	for _, name := range names {
		if !cmd.Flags().Changed(name) {
			missing = append(missing, name)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	return fmt.Errorf("required flag(s) %q not set", strings.Join(missing, ", "))
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

func finishLifecycleAudit(cmd *cobra.Command, operation, outcome, keyID string, epoch uint64, operationErr error, authorization ...string) error {
	if err := emitAudit(cmd, operation, outcome, keyID, epoch, operationErr, authorization...); err != nil {
		auditErr := fmt.Errorf("persist lifecycle audit outcome: %w", err)
		if operationErr == nil {
			return auditErr
		}
		return errors.Join(operationErr, auditErr)
	}
	return operationErr
}

func emitAudit(cmd *cobra.Command, operation, outcome, keyID string, epoch uint64, operationErr error, authorization ...string) error {
	event := auditEvent{Event: "commitment_key_lifecycle", EventType: "commitment_key_lifecycle", Operation: operation, Phase: "outcome", Outcome: outcome, KeyID: keyID, Epoch: epoch, Timestamp: time.Now().UTC().Format(time.RFC3339Nano)}
	sink, hasSink := lifecycleAuditSinkFromCommand(cmd)
	if hasSink {
		event.OperationID = sink.operationID
	}
	if len(authorization) != 0 {
		event.Authorization = authorization[0]
	}
	if operationErr != nil {
		event.Reason = lifecycleAuditReason(operationErr)
	}
	data, err := json.Marshal(event)
	if err == nil {
		_, _ = fmt.Fprintln(cmd.ErrOrStderr(), string(data))
	}
	if hasSink && !sink.writeFailed {
		if err := sink.logger.WriteDurableCommitmentKeyLifecycle(audit.CommitmentKeyLifecycleEvent{
			Operation:     operation,
			Phase:         event.Phase,
			Outcome:       outcome,
			OperationID:   event.OperationID,
			KeyID:         keyID,
			Epoch:         epoch,
			Timestamp:     event.Timestamp,
			Reason:        event.Reason,
			Authorization: event.Authorization,
		}); err != nil {
			sink.writeFailed = true
			return err
		}
	}
	return nil
}

func lifecycleAuditReason(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrCommitmentMismatch):
		return "commitment_mismatch"
	case errors.Is(err, domkey.ErrAlreadyExists):
		return "keyring_already_exists"
	case errors.Is(err, domkey.ErrInvalidKeyring):
		return "invalid_keyring"
	case errors.Is(err, domkey.ErrKeyNotFound):
		return "key_not_found"
	case errors.Is(err, domkey.ErrRetainedKey):
		return "retained_evidence"
	case errors.Is(err, domkey.ErrSymlink):
		return "symlink_refused"
	case errors.Is(err, domkey.ErrUnsafePermission):
		return "unsafe_permission"
	case errors.Is(err, os.ErrNotExist):
		return "file_not_found"
	case errors.Is(err, os.ErrPermission):
		return "permission_denied"
	case strings.Contains(err.Error(), "required flag(s)"):
		return "missing_required_flag"
	case strings.Contains(err.Error(), "lifecycle audit sink"):
		return "audit_sink_unavailable"
	default:
		return "operation_failed"
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
