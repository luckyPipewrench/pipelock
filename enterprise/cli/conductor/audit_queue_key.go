//go:build enterprise

// Copyright 2026 Pipelock contributors
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package conductor

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/enterprise/conductor/auditbatcher"
)

type auditQueueKeyOptions struct {
	keyring  string
	queueDir string
	backup   string
}

func auditQueueKeyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "audit-queue-key",
		Short: "Manage follower audit-queue encryption keys",
	}
	cmd.AddCommand(auditQueueKeyInitCmd())
	cmd.AddCommand(auditQueueKeyInspectCmd())
	cmd.AddCommand(auditQueueKeyRotateCmd())
	cmd.AddCommand(auditQueueKeyMigrateCmd())
	cmd.AddCommand(auditQueueKeyRevokeCmd())
	cmd.AddCommand(auditQueueKeyRecoverCmd())
	return cmd
}

func auditQueueKeyInitCmd() *cobra.Command {
	var opts auditQueueKeyOptions
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Create a new audit-queue keyring",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if _, err := os.Lstat(opts.keyring); err == nil {
				return fmt.Errorf("audit queue keyring already exists: %s", opts.keyring)
			} else if !errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("inspect audit queue keyring: %w", err)
			}
			keyring, err := auditbatcher.NewKeyring()
			if err != nil {
				return err
			}
			if err := auditbatcher.EnsureKeyringParent(opts.keyring); err != nil {
				return err
			}
			if err := keyring.Save(opts.keyring); err != nil {
				return err
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "created audit queue keyring %s (active %s)\n", opts.keyring, keyring.ActiveKeyID())
			return nil
		},
	}
	cmd.Flags().StringVar(&opts.keyring, "keyring", "", "path to the keyring file (required; keep outside the audit queue volume)")
	_ = cmd.MarkFlagRequired("keyring")
	return cmd
}

func auditQueueKeyInspectCmd() *cobra.Command {
	var opts auditQueueKeyOptions
	cmd := &cobra.Command{
		Use:   "inspect",
		Short: "Show key IDs and durable-record usage without exposing key material",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			keyring, usage, err := loadAndInspectQueueKeys(opts)
			if err != nil {
				return err
			}
			for _, id := range keyring.KeyIDs() {
				active := ""
				if id == keyring.ActiveKeyID() {
					active = " active"
				}
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s records=%d%s\n", id, usage[id], active)
			}
			if usage[auditbatcher.LegacyKeyID] > 0 {
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s records=%d\n", auditbatcher.LegacyKeyID, usage[auditbatcher.LegacyKeyID])
			}
			if usage[auditbatcher.UnreadableRecordID] > 0 {
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s records=%d\n", auditbatcher.UnreadableRecordID, usage[auditbatcher.UnreadableRecordID])
			}
			return nil
		},
	}
	addAuditQueueKeyFlags(cmd, &opts)
	return cmd
}

func auditQueueKeyRotateCmd() *cobra.Command {
	var opts auditQueueKeyOptions
	cmd := &cobra.Command{
		Use:   "rotate",
		Short: "Activate a new key, preserve a backup, and re-encrypt queued records",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if strings.TrimSpace(opts.backup) == "" {
				opts.backup = opts.keyring + ".bak"
			}
			oldID, newID, err := auditbatcher.RotateQueueKeyring(opts.queueDir, opts.keyring, opts.backup)
			if err != nil {
				return err
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "rotated audit queue key %s -> %s; recovery backup %s; previous backup %s.previous\n", oldID, newID, opts.backup, opts.backup)
			return nil
		},
	}
	addAuditQueueKeyFlags(cmd, &opts)
	cmd.Flags().StringVar(&opts.backup, "backup", "", "post-rotation recovery backup path; pre-rotation state uses BACKUP.previous (default KEYRING.bak)")
	return cmd
}

func auditQueueKeyMigrateCmd() *cobra.Command {
	var opts auditQueueKeyOptions
	cmd := &cobra.Command{
		Use:   "migrate",
		Short: "Encrypt legacy records and re-encrypt old-key records under the active key",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			activeID, err := auditbatcher.MigrateQueueKeyring(opts.queueDir, opts.keyring)
			if err != nil {
				return err
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "audit queue records converged to active key %s\n", activeID)
			return nil
		},
	}
	addAuditQueueKeyFlags(cmd, &opts)
	return cmd
}

func auditQueueKeyRevokeCmd() *cobra.Command {
	var opts auditQueueKeyOptions
	cmd := &cobra.Command{
		Use:   "revoke KEY_ID",
		Short: "Remove an inactive key only when no durable record uses it",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := auditbatcher.RevokeQueueKeyringKey(opts.queueDir, opts.keyring, args[0]); err != nil {
				return err
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "revoked audit queue key %s\n", args[0])
			return nil
		},
	}
	addAuditQueueKeyFlags(cmd, &opts)
	return cmd
}

func auditQueueKeyRecoverCmd() *cobra.Command {
	var opts auditQueueKeyOptions
	cmd := &cobra.Command{
		Use:   "recover",
		Short: "Restore a backup keyring after proving it decrypts every queued record",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			activeID, err := auditbatcher.RecoverQueueKeyring(opts.queueDir, opts.keyring, opts.backup)
			if err != nil {
				return err
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "recovered audit queue keyring %s from %s (active %s)\n", opts.keyring, opts.backup, activeID)
			return nil
		},
	}
	addAuditQueueKeyFlags(cmd, &opts)
	cmd.Flags().StringVar(&opts.backup, "backup", "", "validated backup keyring to restore (required)")
	_ = cmd.MarkFlagRequired("backup")
	return cmd
}

func addAuditQueueKeyFlags(cmd *cobra.Command, opts *auditQueueKeyOptions) {
	cmd.Flags().StringVar(&opts.keyring, "keyring", "", "path to the keyring file (required)")
	_ = cmd.MarkFlagRequired("keyring")
	cmd.Flags().StringVar(&opts.queueDir, "queue-dir", "", "durable audit queue directory (required)")
	_ = cmd.MarkFlagRequired("queue-dir")
}

func loadAndInspectQueueKeys(opts auditQueueKeyOptions) (*auditbatcher.Keyring, map[string]int, error) {
	keyring, err := auditbatcher.LoadKeyring(opts.keyring)
	if err != nil {
		return nil, nil, err
	}
	usage, err := auditbatcher.InspectQueueKeys(opts.queueDir, 0, keyring)
	if err != nil {
		return nil, nil, err
	}
	return keyring, usage, nil
}
