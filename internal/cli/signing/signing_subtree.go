// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package signing

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	domsigning "github.com/luckyPipewrench/pipelock/internal/signing"
)

// ed25519PubKeyHexLen is the expected hex-encoded length of a 32-byte
// Ed25519 public key: 32 bytes = 64 hex characters.
const ed25519PubKeyHexLen = 64

// pubkeyFileMaxSize caps the size of a public-key file. A 64-hex-char key
// plus newline is 65 bytes; allow a small margin for whitespace or BOMs but
// reject pathologically large inputs that might be a misconfiguration or an
// adversary trying to exhaust the loader on a non-key file.
const pubkeyFileMaxSize = 4096

// errPubkeyFileTooLarge surfaces when a --*-pubkey-file exceeds the cap.
var errPubkeyFileTooLarge = errors.New("public key file exceeds size cap")

// SigningSubtreeCmd returns the "signing" parent cobra command hosting
// offline ceremony verification subcommands: roster show, roster verify,
// recovery verify, and transition verify.
func SigningSubtreeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "signing",
		Short: "Offline ceremony verification for key rosters and trust roots",
		Long: `Verify signed key rosters, recovery authorizations, and root
transition documents offline. These commands are used during key
ceremonies to confirm that signed artifacts are authentic before
trusting them in production.

Subcommand groups:
  roster      Show and verify key rosters
  recovery    Verify recovery authorizations
  transition  Verify root transition documents`,
	}

	roster := &cobra.Command{
		Use:   "roster",
		Short: "Show and verify key rosters",
	}
	roster.AddCommand(rosterShowCmd())
	roster.AddCommand(rosterVerifyCmd())

	recovery := &cobra.Command{
		Use:   "recovery",
		Short: "Verify recovery authorizations",
	}
	recovery.AddCommand(recoveryVerifyCmd())

	transition := &cobra.Command{
		Use:   "transition",
		Short: "Verify root transition documents",
	}
	transition.AddCommand(transitionVerifyCmd())

	cmd.AddCommand(roster, recovery, transition)
	return cmd
}

func rosterShowCmd() *cobra.Command {
	var path string
	var rootFingerprint string

	cmd := &cobra.Command{
		Use:   "show",
		Short: "Load and verify a key roster, then pretty-print its body",
		Long: `Loads a signed key roster from disk, verifies the signature
against the pinned root fingerprint, and prints the roster body as
indented JSON.

Examples:
  pipelock signing roster show --path roster.json --root-fingerprint sha256:abc123...`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			loaded, err := domsigning.LoadRoster(filepath.Clean(path), rootFingerprint)
			if err != nil {
				_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "load failed: %v\n", err)
				return err
			}

			data, err := json.MarshalIndent(loaded.Body, "", "  ")
			if err != nil {
				return fmt.Errorf("marshal roster body: %w", err)
			}
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), string(data))
			return nil
		},
	}

	cmd.Flags().StringVar(&path, "path", "", "path to roster file (.json/.yaml/.yml)")
	cmd.Flags().StringVar(&rootFingerprint, "root-fingerprint", "", "pinned root fingerprint (sha256:...)")
	_ = cmd.MarkFlagRequired("path")
	_ = cmd.MarkFlagRequired("root-fingerprint")
	return cmd
}

func rosterVerifyCmd() *cobra.Command {
	var path string
	var rootFingerprint string

	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify a key roster's signature and print a summary",
		Long: `Loads and verifies a signed key roster against the pinned root
fingerprint. On success prints the key count and signing key ID.
Exit 0 on success, non-zero on failure.

Examples:
  pipelock signing roster verify --path roster.json --root-fingerprint sha256:abc123...`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			loaded, err := domsigning.LoadRoster(filepath.Clean(path), rootFingerprint)
			if err != nil {
				_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "verify failed: %v\n", err)
				return err
			}

			// RosterSignedBy is the operator-supplied roster signing key id
			// from the YAML; it is attacker-controlled before the roster
			// is signed, so quote it for terminal-injection safety.
			_, _ = fmt.Fprintf(cmd.OutOrStdout(),
				"roster verified: %d keys, root_signed_by=%s\n",
				len(loaded.Body.Keys), sanitizeForTerminal(loaded.Body.RosterSignedBy))
			return nil
		},
	}

	cmd.Flags().StringVar(&path, "path", "", "path to roster file (.json/.yaml/.yml)")
	cmd.Flags().StringVar(&rootFingerprint, "root-fingerprint", "", "pinned root fingerprint (sha256:...)")
	_ = cmd.MarkFlagRequired("path")
	_ = cmd.MarkFlagRequired("root-fingerprint")
	return cmd
}

func recoveryVerifyCmd() *cobra.Command {
	var path string
	var recoveryPubkeyHex string
	var recoveryPubkeyFile string
	var pinnedFingerprint string
	var expectedTargetRosterHash string

	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify a recovery authorization file",
		Long: `Loads and verifies a recovery authorization against the
specified recovery-root public key and pinned fingerprint. Checks
the signature, time window, lifetime ceiling, and structural validity.

The optional --expected-target-roster-hash binds the authorization to a
specific roster body. Empty invokes the offline-inspection path
(InspectRecoveryAuthorizationOffline) which skips the binding check; this
is appropriate for ceremony review when the target hash is not yet known.
The runtime LoadRecoveryAuthorization API in internal/signing rejects an
empty value at the boundary so a forgotten parameter cannot bypass the
binding silently in production code.

Pass the recovery-root public key via --recovery-pubkey-file (preferred for
ceremony durability; the file path stays in audit trail) or via
--recovery-pubkey for ad-hoc/test usage. Exactly one must be set.
Exit 0 on success, non-zero on failure.

Examples:
  pipelock signing recovery verify --path recovery.json --recovery-pubkey-file pub.hex --pinned-fingerprint sha256:abc123...
  pipelock signing recovery verify --path recovery.json --recovery-pubkey <64-char-hex> --pinned-fingerprint sha256:abc...
  pipelock signing recovery verify --path recovery.json --recovery-pubkey-file pub.hex --pinned-fingerprint sha256:abc... --expected-target-roster-hash sha256:def...`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			pubBytes, err := resolvePubkey("recovery-pubkey", recoveryPubkeyHex, recoveryPubkeyFile)
			if err != nil {
				_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "verify failed: %v\n", err)
				return err
			}

			// Compute and surface the fingerprint of the key we ACTUALLY
			// loaded so the operator can confirm the trust anchor before
			// trusting any verdict line below it. Mismatch with the pinned
			// expectation would be caught by the loader, but printing the
			// computed value first gives a visible cross-check.
			computedFP, fpErr := domsigning.Fingerprint(pubBytes)
			if fpErr != nil {
				_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "verify failed: %v\n", fpErr)
				return fpErr
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(),
				"loaded recovery-root: fingerprint=%s\n", computedFP)

			var loaded *domsigning.LoadedRecoveryAuthorization
			if expectedTargetRosterHash == "" {
				loaded, err = domsigning.InspectRecoveryAuthorizationOffline(
					filepath.Clean(path), pubBytes, pinnedFingerprint, time.Now())
			} else {
				loaded, err = domsigning.LoadRecoveryAuthorization(
					filepath.Clean(path), pubBytes, pinnedFingerprint,
					expectedTargetRosterHash, time.Now())
			}
			if err != nil {
				_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "verify failed: %v\n", err)
				return err
			}

			// Quote attacker-controlled fields before printing so a hostile
			// signed file with control characters in reason/operator_identity
			// cannot repaint the operator's terminal during ceremony review.
			// expires_at is RFC 3339 validated by the loader so it does not
			// need quoting; reason and operator_identity are free-form.
			_, _ = fmt.Fprintf(cmd.OutOrStdout(),
				"recovery authorization verified: reason=%s, expires_at=%s, operator=%s\n",
				sanitizeForTerminal(loaded.Body.Reason),
				loaded.Body.ExpiresAt,
				sanitizeForTerminal(loaded.Body.OperatorIdentity))
			if expectedTargetRosterHash == "" {
				_, _ = fmt.Fprintln(cmd.OutOrStdout(),
					"NOTE: target_roster_hash binding NOT verified (offline mode). Runtime callers MUST pass --expected-target-roster-hash.")
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&path, "path", "", "path to recovery authorization file")
	cmd.Flags().StringVar(&recoveryPubkeyHex, "recovery-pubkey", "", "recovery-root public key (64-char hex; for ad-hoc/test use)")
	cmd.Flags().StringVar(&recoveryPubkeyFile, "recovery-pubkey-file", "", "path to file containing the recovery-root public key as 64-char hex")
	cmd.Flags().StringVar(&pinnedFingerprint, "pinned-fingerprint", "", "operator-pinned recovery-root fingerprint (sha256:...)")
	cmd.Flags().StringVar(&expectedTargetRosterHash, "expected-target-roster-hash", "", "expected target roster hash (sha256:...); empty = skip binding check (offline only)")
	_ = cmd.MarkFlagRequired("path")
	_ = cmd.MarkFlagRequired("pinned-fingerprint")
	cmd.MarkFlagsOneRequired("recovery-pubkey", "recovery-pubkey-file")
	cmd.MarkFlagsMutuallyExclusive("recovery-pubkey", "recovery-pubkey-file")
	return cmd
}

func transitionVerifyCmd() *cobra.Command {
	var path string
	var oldPubkeyHex string
	var oldPubkeyFile string
	var newPubkeyHex string
	var newPubkeyFile string
	var pinnedFingerprint string

	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify a root transition document's dual signatures",
		Long: `Loads and verifies a root transition document against both
the old and new public keys. Both signatures must be valid. When
--pinned is supplied, the old fingerprint in the document must
match it.

Pass each public key via --*-pubkey-file (preferred for ceremony durability;
the file path stays in audit trail) or via --*-pubkey for ad-hoc/test
usage. Exactly one of each pair must be set.
Exit 0 on success, non-zero on failure.

Examples:
  pipelock signing transition verify --path transition.json --old-pubkey-file old.hex --new-pubkey-file new.hex
  pipelock signing transition verify --path transition.json --old-pubkey <hex> --new-pubkey <hex> --pinned sha256:abc123...`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			oldPub, err := resolvePubkey("old-pubkey", oldPubkeyHex, oldPubkeyFile)
			if err != nil {
				_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "verify failed: %v\n", err)
				return err
			}
			newPub, err := resolvePubkey("new-pubkey", newPubkeyHex, newPubkeyFile)
			if err != nil {
				_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "verify failed: %v\n", err)
				return err
			}

			// Echo the fingerprints of the two keys we ACTUALLY loaded so
			// the operator confirms the trust anchors before trusting any
			// verdict line below them.
			oldFP, fpErr := domsigning.Fingerprint(oldPub)
			if fpErr != nil {
				_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "verify failed: %v\n", fpErr)
				return fpErr
			}
			newFP, fpErr := domsigning.Fingerprint(newPub)
			if fpErr != nil {
				_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "verify failed: %v\n", fpErr)
				return fpErr
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(),
				"loaded transition keys: old_fingerprint=%s, new_fingerprint=%s\n",
				oldFP, newFP)

			loaded, err := domsigning.LoadRootTransition(
				filepath.Clean(path), oldPub, newPub, pinnedFingerprint)
			if err != nil {
				_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "verify failed: %v\n", err)
				return err
			}

			// RootKind is enum-validated and OldFingerprint/NewFingerprint
			// match the sha256:<hex> pattern, so they don't carry control
			// characters; effective_at is RFC 3339 validated by the loader.
			// No quoting needed for these — they're constrained.
			_, _ = fmt.Fprintf(cmd.OutOrStdout(),
				"transition verified: kind=%s, old=%s, new=%s, effective_at=%s\n",
				loaded.Body.RootKind, loaded.Body.OldFingerprint,
				loaded.Body.NewFingerprint, loaded.Body.EffectiveAt)
			return nil
		},
	}

	cmd.Flags().StringVar(&path, "path", "", "path to root transition file")
	cmd.Flags().StringVar(&oldPubkeyHex, "old-pubkey", "", "old root public key (64-char hex; for ad-hoc/test use)")
	cmd.Flags().StringVar(&oldPubkeyFile, "old-pubkey-file", "", "path to file containing the old root public key as 64-char hex")
	cmd.Flags().StringVar(&newPubkeyHex, "new-pubkey", "", "new root public key (64-char hex; for ad-hoc/test use)")
	cmd.Flags().StringVar(&newPubkeyFile, "new-pubkey-file", "", "path to file containing the new root public key as 64-char hex")
	cmd.Flags().StringVar(&pinnedFingerprint, "pinned", "", "operator-pinned old fingerprint (sha256:..., optional)")
	_ = cmd.MarkFlagRequired("path")
	cmd.MarkFlagsOneRequired("old-pubkey", "old-pubkey-file")
	cmd.MarkFlagsMutuallyExclusive("old-pubkey", "old-pubkey-file")
	cmd.MarkFlagsOneRequired("new-pubkey", "new-pubkey-file")
	cmd.MarkFlagsMutuallyExclusive("new-pubkey", "new-pubkey-file")
	return cmd
}

// decodeHexPubkey decodes a 64-character hex string into a 32-byte Ed25519
// public key. Returns a descriptive error on invalid input.
func decodeHexPubkey(hexStr string) ([]byte, error) {
	if len(hexStr) != ed25519PubKeyHexLen {
		return nil, fmt.Errorf("hex public key must be %d characters, got %d", ed25519PubKeyHexLen, len(hexStr))
	}
	b, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, fmt.Errorf("invalid hex in public key: %w", err)
	}
	return b, nil
}

// readPubkeyFile reads a hex-encoded Ed25519 public key from disk. The file
// is expected to contain exactly the 64-hex-character form, optionally with
// surrounding whitespace (newline trailing, etc.). Decodes and returns the
// 32-byte raw key.
//
// Why files: ceremony commands previously took --*-pubkey as raw CLI args.
// On multi-user systems those values appear in process listings and shell
// history. Public keys are not secret, but durable provenance of which trust
// anchor was used during a key ceremony belongs in a file, not on argv.
func readPubkeyFile(path string) ([]byte, error) {
	cleanPath := filepath.Clean(path)
	info, err := os.Stat(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("stat public key file %q: %w", cleanPath, err)
	}
	if info.Size() > pubkeyFileMaxSize {
		return nil, fmt.Errorf("%w: %d bytes (cap %d): %q",
			errPubkeyFileTooLarge, info.Size(), pubkeyFileMaxSize, cleanPath)
	}
	raw, err := os.ReadFile(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("read public key file %q: %w", cleanPath, err)
	}
	hexStr := strings.TrimSpace(string(raw))
	return decodeHexPubkey(hexStr)
}

// resolvePubkey returns the raw key bytes from either an inline hex flag or
// a file flag. Exactly one must be non-empty; cobra's MarkFlagsOneRequired +
// MarkFlagsMutuallyExclusive enforce this at parse time, so the empty/dual
// cases are defense in depth.
//
// Errors are wrapped with "invalid <label>: ..." so the CLI's stderr message
// makes the offending flag obvious.
func resolvePubkey(label, hexFlag, fileFlag string) ([]byte, error) {
	if hexFlag != "" && fileFlag != "" {
		return nil, fmt.Errorf("invalid %s: pass either --%s or --%s-file, not both", label, label, label)
	}
	if fileFlag != "" {
		key, err := readPubkeyFile(fileFlag)
		if err != nil {
			return nil, fmt.Errorf("invalid %s: %w", label, err)
		}
		return key, nil
	}
	if hexFlag != "" {
		key, err := decodeHexPubkey(hexFlag)
		if err != nil {
			return nil, fmt.Errorf("invalid %s: %w", label, err)
		}
		return key, nil
	}
	return nil, fmt.Errorf("invalid %s: --%s or --%s-file is required", label, label, label)
}

// sanitizeForTerminal returns a Go-quoted form of s suitable for printing to
// a terminal without risking control-character or newline injection. Even
// signed artifact fields like reason and operator_identity are
// attacker-controlled before signing — an operator tricked into verifying a
// hostile signed file should not have their terminal repainted by the
// printed output. %q escapes control bytes and quotes the result so the
// boundary between operator-supplied content and CLI chrome stays visible.
func sanitizeForTerminal(s string) string {
	return fmt.Sprintf("%q", s)
}
