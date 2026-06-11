// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package signing

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/atomicfile"
	"github.com/luckyPipewrench/pipelock/internal/secperm"
	domsigning "github.com/luckyPipewrench/pipelock/internal/signing"
)

// keyFileSchemaVersion is the wire schema version of files written by
// "pipelock signing key generate". Bump only on a breaking change.
const keyFileSchemaVersion = 1

// keyFileShortFingerprintHex is the number of hex chars taken from the
// canonical sha256 fingerprint when deriving a default key_id.
const keyFileShortFingerprintHex = 8

// keyFileMaxSize caps JSON key files accepted by the roster CLI. Generated
// files are under 1 KiB; this leaves room for formatting while avoiding
// accidental reads of large non-key files.
const keyFileMaxSize = 16 * 1024

// privateKeyDisallowedPermBits masks group-write, group-execute, and all world
// bits. Group-read is allowed for Kubernetes fsGroup read-only mounts.
const privateKeyDisallowedPermBits = 0o037

// fingerprintPrefix is the canonical prefix on sha256 fingerprints emitted
// by signing.Fingerprint and consumed by pinned-fingerprint config fields.
const fingerprintPrefix = "sha256:"

var errKeyFileTooLarge = errors.New("key file exceeds size cap")

func keyPurposeUsage() string {
	purposes := domsigning.KnownPurposes()
	labels := make([]string, 0, len(purposes))
	for _, purpose := range purposes {
		labels = append(labels, purpose.String())
	}
	return strings.Join(labels, ", ")
}

func isReservedConductorKeyPurpose(purpose domsigning.KeyPurpose) bool {
	switch purpose {
	case domsigning.PurposeTrustRootRotation, domsigning.PurposeEnrollmentTokenSigning:
		return true
	default:
		return false
	}
}

// keyFile is the on-disk JSON shape produced by "pipelock signing key generate".
// Both private and public keys are stored hex-encoded; the file is written
// 0o600 because the private key is sensitive.
type keyFile struct {
	SchemaVersion int    `json:"schema_version"`
	Purpose       string `json:"purpose"`
	KeyID         string `json:"key_id"`
	Public        string `json:"public"`     // 64-char hex
	Private       string `json:"private"`    // 128-char hex
	CreatedAt     string `json:"created_at"` // RFC 3339 UTC
}

// keyGenerateGroupCmd is the parent "key" cobra command hosting key
// generation subcommands. Distinct from the agent-scoped pipelock keygen
// command because deployment-level keys (root, activation) live outside the
// per-agent keystore layout and carry an explicit purpose binding.
func keyGenerateGroupCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "key",
		Short: "Generate deployment-level signing keys",
		Long: `Generate deployment-level Ed25519 keys with explicit purpose
binding. Subcommands:
  generate    Generate one keypair bound to a recognised wire purpose`,
	}
	cmd.AddCommand(keyGenerateCmd())
	return cmd
}

func keyGenerateCmd() *cobra.Command {
	var purpose string
	var outPath string
	var keyID string
	var force bool

	cmd := &cobra.Command{
		Use:   "generate",
		Short: "Generate an Ed25519 keypair bound to a specific purpose",
		Long: `Generates a new Ed25519 keypair for a deployment-level role and
writes it to disk as a JSON file. Distinct from "pipelock keygen <agent>",
which writes per-agent keystore files under ~/.pipelock/agents/.

The --purpose flag binds the key to one of the recognised wire purposes:
  roster-root                    deployment-local trust root that signs the roster
  contract-activation-signing    operator key that signs ratify and promote
  contract-compile-signing       per-agent compile signing
  recovery-root                  break-glass root for recovery operations
  receipt-signing                runtime receipt signing
  rules-official-signing         official rules package signing
  policy-bundle-signing          Conductor policy bundle signing
  policy-bundle-rollback         Conductor rollback authorization signing
  remote-kill-signing            Conductor remote kill-switch signing
  trust-root-rotation            reserved Conductor trust-root rotation signing
  audit-batch-signing            Conductor follower audit batch signing
  enrollment-token-signing       reserved Conductor enrollment-token signing

Conductor rollback, remote-kill, and trust-root-rotation keys are threshold
keys: generate independent keys for separate approvers and configure the
Conductor roster/control plane to require the fleet threshold. Reserved
purposes are wire-stable purpose bindings, but no shipped operator workflow
consumes them yet.

Writes a 0o600 JSON file containing schema_version, purpose, key_id, public
(hex), private (hex), and created_at. The canonical sha256 fingerprint is
printed on success for use in pinned_root_fingerprint configuration.

Examples:
  pipelock signing key generate --purpose roster-root --out /etc/pipelock/keys/fleet-root.json
  pipelock signing key generate --purpose contract-activation-signing \
    --out /etc/pipelock/keys/activation.json --id activation-primary`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			out := cmd.OutOrStdout()

			kp := domsigning.KeyPurpose(purpose)
			if err := kp.Validate(); err != nil {
				return err
			}

			if !filepath.IsAbs(outPath) {
				return fmt.Errorf("--out must be absolute, got %q", outPath)
			}
			cleanOut := filepath.Clean(outPath)

			if !force {
				if _, statErr := os.Stat(cleanOut); statErr == nil {
					return fmt.Errorf("output file %q already exists (use --force to overwrite)", cleanOut)
				} else if !errors.Is(statErr, os.ErrNotExist) {
					return fmt.Errorf("stat output file %q: %w", cleanOut, statErr)
				}
			}

			pub, priv, err := domsigning.GenerateKeyPair()
			if err != nil {
				return err
			}

			fp, err := domsigning.Fingerprint(pub)
			if err != nil {
				return fmt.Errorf("compute fingerprint: %w", err)
			}

			resolvedID := keyID
			if resolvedID == "" {
				short := strings.TrimPrefix(fp, fingerprintPrefix)
				if len(short) > keyFileShortFingerprintHex {
					short = short[:keyFileShortFingerprintHex]
				}
				resolvedID = fmt.Sprintf("%s-%s", purpose, short)
			}

			file := keyFile{
				SchemaVersion: keyFileSchemaVersion,
				Purpose:       purpose,
				KeyID:         resolvedID,
				Public:        hex.EncodeToString(pub),
				Private:       hex.EncodeToString(priv),
				CreatedAt:     time.Now().UTC().Format(time.RFC3339),
			}

			data, err := json.MarshalIndent(file, "", "  ")
			if err != nil {
				return fmt.Errorf("marshal key file: %w", err)
			}
			data = append(data, '\n')

			if err := atomicfile.Write(cleanOut, data, 0o600); err != nil {
				return fmt.Errorf("write key file: %w", err)
			}

			_, _ = fmt.Fprintf(out, "Generated %s keypair\n", purpose)
			_, _ = fmt.Fprintf(out, "  key_id:      %s\n", resolvedID)
			_, _ = fmt.Fprintf(out, "  fingerprint: %s\n", fp)
			if isReservedConductorKeyPurpose(kp) {
				_, _ = fmt.Fprintf(out, "  status:      reserved purpose; no shipped operator workflow consumes this key yet\n")
			}
			if kp.RequiresConductorThreshold() {
				_, _ = fmt.Fprintf(out, "  threshold:   required for this Conductor purpose; do not deploy as a single-signer authority\n")
			}
			_, _ = fmt.Fprintf(out, "  out:         %s\n", cleanOut)
			return nil
		},
	}

	cmd.Flags().StringVar(&purpose, "purpose", "",
		"key purpose (one of: "+keyPurposeUsage()+")")
	cmd.Flags().StringVar(&outPath, "out", "", "absolute output path for the keypair JSON file")
	cmd.Flags().StringVar(&keyID, "id", "", "operator-chosen key ID (default: <purpose>-<short-fingerprint>)")
	cmd.Flags().BoolVar(&force, "force", false, "overwrite an existing output file")
	_ = cmd.MarkFlagRequired("purpose")
	_ = cmd.MarkFlagRequired("out")
	return cmd
}

// loadKeyFile reads a keyFile from disk and returns the parsed struct
// alongside the decoded public and private keys. If expectedPurpose is
// non-empty, the file's purpose field must match exactly.
//
// Strict JSON decoding rejects unknown fields so a hostile or stale key file
// cannot smuggle extra metadata past the loader.
func loadKeyFile(path string, expectedPurpose domsigning.KeyPurpose) (*keyFile, ed25519.PublicKey, ed25519.PrivateKey, error) {
	cleanPath := filepath.Clean(path)
	raw, err := ReadKeyFileBytes(cleanPath, true)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("read key file %q: %w", cleanPath, err)
	}
	kf, err := decodeKeyFile(raw)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("decode key file %q: %w", cleanPath, err)
	}
	kp, err := validateKeyFileMetadata(kf)
	if err != nil {
		return nil, nil, nil, err
	}
	if expectedPurpose != "" && kp != expectedPurpose {
		return nil, nil, nil, fmt.Errorf("key file purpose mismatch: file=%q expected=%q", kf.Purpose, expectedPurpose)
	}
	pubBytes, err := decodeKeyFilePublic(kf)
	if err != nil {
		return nil, nil, nil, err
	}
	privBytes, err := hex.DecodeString(kf.Private)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("decode private key hex: %w", err)
	}
	if len(privBytes) != ed25519.PrivateKeySize {
		return nil, nil, nil, fmt.Errorf("private key has wrong size: got %d, want %d", len(privBytes), ed25519.PrivateKeySize)
	}
	priv := ed25519.PrivateKey(privBytes)
	derivedPub, ok := priv.Public().(ed25519.PublicKey)
	if !ok || !bytes.Equal(derivedPub, pubBytes) {
		return nil, nil, nil, fmt.Errorf("private key does not match public key")
	}
	return &kf, pubBytes, priv, nil
}

// readPublicKeyForRoster reads a public key from disk in either the JSON
// keyFile format produced by "pipelock signing key generate" or the agent
// keystore .pub format produced by "pipelock keygen". Returns the raw
// 32-byte public key and the file's declared purpose if available.
//
// The detected purpose is used to enforce that a roster --include entry's
// purpose= flag matches the file's binding. The agent keystore .pub format
// has no purpose field, so callers fall back to the operator-supplied flag.
func readPublicKeyForRoster(path string) ([]byte, string, error) {
	cleanPath := filepath.Clean(path)
	raw, err := ReadKeyFileBytes(cleanPath, false)
	if err != nil {
		return nil, "", fmt.Errorf("read public key %q: %w", cleanPath, err)
	}
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) > 0 && trimmed[0] == '{' {
		// Delegate to loadKeyFile so the include path inherits the full
		// keyFile gate (schema, purpose, hex sizes, trailing JSON, AND the
		// private->public derivation check). Otherwise an include-side
		// keyFile with a tampered private half could be silently accepted
		// since this branch never uses the private key.
		kf, pub, _, err := loadKeyFile(cleanPath, "")
		if err != nil {
			return nil, "", fmt.Errorf("decode key file %q: %w", cleanPath, err)
		}
		return pub, kf.Purpose, nil
	}
	pub, err := domsigning.DecodePublicKey(string(raw))
	if err != nil {
		return nil, "", fmt.Errorf("decode agent keystore .pub file %q: %w", cleanPath, err)
	}
	return pub, "", nil
}

// ReadKeyFileBytes reads a key file from disk with the secure gates every
// key-file consumer needs: reject a symlink AT the path, reject a non-regular
// target (device/FIFO), optionally reject group/other-accessible permissions
// (requireSecretPerms), and bound the read to keyFileMaxSize (16 KiB).
//
// Exported so non-signing callers (e.g. the Conductor publish CLI's
// policy-bundle-signing key loader) reuse this one secure reader instead of
// duplicating the open/stat/perm/size dance — and the one gosec G304 suppression
// on the operator-path os.Open below lives in exactly one place.
//
// The symlink check is explicit and must come BEFORE os.Open: os.Open FOLLOWS
// symlinks, so a later f.Stat() reports the TARGET's mode and would silently
// accept a symlink pointing at a 0600 regular file the operator never named (a
// local confused-deputy vector). We os.Lstat the path first and reject
// os.ModeSymlink, THEN open and fd-stat so every subsequent check runs against
// the descriptor we actually read from.
func ReadKeyFileBytes(cleanPath string, requireSecretPerms bool) ([]byte, error) {
	lst, err := os.Lstat(cleanPath)
	if err != nil {
		return nil, err
	}
	if lst.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("key file %q is a symlink; pass the real key file path", cleanPath)
	}
	// Open first so the subsequent Stat is on the same file descriptor
	// (TOCTOU defense) AND so a non-regular file like a FIFO or device
	// is detected before any read can block. Plain os.Stat + os.ReadFile
	// would happily ReadFile-block-forever on a named pipe whose size
	// reports 0.
	f, err := os.Open(cleanPath) //nolint:gosec // path is operator-supplied and cleaned; size cap and regular-file check below
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("key file %q is not a regular file (mode=%s)", cleanPath, info.Mode())
	}
	if requireSecretPerms && secperm.TooPermissive(info.Mode().Perm(), privateKeyDisallowedPermBits) {
		return nil, fmt.Errorf("private key %s has permissions %04o, want 0600 or 0640 (run: chmod 640 %s)", cleanPath, info.Mode().Perm(), cleanPath)
	}
	if info.Size() > keyFileMaxSize {
		return nil, fmt.Errorf("%w: got %d bytes, max %d", errKeyFileTooLarge, info.Size(), keyFileMaxSize)
	}
	// LimitReader is belt-and-suspenders: even if the file grew between
	// stat and read, the read is bounded.
	raw, err := io.ReadAll(io.LimitReader(f, keyFileMaxSize+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > keyFileMaxSize {
		return nil, fmt.Errorf("%w: got %d bytes, max %d", errKeyFileTooLarge, len(raw), keyFileMaxSize)
	}
	return raw, nil
}

func decodeKeyFile(raw []byte) (keyFile, error) {
	var kf keyFile
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&kf); err != nil {
		return keyFile{}, err
	}
	var extra any
	if err := dec.Decode(&extra); err == nil {
		return keyFile{}, fmt.Errorf("trailing JSON after key file object")
	} else if !errors.Is(err, io.EOF) {
		return keyFile{}, fmt.Errorf("trailing JSON after key file object")
	}
	return kf, nil
}

func validateKeyFileMetadata(kf keyFile) (domsigning.KeyPurpose, error) {
	if kf.SchemaVersion != keyFileSchemaVersion {
		return "", fmt.Errorf("unsupported key file schema_version %d (expected %d)", kf.SchemaVersion, keyFileSchemaVersion)
	}
	kp := domsigning.KeyPurpose(kf.Purpose)
	if err := kp.Validate(); err != nil {
		return "", fmt.Errorf("invalid key file purpose: %w", err)
	}
	return kp, nil
}

func decodeKeyFilePublic(kf keyFile) (ed25519.PublicKey, error) {
	pubBytes, err := hex.DecodeString(kf.Public)
	if err != nil {
		return nil, fmt.Errorf("decode public key hex: %w", err)
	}
	if len(pubBytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("public key has wrong size: got %d, want %d", len(pubBytes), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(pubBytes), nil
}
