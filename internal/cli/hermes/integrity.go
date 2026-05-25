// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package hermes

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/signing"
)

// Hermes seeds identity-anchor files (SOUL.md, IDENTITY.md, AGENTS.md) onto the
// agent's persistent workspace once, then never re-seeds them. An attacker who
// can write that workspace can therefore overwrite the agent's identity and
// have it persist across restarts, since the seed step only writes the files
// when they are absent. The anchor-integrity primitive pins those files:
// `seal` records a SHA-256 of each anchor and signs the manifest with an
// operator-held Ed25519 key; `verify` (run by a startup/init step) refuses to
// start when an anchor no longer matches or the manifest signature is invalid.
//
// Why a signature rather than a keyed MAC: verify needs only the PUBLIC key,
// which can sit in the cluster (a Secret or ConfigMap) with no risk, while the
// private signing key stays off-cluster and is used only at seal time. A fully
// compromised agent or cluster therefore cannot forge a baseline at all. The
// signature covers the whole {version, digest_algorithm, digests} manifest, so
// an attacker who can write the baseline cannot add, drop, or alter an anchor
// entry, downgrade the version, or swap in a baseline signed by another key.
//
// Coverage boundary: verify is a point-in-time check at startup. It detects
// tampering that persisted from before boot and refuses to start; it does not
// prevent writes to the workspace while the agent runs. Closing that window is
// a deployment concern — mount the anchor files (and ideally the baseline)
// read-only to the agent — handled by the cluster identity/topology layer, not
// this command.

const (
	// defaultAnchorBaselineName is the baseline manifest filename written under
	// the workspace by `seal` and read by `verify`. Override with --baseline to
	// place it on a read-only mount the agent cannot delete.
	defaultAnchorBaselineName = ".pipelock-anchors.json"
	anchorBaselineVersion     = 1
	anchorDigestAlgorithm     = "sha256"
	anchorSignatureAlgorithm  = "ed25519"
)

// manifestDomainPrefix domain-separates the signed payload so an anchor
// manifest signature can never be mistaken for a signature over any other
// pipelock artifact.
const manifestDomainPrefix = "pipelock hermes anchors manifest v1\n"

// defaultAnchorFiles are the immutable Hermes identity files whose integrity is
// pinned. MEMORY.md is intentionally excluded: it changes legitimately as the
// agent curates memory across sessions, so it is not an identity anchor.
var defaultAnchorFiles = []string{"SOUL.md", "IDENTITY.md", "AGENTS.md"}

// maxAnchorSize caps an anchor file read. Identity anchors are small text
// files; a multi-gigabyte anchor (or a symlink to a device) would otherwise OOM
// or hang verify at startup. 16 MiB is far above any legitimate anchor. A
// package var (not const) only so tests can lower it without writing a 16 MiB
// fixture; production never reassigns it.
var maxAnchorSize int64 = 16 << 20

// anchorBaseline is the on-disk signed manifest. Digests maps each anchor file
// name (relative to the workspace) to the hex SHA-256 of its content. Signature
// is the hex Ed25519 signature over the canonical {version, digest_algorithm,
// digests} payload.
type anchorBaseline struct {
	Version            int               `json:"version"`
	DigestAlgorithm    string            `json:"digest_algorithm"`
	SignatureAlgorithm string            `json:"signature_algorithm"`
	Digests            map[string]string `json:"digests"`
	Signature          string            `json:"signature"`
}

// anchorManifestPayload is the exact, signature-free structure that is signed
// and verified. Field order and json tags are fixed; json.Marshal sorts map
// keys, so the encoding is deterministic across seal and verify.
type anchorManifestPayload struct {
	Version         int               `json:"version"`
	DigestAlgorithm string            `json:"digest_algorithm"`
	Digests         map[string]string `json:"digests"`
}

// anchorOptions holds the flags for seal and verify. SigningKey is used by seal
// (Ed25519 private key); PublicKey is used by verify (Ed25519 public key, path
// or inline value).
type anchorOptions struct {
	Workspace  string
	SigningKey string
	PublicKey  string
	Baseline   string
	Anchors    []string
	HomeDir    string
}

// resolvePaths fills Workspace, Baseline, and Anchors from HOME/defaults when
// unset and validates the anchor names. Key validation is per-subcommand.
func (o *anchorOptions) resolvePaths() error {
	if o.Workspace == "" {
		home := o.HomeDir
		if home == "" {
			detected, err := userHomeDir()
			if err != nil {
				return fmt.Errorf("hermes anchors: %w", err)
			}
			home = detected
		}
		o.Workspace = filepath.Join(home, ".hermes")
	}
	if o.Baseline == "" {
		o.Baseline = filepath.Join(o.Workspace, defaultAnchorBaselineName)
	}
	if len(o.Anchors) == 0 {
		o.Anchors = append([]string(nil), defaultAnchorFiles...)
	}
	return validateAnchorNames(o.Anchors)
}

// rejectKeyInsideWorkspace refuses a key path that lives (directly or via
// symlink) under the agent-writable workspace. For the private signing key this
// keeps the secret out of the agent's reach; for the public verify key it stops
// an attacker from swapping the key the baseline is checked against.
func rejectKeyInsideWorkspace(workspace, keyPath string) error {
	workspaceAbs, err := filepath.Abs(filepath.Clean(workspace))
	if err != nil {
		return fmt.Errorf("hermes anchors: workspace: %w", err)
	}
	keyAbs, err := filepath.Abs(filepath.Clean(keyPath))
	if err != nil {
		return fmt.Errorf("hermes anchors: key file: %w", err)
	}
	if isSubpath(workspaceAbs, keyAbs) {
		return fmt.Errorf("hermes anchors: key file %q must not live under workspace %q", keyPath, workspace)
	}
	resolvedWorkspace := workspaceAbs
	if rw, err := filepath.EvalSymlinks(workspaceAbs); err == nil {
		resolvedWorkspace = rw
	}
	if resolvedKey, err := filepath.EvalSymlinks(keyAbs); err == nil {
		if isSubpath(workspaceAbs, resolvedKey) || isSubpath(resolvedWorkspace, resolvedKey) {
			return fmt.Errorf("hermes anchors: key file %q resolves under workspace %q", keyPath, workspace)
		}
	}
	if isSubpath(resolvedWorkspace, keyAbs) {
		return fmt.Errorf("hermes anchors: key file %q must not live under workspace %q", keyPath, workspace)
	}
	return nil
}

func isSubpath(parent, child string) bool {
	parent = filepath.Clean(parent)
	child = filepath.Clean(child)
	if parent == child {
		return true
	}
	rel, err := filepath.Rel(parent, child)
	if err != nil {
		return false
	}
	return rel != "." && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func validateAnchorNames(anchors []string) error {
	if len(anchors) == 0 {
		return errors.New("hermes anchors: no anchors specified")
	}
	seen := make(map[string]struct{}, len(anchors))
	for _, name := range anchors {
		clean := filepath.Clean(name)
		if name == "" || filepath.IsAbs(name) || clean == "." || clean != name ||
			clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
			return fmt.Errorf("hermes anchors: anchor %q must be a clean relative path under --workspace", name)
		}
		if _, ok := seen[name]; ok {
			return fmt.Errorf("hermes anchors: duplicate anchor %q", name)
		}
		seen[name] = struct{}{}
	}
	return nil
}

// computeAnchorDigest returns the hex SHA-256 of one anchor file's content. The
// anchor must be a plain, bounded regular file: a missing, symlinked,
// non-regular, or oversized anchor is an error so verify fails closed and a
// tampered anchor cannot turn verify into a device read or an OOM.
func computeAnchorDigest(workspace, name string) (string, error) {
	path := filepath.Clean(filepath.Join(workspace, name))
	info, err := os.Lstat(path)
	if err != nil {
		return "", fmt.Errorf("anchor %q: %w", name, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("anchor %q: is a symlink; identity anchors must be regular files", name)
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("anchor %q: not a regular file (mode=%s)", name, info.Mode())
	}
	if info.Size() > maxAnchorSize {
		return "", fmt.Errorf("anchor %q: %d bytes exceeds the %d-byte anchor limit", name, info.Size(), maxAnchorSize)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("anchor %q: %w", name, err)
	}
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:]), nil
}

func computeAnchorDigests(workspace string, anchors []string) (map[string]string, error) {
	digests := make(map[string]string, len(anchors))
	names := append([]string(nil), anchors...)
	sort.Strings(names)
	for _, name := range names {
		digest, err := computeAnchorDigest(workspace, name)
		if err != nil {
			return nil, err
		}
		digests[name] = digest
	}
	return digests, nil
}

// canonicalManifestBytes returns the deterministic, domain-prefixed bytes that
// are signed at seal and verified at verify.
func canonicalManifestBytes(version int, digestAlgorithm string, digests map[string]string) ([]byte, error) {
	payload := anchorManifestPayload{
		Version:         version,
		DigestAlgorithm: digestAlgorithm,
		Digests:         digests,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("encode anchor manifest payload: %w", err)
	}
	return append([]byte(manifestDomainPrefix), data...), nil
}

func anchorsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "anchors",
		Short: "Pin and verify the integrity of Hermes identity-anchor files",
		Long: `Protect the immutable Hermes identity files (SOUL.md, IDENTITY.md,
AGENTS.md) against persistent tampering on a writable workspace.

'seal' records a SHA-256 of each anchor and signs the manifest with an
operator-held Ed25519 private key; 'verify' (run at startup, e.g. from a
Kubernetes init container) recomputes the digests, checks the signature against
the public key, and exits non-zero if any anchor has drifted, refusing to start
the agent.

Only the PUBLIC key is needed in-cluster to verify; keep the private signing key
off-cluster and use it only at seal time, so a compromised agent cannot forge a
baseline. The public key must come from a trusted, non-workspace location (a
read-only Secret/ConfigMap), never the agent-writable workspace. Run 'verify'
with the same --anchor set used for 'seal': verify requires the baseline to
cover exactly the requested anchors.`,
	}
	cmd.AddCommand(anchorsSealCmd(), anchorsVerifyCmd())
	return cmd
}

func anchorsSealCmd() *cobra.Command {
	opts := &anchorOptions{}
	cmd := &cobra.Command{
		Use:   "seal",
		Short: "Record and Ed25519-sign the baseline of the identity-anchor files",
		Long: `Compute SHA-256(content) for each identity-anchor file and sign the manifest
with an Ed25519 private key. Run once after the anchors are seeded and trusted;
re-run after a deliberate, reviewed change to an anchor.`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runAnchorsSeal(cmd, opts)
		},
	}
	bindCommonAnchorFlags(cmd, opts)
	cmd.Flags().StringVar(&opts.SigningKey, "signing-key", "",
		"path to the Ed25519 private signing key (0600/0640; keep off-cluster and off the workspace)")
	return cmd
}

func anchorsVerifyCmd() *cobra.Command {
	opts := &anchorOptions{}
	var jsonOut bool
	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify the identity anchors against the signed baseline",
		Long: `Recompute SHA-256(content) for each anchor in the baseline, verify the
manifest's Ed25519 signature against the public key, and compare digests in
constant time. Exits non-zero if the signature is invalid or any anchor is
missing, unreadable, or altered, so a Kubernetes init container running this
command refuses to start the agent on tampering.`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runAnchorsVerify(cmd, opts, jsonOut)
		},
	}
	bindCommonAnchorFlags(cmd, opts)
	cmd.Flags().StringVar(&opts.PublicKey, "public-key", "",
		"Ed25519 public key to verify the baseline: a file path or an inline encoded key")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "emit the verification report as JSON")
	return cmd
}

func bindCommonAnchorFlags(cmd *cobra.Command, opts *anchorOptions) {
	cmd.Flags().StringVar(&opts.Workspace, "workspace", "",
		"directory holding the anchor files (default ~/.hermes)")
	cmd.Flags().StringVar(&opts.Baseline, "baseline", "",
		"path to the baseline manifest (default <workspace>/"+defaultAnchorBaselineName+")")
	cmd.Flags().StringArrayVar(&opts.Anchors, "anchor", nil,
		"anchor file name relative to --workspace (repeatable; default SOUL.md, IDENTITY.md, AGENTS.md)")
}

func runAnchorsSeal(cmd *cobra.Command, opts *anchorOptions) error {
	if opts.SigningKey == "" {
		return errors.New("hermes anchors seal: --signing-key is required")
	}
	if err := opts.resolvePaths(); err != nil {
		return err
	}
	if err := rejectKeyInsideWorkspace(opts.Workspace, opts.SigningKey); err != nil {
		return err
	}
	priv, err := signing.LoadPrivateKeyFile(opts.SigningKey)
	if err != nil {
		return fmt.Errorf("hermes anchors seal: signing key: %w", err)
	}
	digests, err := computeAnchorDigests(opts.Workspace, opts.Anchors)
	if err != nil {
		return fmt.Errorf("hermes anchors seal: %w", err)
	}
	payload, err := canonicalManifestBytes(anchorBaselineVersion, anchorDigestAlgorithm, digests)
	if err != nil {
		return fmt.Errorf("hermes anchors seal: %w", err)
	}
	baseline := anchorBaseline{
		Version:            anchorBaselineVersion,
		DigestAlgorithm:    anchorDigestAlgorithm,
		SignatureAlgorithm: anchorSignatureAlgorithm,
		Digests:            digests,
		Signature:          hex.EncodeToString(ed25519.Sign(priv, payload)),
	}
	data, err := json.MarshalIndent(baseline, "", "  ")
	if err != nil {
		return fmt.Errorf("hermes anchors seal: encode baseline: %w", err)
	}
	if err := writeFileAtomic(opts.Baseline, append(data, '\n')); err != nil {
		return fmt.Errorf("hermes anchors seal: %w", err)
	}
	out := cmd.OutOrStdout()
	_, _ = fmt.Fprintf(out, "pipelock: sealed and signed %d anchor(s) to %s\n", len(digests), opts.Baseline)
	for _, name := range sortedDigestNames(digests) {
		_, _ = fmt.Fprintf(out, "pipelock:   %s\n", name)
	}
	return nil
}

// anchorVerifyReport is the machine-readable result of `anchors verify`.
type anchorVerifyReport struct {
	OK       bool     `json:"ok"`
	Baseline string   `json:"baseline"`
	Checked  int      `json:"checked"`
	Drifted  []string `json:"drifted,omitempty"`
	Missing  []string `json:"missing,omitempty"`
	Errors   []string `json:"errors,omitempty"`
}

func runAnchorsVerify(cmd *cobra.Command, opts *anchorOptions, jsonOut bool) error {
	if opts.PublicKey == "" {
		return errors.New("hermes anchors verify: --public-key is required")
	}
	if err := opts.resolvePaths(); err != nil {
		return err
	}
	// When the public key is given as a file path, it must not be readable-and-
	// replaceable from the agent-writable workspace, or an attacker could swap
	// both the key and a baseline signed by their own key. An inline value
	// (from trusted args/env) has no such path.
	if info, statErr := os.Stat(opts.PublicKey); statErr == nil && !info.IsDir() {
		if err := rejectKeyInsideWorkspace(opts.Workspace, opts.PublicKey); err != nil {
			return err
		}
	}
	pub, err := signing.LoadPublicKey(opts.PublicKey)
	if err != nil {
		return fmt.Errorf("hermes anchors verify: public key: %w", err)
	}
	baseline, err := loadAnchorBaseline(opts.Baseline)
	if err != nil {
		return err
	}
	if err := verifyAnchorSignature(baseline, opts.Anchors, pub); err != nil {
		return err
	}

	report := anchorVerifyReport{Baseline: opts.Baseline}
	for _, name := range sortedDigestNames(baseline.Digests) {
		report.Checked++
		want := baseline.Digests[name]
		got, err := computeAnchorDigest(opts.Workspace, name)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				report.Missing = append(report.Missing, name)
			} else {
				report.Errors = append(report.Errors, fmt.Sprintf("%s: %v", name, err))
			}
			continue
		}
		if subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
			report.Drifted = append(report.Drifted, name)
		}
	}
	report.OK = len(report.Drifted) == 0 && len(report.Missing) == 0 && len(report.Errors) == 0

	if jsonOut {
		if err := emitAnchorJSON(cmd, report); err != nil {
			return err
		}
	} else {
		emitAnchorText(cmd, report)
	}
	if !report.OK {
		// Non-zero exit so an init container refuses to start the agent.
		return fmt.Errorf("hermes anchors verify: integrity check failed (%d drifted, %d missing, %d error)",
			len(report.Drifted), len(report.Missing), len(report.Errors))
	}
	return nil
}

func loadAnchorBaseline(path string) (*anchorBaseline, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("hermes anchors verify: baseline: %w", err)
	}
	var b anchorBaseline
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("hermes anchors verify: parse baseline %q: %w", path, err)
	}
	if b.Version != anchorBaselineVersion {
		return nil, fmt.Errorf("hermes anchors verify: baseline %q uses unsupported version %d", path, b.Version)
	}
	if b.DigestAlgorithm != anchorDigestAlgorithm {
		return nil, fmt.Errorf("hermes anchors verify: baseline %q uses unsupported digest algorithm %q", path, b.DigestAlgorithm)
	}
	if b.SignatureAlgorithm != anchorSignatureAlgorithm {
		return nil, fmt.Errorf("hermes anchors verify: baseline %q uses unsupported signature algorithm %q", path, b.SignatureAlgorithm)
	}
	if len(b.Digests) == 0 {
		return nil, fmt.Errorf("hermes anchors verify: baseline %q has no anchors", path)
	}
	if err := validateAnchorNames(sortedDigestNames(b.Digests)); err != nil {
		return nil, fmt.Errorf("hermes anchors verify: baseline %q: %w", path, err)
	}
	return &b, nil
}

// verifyAnchorSignature checks the manifest's Ed25519 signature against the
// public key and confirms the baseline covers exactly the requested anchor set.
// The signature already binds the digest set (an attacker without the private
// key cannot drop or alter an entry); the set check is defense-in-depth and
// also catches a baseline sealed with a different --anchor set than requested.
func verifyAnchorSignature(b *anchorBaseline, expectedAnchors []string, pub ed25519.PublicKey) error {
	if !sameAnchorSet(sortedDigestNames(b.Digests), expectedAnchors) {
		return errors.New("hermes anchors verify: baseline anchor set does not match requested anchors")
	}
	sig, err := hex.DecodeString(b.Signature)
	if err != nil {
		return fmt.Errorf("hermes anchors verify: baseline signature is invalid: %w", err)
	}
	payload, err := canonicalManifestBytes(b.Version, b.DigestAlgorithm, b.Digests)
	if err != nil {
		return fmt.Errorf("hermes anchors verify: %w", err)
	}
	if !ed25519.Verify(pub, payload, sig) {
		return errors.New("hermes anchors verify: baseline signature does not verify against the public key")
	}
	return nil
}

func sameAnchorSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	left := append([]string(nil), a...)
	right := append([]string(nil), b...)
	sort.Strings(left)
	sort.Strings(right)
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func emitAnchorJSON(cmd *cobra.Command, r anchorVerifyReport) error {
	enc := json.NewEncoder(cmd.OutOrStdout())
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

func emitAnchorText(cmd *cobra.Command, r anchorVerifyReport) {
	out := cmd.OutOrStdout()
	if r.OK {
		_, _ = fmt.Fprintf(out, "pipelock: anchor integrity OK (%d verified) against %s\n", r.Checked, r.Baseline)
		return
	}
	errOut := cmd.ErrOrStderr()
	_, _ = fmt.Fprintf(errOut, "pipelock: ANCHOR INTEGRITY VIOLATION against %s\n", r.Baseline)
	for _, name := range r.Drifted {
		_, _ = fmt.Fprintf(errOut, "pipelock:   altered: %s\n", name)
	}
	for _, name := range r.Missing {
		_, _ = fmt.Fprintf(errOut, "pipelock:   missing: %s\n", name)
	}
	for _, msg := range r.Errors {
		_, _ = fmt.Fprintf(errOut, "pipelock:   error:   %s\n", msg)
	}
}

func sortedDigestNames(digests map[string]string) []string {
	names := make([]string, 0, len(digests))
	for name := range digests {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
