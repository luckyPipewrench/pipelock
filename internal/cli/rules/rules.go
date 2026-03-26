// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	"github.com/luckyPipewrench/pipelock/internal/config"
	domrules "github.com/luckyPipewrench/pipelock/internal/rules"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

// Official bundle registry base URL. Bundles are served as static files
// from the pipelab.org Hugo site via Cloudflare Pages.
const officialRegistryURL = "https://pipelab.org/rules"

// loadRulesConfig loads the pipelock config for trusted key resolution.
// When configFile is explicitly set (--config flag), load failures are fatal
// (returned as error). Auto-discovery (PIPELOCK_CONFIG env, cwd pipelock.yaml)
// is best-effort: failures return nil config, not an error.
func loadRulesConfig(configFile string) (*config.Config, error) {
	// Explicit flag: hard error on failure.
	if configFile != "" {
		cfg, err := config.Load(configFile)
		if err != nil {
			return nil, fmt.Errorf("loading config %q: %w", configFile, err)
		}
		return cfg, nil
	}
	// Try PIPELOCK_CONFIG env var (best-effort).
	if envPath := os.Getenv("PIPELOCK_CONFIG"); envPath != "" {
		if cfg, err := config.Load(envPath); err == nil {
			return cfg, nil
		}
	}
	// Try pipelock.yaml in current directory (best-effort).
	if cfg, err := config.Load("pipelock.yaml"); err == nil {
		return cfg, nil
	}
	return nil, nil
}

// HTTP fetch timeout for remote bundle downloads.
const httpFetchTimeout = 30 * time.Second

// URL scheme constants.
const (
	schemeHTTP  = "http"
	schemeHTTPS = "https"
)

// Cmd returns the top-level "rules" command with all subcommands.
func Cmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rules",
		Short: "Manage community rule bundles",
		Long:  "Install, update, list, verify, diff, and remove signed rule bundles.",
	}
	cmd.AddCommand(
		rulesInstallCmd(),
		rulesUpdateCmd(),
		rulesListCmd(),
		rulesVerifyCmd(),
		rulesDiffCmd(),
		rulesRemoveCmd(),
	)
	return cmd
}

// acquireRulesLock is defined in rules_lock_unix.go and rules_lock_windows.go.
// It acquires an advisory file lock for mutating operations. Returns a release
// function and an error. The caller must call the release function when done.

// ensureDir creates a directory with 0o750 permissions if it does not exist.
func ensureDir(path string) error {
	return os.MkdirAll(path, 0o750)
}

// validateBundlePath sanitizes a bundle name and returns the resolved bundle
// directory. It rejects names that escape the rules directory via path traversal
// or symlinks. This MUST be called before any filesystem operation on user-
// supplied bundle names (update, diff, remove).
func validateBundlePath(rulesDir, name string) (string, error) {
	cleaned := filepath.Clean(name)
	if cleaned != name || strings.Contains(cleaned, string(filepath.Separator)) || cleaned == "." || cleaned == ".." {
		return "", fmt.Errorf("invalid bundle name %q: must be a plain directory name", name)
	}

	bundleDir := filepath.Join(rulesDir, cleaned)

	// Resolve symlinks for containment check.
	resolvedRules, err := filepath.EvalSymlinks(rulesDir)
	if err != nil {
		return "", fmt.Errorf("resolving rules directory: %w", err)
	}

	resolvedBundle, err := filepath.EvalSymlinks(bundleDir)
	if err != nil {
		// If the directory doesn't exist yet (install path), just verify the
		// cleaned name doesn't escape. EvalSymlinks fails for non-existent paths.
		if os.IsNotExist(err) {
			return bundleDir, nil
		}
		return "", fmt.Errorf("resolving bundle directory: %w", err)
	}

	rel, err := filepath.Rel(resolvedRules, resolvedBundle)
	if err != nil || strings.HasPrefix(rel, "..") {
		return "", fmt.Errorf("bundle name %q escapes rules directory", name)
	}

	return bundleDir, nil
}

// fetchRemoteBundle fetches bundle.yaml and bundle.yaml.sig from a remote URL.
// Requires HTTPS. Returns the bundle data and signature data.
func fetchRemoteBundle(ctx context.Context, bundleURL string) ([]byte, []byte, error) {
	if !strings.HasPrefix(bundleURL, "https://") {
		return nil, nil, fmt.Errorf("remote source must use HTTPS: %s", bundleURL)
	}

	bundleData, err := httpGet(ctx, bundleURL)
	if err != nil {
		return nil, nil, fmt.Errorf("fetching bundle: %w", err)
	}

	sigURL := bundleURL + signing.SigExtension
	sigData, err := httpGet(ctx, sigURL)
	if err != nil {
		return nil, nil, fmt.Errorf("fetching signature: %w", err)
	}

	return bundleData, sigData, nil
}

// httpsOnlyClient is a shared HTTP client that rejects HTTPS-to-HTTP
// redirect downgrades. Bundle fetches must stay on HTTPS.
var httpsOnlyClient = &http.Client{
	CheckRedirect: func(req *http.Request, _ []*http.Request) error {
		if req.URL.Scheme != schemeHTTPS {
			return fmt.Errorf("refusing redirect to non-HTTPS URL: %s", req.URL)
		}
		return nil
	},
}

// httpGet performs an HTTP GET with context and timeout.
func httpGet(ctx context.Context, url string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, httpFetchTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	resp, err := httpsOnlyClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP GET %s: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP GET %s: status %d", url, resp.StatusCode)
	}

	// Enforce size limit.
	limited := io.LimitReader(resp.Body, int64(domrules.MaxBundleFileSize)+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}

	if len(data) > domrules.MaxBundleFileSize {
		return nil, fmt.Errorf("response exceeds maximum bundle size (%d bytes)", domrules.MaxBundleFileSize)
	}

	return data, nil
}

// decodeSignatureBytes decodes a base64-encoded signature from raw bytes.
// This mirrors signing.LoadSignature but works on in-memory data instead
// of a file path (for HTTP-fetched signatures).
func decodeSignatureBytes(data []byte) ([]byte, error) {
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
	if err != nil {
		return nil, fmt.Errorf("decoding signature: %w", err)
	}
	if len(sig) != ed25519.SignatureSize {
		return nil, fmt.Errorf("invalid signature length: got %d, want %d", len(sig), ed25519.SignatureSize)
	}
	return sig, nil
}

// verifyRemoteSignature verifies bundleData against sigData using the embedded
// keyring and trusted keys. Returns the verification result.
func verifyRemoteSignature(bundleData, sigData []byte, trustedKeys []config.TrustedKey) (*domrules.VerifyResult, error) {
	sig, err := decodeSignatureBytes(sigData)
	if err != nil {
		return nil, fmt.Errorf("decoding signature: %w", err)
	}

	// Try embedded keyring first (official tier).
	for _, key := range domrules.EmbeddedKeyring() {
		if ed25519.Verify(key, bundleData, sig) {
			return &domrules.VerifyResult{
				Tier:              domrules.TrustTierOfficial,
				SignerFingerprint: domrules.KeyFingerprint(key),
			}, nil
		}
	}

	// Try trusted keys (third-party tier).
	for _, tk := range trustedKeys {
		raw, err := hex.DecodeString(tk.PublicKey)
		if err != nil {
			continue
		}
		if len(raw) != ed25519.PublicKeySize {
			continue
		}
		key := ed25519.PublicKey(raw)
		if ed25519.Verify(key, bundleData, sig) {
			return &domrules.VerifyResult{
				Tier:              domrules.TrustTierThirdParty,
				SignerFingerprint: domrules.KeyFingerprint(key),
			}, nil
		}
	}

	return nil, fmt.Errorf("no matching signer found for bundle")
}

// sha256Hex returns the lowercase hex SHA-256 digest of data.
func sha256Hex(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// timeNowUTC returns the current time in RFC3339 UTC format.
func timeNowUTC() string {
	return time.Now().UTC().Format(time.RFC3339)
}

// ---------- rules list ----------

// bundleListEntry is the JSON representation for "rules list --json".
type bundleListEntry struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Source  string `json:"source"`
	Signed  bool   `json:"signed"`
	LastChk string `json:"last_check,omitempty"`
}

func rulesListCmd() *cobra.Command {
	var rulesDir string
	var jsonOut bool

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List installed rule bundles",
		RunE: func(cmd *cobra.Command, _ []string) error {
			dir := domrules.ResolveRulesDir(rulesDir)
			out := cmd.OutOrStdout()

			entries, err := os.ReadDir(dir)
			if err != nil {
				if os.IsNotExist(err) {
					_, _ = fmt.Fprintln(out, "No bundles installed.")
					return nil
				}
				return fmt.Errorf("reading rules directory: %w", err)
			}

			var bundles []bundleListEntry
			for _, e := range entries {
				if !e.IsDir() || strings.HasPrefix(e.Name(), ".") || strings.HasSuffix(e.Name(), ".bak") {
					continue
				}
				lockPath := filepath.Join(dir, e.Name(), "bundle.lock")
				lf, err := domrules.ReadLockFile(lockPath)
				if err != nil {
					continue // skip directories without lock files
				}
				bundles = append(bundles, bundleListEntry{
					Name:    e.Name(),
					Version: lf.InstalledVersion,
					Source:  lf.Source,
					Signed:  !lf.Unsigned,
					LastChk: lf.LastCheck,
				})
			}

			if len(bundles) == 0 {
				_, _ = fmt.Fprintln(out, "No bundles installed.")
				return nil
			}

			if jsonOut {
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				return enc.Encode(bundles)
			}

			for _, b := range bundles {
				signedLabel := "signed"
				if !b.Signed {
					signedLabel = "unsigned"
				}
				_, _ = fmt.Fprintf(out, "%-30s v%-14s %s  (%s)\n", b.Name, b.Version, signedLabel, b.Source)
				if b.LastChk != "" {
					_, _ = fmt.Fprintf(out, "  last checked: %s\n", b.LastChk)
				}
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&rulesDir, "rules-dir", "", "override rules directory")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "output as JSON")
	return cmd
}

// ---------- rules install ----------

func rulesInstallCmd() *cobra.Command {
	var (
		sourceURL   string
		localPath   string
		allowUnsign bool
		rulesDir    string
		configFile  string
	)

	cmd := &cobra.Command{
		Use:   "install [name]",
		Short: "Install a rule bundle",
		Long: `Install a rule bundle from the official registry, a third-party URL, or a local directory.

Examples:
  pipelock rules install pipelock-community
  pipelock rules install --source https://example.com/bundle.yaml
  pipelock rules install --path ./my-rules/ --allow-unsigned`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			dir := domrules.ResolveRulesDir(rulesDir)

			if err := ensureDir(dir); err != nil {
				return fmt.Errorf("creating rules directory: %w", err)
			}

			unlock, err := acquireRulesLock(dir)
			if err != nil {
				return err
			}
			defer unlock()

			// Determine install mode.
			switch {
			case localPath != "":
				return installLocal(out, dir, localPath, allowUnsign)
			case sourceURL != "":
				return installRemote(out, dir, sourceURL, configFile, "")
			case len(args) == 1:
				name := args[0]
				url := officialRegistryURL + "/" + name + "/bundle.yaml"
				return installRemote(out, dir, url, configFile, name)
			default:
				return fmt.Errorf("specify a bundle name, --source URL, or --path DIR")
			}
		},
	}

	cmd.Flags().StringVar(&sourceURL, "source", "", "third-party bundle URL")
	cmd.Flags().StringVar(&localPath, "path", "", "local bundle directory")
	cmd.Flags().BoolVar(&allowUnsign, "allow-unsigned", false, "allow unsigned local bundles")
	cmd.Flags().StringVar(&rulesDir, "rules-dir", "", "override rules directory")
	cmd.Flags().StringVar(&configFile, "config", "", "config file for trusted keys")
	return cmd
}

// installLocal installs a bundle from a local directory.
func installLocal(out io.Writer, rulesDir, localPath string, allowUnsigned bool) error {
	if !allowUnsigned {
		return fmt.Errorf("local installs require --allow-unsigned (local bundles cannot be signature-verified)")
	}

	bundlePath := filepath.Join(filepath.Clean(localPath), "bundle.yaml")
	data, err := os.ReadFile(filepath.Clean(bundlePath))
	if err != nil {
		return fmt.Errorf("reading local bundle: %w", err)
	}

	if len(data) > domrules.MaxBundleFileSize {
		return fmt.Errorf("bundle file exceeds maximum size (%d bytes)", domrules.MaxBundleFileSize)
	}

	bundle, err := domrules.ParseBundle(data)
	if err != nil {
		return fmt.Errorf("parsing bundle: %w", err)
	}

	if err := domrules.CheckMinPipelock(bundle.MinPipelock, cliutil.Version); err != nil {
		return err
	}

	// Check pipelock-* prefix reservation: local unsigned bundles cannot use it.
	if strings.HasPrefix(bundle.Name, "pipelock-") {
		return fmt.Errorf("bundle name %q uses reserved prefix %q: only officially signed bundles may use this prefix", bundle.Name, "pipelock-")
	}

	digest := sha256Hex(data)
	destDir := filepath.Join(rulesDir, bundle.Name)

	// Check if already installed with same version+digest.
	if err := checkExistingInstall(destDir, bundle.Version, digest); err != nil {
		return err
	}

	// Build lock file and stage everything atomically.
	now := timeNowUTC()
	lf := &domrules.LockFile{
		InstalledVersion: bundle.Version,
		InstalledAt:      now,
		Source:           "local:" + filepath.Clean(localPath),
		LastCheck:        now,
		BundleSHA256:     digest,
		Unsigned:         true,
	}
	if err := stageBundle(rulesDir, bundle.Name, data, nil, lf); err != nil {
		return err
	}

	_, _ = fmt.Fprintf(out, "Installed %s v%s (unsigned, local)\n", bundle.Name, bundle.Version)
	_, _ = fmt.Fprintf(out, "  %d rules\n", len(bundle.Rules))
	return nil
}

// installRemote installs a bundle from a remote URL.
func installRemote(out io.Writer, rulesDir, bundleURL, configFile, expectedName string) error {
	ctx := context.Background()

	bundleData, sigData, err := fetchRemoteBundle(ctx, bundleURL)
	if err != nil {
		return err
	}

	// Load trusted keys from config (explicit flag, env, or cwd).
	var trustedKeys []config.TrustedKey
	if cfg, cfgErr := loadRulesConfig(configFile); cfgErr != nil {
		return cfgErr
	} else if cfg != nil {
		trustedKeys = cfg.Rules.TrustedKeys
	}

	result, err := verifyRemoteSignature(bundleData, sigData, trustedKeys)
	if err != nil {
		return fmt.Errorf("signature verification: %w", err)
	}

	bundle, err := domrules.ParseBundle(bundleData)
	if err != nil {
		return fmt.Errorf("parsing bundle: %w", err)
	}

	// If an expected name was given (official install), verify it matches.
	if expectedName != "" && bundle.Name != expectedName {
		return fmt.Errorf("bundle name %q does not match expected %q", bundle.Name, expectedName)
	}

	// Enforce pipelock-* prefix reservation: only official keys allowed.
	if strings.HasPrefix(bundle.Name, "pipelock-") && result.Tier != domrules.TrustTierOfficial {
		return fmt.Errorf("bundle name %q uses reserved prefix %q but signer is not official", bundle.Name, "pipelock-")
	}

	if err := domrules.CheckMinPipelock(bundle.MinPipelock, cliutil.Version); err != nil {
		return err
	}

	digest := sha256Hex(bundleData)
	destDir := filepath.Join(rulesDir, bundle.Name)

	if err := checkExistingInstall(destDir, bundle.Version, digest); err != nil {
		return err
	}

	// Build lock file and stage everything atomically.
	now := timeNowUTC()
	lf := &domrules.LockFile{
		InstalledVersion:  bundle.Version,
		InstalledAt:       now,
		Source:            bundleURL,
		LastCheck:         now,
		BundleSHA256:      digest,
		SignerFingerprint: result.SignerFingerprint,
	}
	if err := stageBundle(rulesDir, bundle.Name, bundleData, sigData, lf); err != nil {
		return err
	}

	_, _ = fmt.Fprintf(out, "Installed %s v%s (%s)\n", bundle.Name, bundle.Version, result.Tier)
	_, _ = fmt.Fprintf(out, "  %d rules, signer: %s\n", len(bundle.Rules), result.SignerFingerprint[:16]+"...")
	return nil
}

// checkExistingInstall checks if a bundle is already installed.
// Same version + same digest = skip (returns error to short-circuit).
// Same version + different digest = error (republished).
func checkExistingInstall(destDir, version, digest string) error {
	lockPath := filepath.Join(destDir, "bundle.lock")
	lf, err := domrules.ReadLockFile(lockPath)
	if err != nil {
		return nil // not installed
	}

	if lf.InstalledVersion == version {
		if lf.BundleSHA256 == digest {
			return fmt.Errorf("bundle already installed at v%s with same digest (skipping)", version)
		}
		return fmt.Errorf("bundle v%s already installed with different digest (possible republish attack)", version)
	}

	return nil
}

// stageBundle writes bundle files and lock into a temp directory under rulesDir,
// then atomically swaps to the final location. The lock file is included in the
// staged directory so that no observer (startup, verify, concurrent CLI) can see
// a bundle without matching provenance. If an existing bundle is present, it is
// moved to a backup before the swap and removed only after success.
func stageBundle(rulesDir, bundleName string, bundleData, sigData []byte, lf *domrules.LockFile) error {
	destDir := filepath.Join(rulesDir, bundleName)

	// Create temp staging directory (MkdirTemp creates 0o700, tighten to 0o750).
	tmpDir, err := os.MkdirTemp(rulesDir, ".stage-"+bundleName+"-*")
	if err != nil {
		return fmt.Errorf("creating staging directory: %w", err)
	}
	if err := os.Chmod(tmpDir, 0o750); err != nil { //nolint:gosec // G302: 0o750 is correct for directories per project policy
		return fmt.Errorf("setting staging directory permissions: %w", err)
	}

	// Clean up staging dir on failure.
	success := false
	defer func() {
		if !success {
			_ = os.RemoveAll(tmpDir)
		}
	}()

	// Write bundle.yaml.
	bundlePath := filepath.Join(tmpDir, "bundle.yaml")
	if err := os.WriteFile(bundlePath, bundleData, 0o600); err != nil {
		return fmt.Errorf("writing staged bundle: %w", err)
	}

	// Write signature if present.
	if sigData != nil {
		sigPath := filepath.Join(tmpDir, "bundle.yaml.sig")
		if err := os.WriteFile(sigPath, sigData, 0o600); err != nil {
			return fmt.Errorf("writing staged signature: %w", err)
		}
	}

	// Write lock file inside the staged directory so the rename is fully atomic:
	// no window where bundle exists without matching provenance.
	lockPath := filepath.Join(tmpDir, "bundle.lock")
	if err := domrules.WriteLockFile(lockPath, lf); err != nil {
		return fmt.Errorf("writing staged lock file: %w", err)
	}

	// If the destination already exists, move it to a backup instead of deleting.
	// This preserves the last known-good bundle if the rename fails.
	backupDir := ""
	if _, statErr := os.Stat(destDir); statErr == nil {
		backupDir = destDir + ".bak"
		_ = os.RemoveAll(backupDir) // remove stale backup from prior failed attempt
		if err := os.Rename(destDir, backupDir); err != nil {
			return fmt.Errorf("backing up existing bundle: %w", err)
		}
	}

	// Atomic rename into final location.
	if err := os.Rename(tmpDir, destDir); err != nil {
		// Restore backup if rename failed.
		if backupDir != "" {
			_ = os.Rename(backupDir, destDir)
		}
		return fmt.Errorf("installing bundle (rename): %w", err)
	}

	// Remove backup after successful swap.
	if backupDir != "" {
		_ = os.RemoveAll(backupDir)
	}

	success = true
	return nil
}

// ---------- rules update ----------

func rulesUpdateCmd() *cobra.Command {
	var (
		force          bool
		allowKeyRotate bool
		rulesDir       string
		configFile     string
	)

	cmd := &cobra.Command{
		Use:   "update [name]",
		Short: "Update installed rule bundles",
		Long: `Update all installed bundles or a specific named bundle.
Local (unsigned) bundles are skipped during update.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			dir := domrules.ResolveRulesDir(rulesDir)

			if err := ensureDir(dir); err != nil {
				return fmt.Errorf("creating rules directory: %w", err)
			}

			unlock, err := acquireRulesLock(dir)
			if err != nil {
				return err
			}
			defer unlock()

			var trustedKeys []config.TrustedKey
			if cfg, cfgErr := loadRulesConfig(configFile); cfgErr != nil {
				return cfgErr
			} else if cfg != nil {
				trustedKeys = cfg.Rules.TrustedKeys
			}

			if len(args) == 1 {
				return updateBundle(out, dir, args[0], trustedKeys, force, allowKeyRotate)
			}

			// Update all.
			entries, err := os.ReadDir(dir)
			if err != nil {
				if os.IsNotExist(err) {
					_, _ = fmt.Fprintln(out, "No bundles installed.")
					return nil
				}
				return fmt.Errorf("reading rules directory: %w", err)
			}

			var updated, failures int
			for _, e := range entries {
				if !e.IsDir() || strings.HasPrefix(e.Name(), ".") || strings.HasSuffix(e.Name(), ".bak") {
					continue
				}
				err := updateBundle(out, dir, e.Name(), trustedKeys, force, allowKeyRotate)
				if err != nil {
					_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "error updating %s: %v\n", e.Name(), err)
					failures++
				} else {
					updated++
				}
			}

			if updated == 0 && failures == 0 {
				_, _ = fmt.Fprintln(out, "No bundles updated.")
			}
			if failures > 0 {
				return fmt.Errorf("%d bundle(s) failed to update", failures)
			}
			return nil
		},
	}

	cmd.Flags().BoolVar(&force, "force", false, "force update (allow downgrades and republish)")
	cmd.Flags().BoolVar(&allowKeyRotate, "allow-key-rotation", false, "allow signer key changes")
	cmd.Flags().StringVar(&rulesDir, "rules-dir", "", "override rules directory")
	cmd.Flags().StringVar(&configFile, "config", "", "config file for trusted keys")
	return cmd
}

// updateBundle updates a single installed bundle.
func updateBundle(out io.Writer, rulesDir, name string, trustedKeys []config.TrustedKey, force, allowKeyRotation bool) error {
	bundleDir, err := validateBundlePath(rulesDir, name)
	if err != nil {
		return err
	}
	lockPath := filepath.Join(bundleDir, "bundle.lock")

	lf, err := domrules.ReadLockFile(lockPath)
	if err != nil {
		return fmt.Errorf("bundle %q not installed", name)
	}

	// Skip local/unsigned bundles.
	if lf.Unsigned || !strings.HasPrefix(lf.Source, "https://") {
		_, _ = fmt.Fprintf(out, "skipping %s: installed from local path\n", name)
		return nil
	}

	// Fetch latest from source.
	ctx := context.Background()
	bundleData, sigData, err := fetchRemoteBundle(ctx, lf.Source)
	if err != nil {
		return fmt.Errorf("fetching update for %s: %w", name, err)
	}

	result, err := verifyRemoteSignature(bundleData, sigData, trustedKeys)
	if err != nil {
		return fmt.Errorf("signature verification for %s: %w", name, err)
	}

	// Check signer pinning.
	if lf.SignerFingerprint != "" {
		if err := domrules.CheckSignerPinning(lf.SignerFingerprint, result.SignerFingerprint, allowKeyRotation); err != nil {
			return fmt.Errorf("update %s: %w", name, err)
		}
	}

	bundle, err := domrules.ParseBundle(bundleData)
	if err != nil {
		return fmt.Errorf("parsing updated bundle %s: %w", name, err)
	}

	// Reject name changes: a source cannot silently rename a bundle on update.
	if bundle.Name != name {
		return fmt.Errorf("update %s: bundle manifest name changed from %q to %q (rejected)", name, name, bundle.Name)
	}

	// Re-run reserved prefix check: updates must also enforce pipelock-* reservation.
	if strings.HasPrefix(bundle.Name, "pipelock-") && result.Tier != domrules.TrustTierOfficial {
		return fmt.Errorf("update %s: bundle name %q uses reserved prefix %q but signer is not official", name, bundle.Name, "pipelock-")
	}

	if err := domrules.CheckMinPipelock(bundle.MinPipelock, cliutil.Version); err != nil {
		return err
	}

	// Compare versions.
	newVer, err := domrules.ParseCalVer(bundle.Version)
	if err != nil {
		return fmt.Errorf("parsing new version: %w", err)
	}
	oldVer, err := domrules.ParseCalVer(lf.InstalledVersion)
	if err != nil {
		return fmt.Errorf("parsing installed version: %w", err)
	}

	newDigest := sha256Hex(bundleData)
	now := timeNowUTC()

	cmp := newVer.Compare(oldVer)
	switch {
	case cmp < 0 && !force:
		return fmt.Errorf("update %s: new version %s is older than installed %s (use --force to downgrade)", name, bundle.Version, lf.InstalledVersion)

	case cmp == 0 && newDigest == lf.BundleSHA256:
		// Same version, same digest: just update last_check.
		lf.LastCheck = now
		if err := domrules.WriteLockFile(lockPath, lf); err != nil {
			return fmt.Errorf("updating last_check for %s: %w", name, err)
		}
		_, _ = fmt.Fprintf(out, "%s v%s: already up to date\n", name, bundle.Version)
		return nil

	case cmp == 0 && newDigest != lf.BundleSHA256 && !force:
		return fmt.Errorf("update %s: same version %s but different digest (possible republish attack, use --force to override)", name, bundle.Version)
	}

	// Build lock file and stage everything atomically.
	newLF := &domrules.LockFile{
		InstalledVersion:  bundle.Version,
		InstalledAt:       now,
		Source:            lf.Source,
		LastCheck:         now,
		BundleSHA256:      newDigest,
		SignerFingerprint: result.SignerFingerprint,
	}
	if err := stageBundle(rulesDir, name, bundleData, sigData, newLF); err != nil {
		return err
	}

	_, _ = fmt.Fprintf(out, "Updated %s: v%s -> v%s\n", name, lf.InstalledVersion, bundle.Version)
	return nil
}

// ---------- rules verify ----------

func rulesVerifyCmd() *cobra.Command {
	var rulesDir string
	var configFile string

	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Re-verify integrity of all installed bundles",
		RunE: func(cmd *cobra.Command, _ []string) error {
			out := cmd.OutOrStdout()
			dir := domrules.ResolveRulesDir(rulesDir)

			var trustedKeys []config.TrustedKey
			if cfg, cfgErr := loadRulesConfig(configFile); cfgErr != nil {
				return cfgErr
			} else if cfg != nil {
				trustedKeys = cfg.Rules.TrustedKeys
			}

			entries, err := os.ReadDir(dir)
			if err != nil {
				if os.IsNotExist(err) {
					_, _ = fmt.Fprintln(out, "No bundles installed.")
					return nil
				}
				return fmt.Errorf("reading rules directory: %w", err)
			}

			var failures int
			var checked int
			for _, e := range entries {
				if !e.IsDir() || strings.HasPrefix(e.Name(), ".") || strings.HasSuffix(e.Name(), ".bak") {
					continue
				}
				checked++
				bundleDir := filepath.Join(dir, e.Name())
				lockPath := filepath.Join(bundleDir, "bundle.lock")

				lf, err := domrules.ReadLockFile(lockPath)
				if err != nil {
					_, _ = fmt.Fprintf(out, "FAIL  %s: missing lock file\n", e.Name())
					failures++
					continue
				}

				err = domrules.VerifyIntegrity(bundleDir, lf.Unsigned, lf.SignerFingerprint, lf.BundleSHA256, trustedKeys)
				if err != nil {
					_, _ = fmt.Fprintf(out, "FAIL  %s: %v\n", e.Name(), err)
					failures++
				} else {
					label := "signature OK"
					if lf.Unsigned {
						label = "SHA-256 OK"
					}
					_, _ = fmt.Fprintf(out, "OK    %s (%s)\n", e.Name(), label)
				}
			}

			if checked == 0 {
				_, _ = fmt.Fprintln(out, "No bundles installed.")
				return nil
			}

			if failures > 0 {
				return fmt.Errorf("%d bundle(s) failed verification", failures)
			}

			_, _ = fmt.Fprintf(out, "\nAll %d bundle(s) verified.\n", checked)
			return nil
		},
	}

	cmd.Flags().StringVar(&rulesDir, "rules-dir", "", "override rules directory")
	cmd.Flags().StringVar(&configFile, "config", "", "config file for trusted keys")
	return cmd
}

// ---------- rules diff ----------

func rulesDiffCmd() *cobra.Command {
	var rulesDir string
	var sourceURL string

	cmd := &cobra.Command{
		Use:   "diff <name>",
		Short: "Show differences between installed and remote bundle",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			dir := domrules.ResolveRulesDir(rulesDir)
			name := args[0]

			bundleDir, pathErr := validateBundlePath(dir, name)
			if pathErr != nil {
				return pathErr
			}
			lockPath := filepath.Join(bundleDir, "bundle.lock")

			lf, err := domrules.ReadLockFile(lockPath)
			if err != nil {
				return fmt.Errorf("bundle %q not installed", name)
			}

			// Determine source URL.
			fetchURL := sourceURL
			if fetchURL == "" {
				fetchURL = lf.Source
			}

			if !strings.HasPrefix(fetchURL, "https://") {
				return fmt.Errorf("cannot diff local bundles (source: %s); use --source to specify a remote URL", fetchURL)
			}

			// Read installed bundle.
			installedPath := filepath.Join(bundleDir, "bundle.yaml")
			installedData, err := os.ReadFile(filepath.Clean(installedPath))
			if err != nil {
				return fmt.Errorf("reading installed bundle: %w", err)
			}

			installedBundle, err := domrules.ParseBundle(installedData)
			if err != nil {
				return fmt.Errorf("parsing installed bundle: %w", err)
			}

			// Fetch remote bundle.
			ctx := context.Background()
			remoteData, _, err := fetchRemoteBundle(ctx, fetchURL)
			if err != nil {
				return fmt.Errorf("fetching remote bundle: %w", err)
			}

			remoteBundle, err := domrules.ParseBundle(remoteData)
			if err != nil {
				return fmt.Errorf("parsing remote bundle: %w", err)
			}

			// Build rule maps.
			installedRules := make(map[string]*domrules.Rule, len(installedBundle.Rules))
			for i := range installedBundle.Rules {
				r := &installedBundle.Rules[i]
				installedRules[r.ID] = r
			}

			remoteRules := make(map[string]*domrules.Rule, len(remoteBundle.Rules))
			for i := range remoteBundle.Rules {
				r := &remoteBundle.Rules[i]
				remoteRules[r.ID] = r
			}

			// Calculate diffs.
			var added, removed, changed []string

			for id := range remoteRules {
				nsID := domrules.NamespacedID(name, id)
				if _, ok := installedRules[id]; !ok {
					added = append(added, nsID)
				}
			}

			for id := range installedRules {
				nsID := domrules.NamespacedID(name, id)
				if _, ok := remoteRules[id]; !ok {
					removed = append(removed, nsID)
				}
			}

			for id, installedRule := range installedRules {
				remoteRule, ok := remoteRules[id]
				if !ok {
					continue
				}
				if ruleChanged(installedRule, remoteRule) {
					changed = append(changed, domrules.NamespacedID(name, id))
				}
			}

			// Print diff.
			_, _ = fmt.Fprintf(out, "Diff: %s (installed v%s vs remote v%s)\n\n", name, installedBundle.Version, remoteBundle.Version)

			if len(added) == 0 && len(removed) == 0 && len(changed) == 0 {
				_, _ = fmt.Fprintln(out, "No differences found.")
				return nil
			}

			for _, id := range added {
				_, _ = fmt.Fprintf(out, "+ %s\n", id)
			}
			for _, id := range removed {
				_, _ = fmt.Fprintf(out, "- %s\n", id)
			}
			for _, id := range changed {
				_, _ = fmt.Fprintf(out, "~ %s\n", id)
			}

			_, _ = fmt.Fprintf(out, "\nSummary: %d added, %d removed, %d changed\n", len(added), len(removed), len(changed))
			return nil
		},
	}

	cmd.Flags().StringVar(&rulesDir, "rules-dir", "", "override rules directory")
	cmd.Flags().StringVar(&sourceURL, "source", "", "override source URL for comparison")
	return cmd
}

// ruleChanged returns true if two rules differ in any meaningful field.
func ruleChanged(a, b *domrules.Rule) bool {
	if a.Type != b.Type {
		return true
	}
	if a.Status != b.Status {
		return true
	}
	if a.Severity != b.Severity {
		return true
	}
	if a.Pattern.Regex != b.Pattern.Regex {
		return true
	}
	if a.Description != b.Description {
		return true
	}
	return false
}

// ---------- rules remove ----------

func rulesRemoveCmd() *cobra.Command {
	var rulesDir string

	cmd := &cobra.Command{
		Use:   "remove <name>",
		Short: "Remove an installed rule bundle",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			dir := domrules.ResolveRulesDir(rulesDir)
			name := args[0]

			if err := ensureDir(dir); err != nil {
				return fmt.Errorf("creating rules directory: %w", err)
			}

			unlock, err := acquireRulesLock(dir)
			if err != nil {
				return err
			}
			defer unlock()

			bundleDir, pathErr := validateBundlePath(dir, name)
			if pathErr != nil {
				return pathErr
			}
			info, err := os.Stat(bundleDir)
			if err != nil || !info.IsDir() {
				return fmt.Errorf("bundle %q is not installed", name)
			}

			if err := os.RemoveAll(bundleDir); err != nil {
				return fmt.Errorf("removing bundle %q: %w", name, err)
			}

			_, _ = fmt.Fprintf(out, "Removed %s\n", name)
			return nil
		},
	}

	cmd.Flags().StringVar(&rulesDir, "rules-dir", "", "override rules directory")
	return cmd
}
