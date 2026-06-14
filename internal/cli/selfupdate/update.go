// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package selfupdate implements the "pipelock update" command: a fail-closed
// self-updater that fetches a release archive from GitHub, verifies it against
// the published checksums (and, when a cosign binary is available, against the
// keyless publisher signature), then atomically replaces the running binary.
//
// Every failure in the verification chain aborts and leaves the installed
// binary untouched. The temp download/extract happens in the SAME directory as
// the target binary so the final os.Rename is atomic on one filesystem.
package selfupdate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	neturl "net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// GitHub repository coordinates. The host is ours, so naming it is fine.
const (
	repoOwner = "luckyPipewrench"
	repoName  = "pipelock"

	// defaultAPIBase is the GitHub REST API base for release lookups. Tests
	// override this with an httptest server.
	defaultAPIBase = "https://api.github.com"

	// binaryName is the executable extracted from the release archive.
	binaryName = "pipelock"

	// checksumsFile and its signature/certificate companions, published by
	// GoReleaser alongside every release.
	checksumsFile = "checksums.txt"
	checksumsSig  = "checksums.txt.sig"
	checksumsPEM  = "checksums.txt.pem"

	// backupSuffix names the saved previous binary used by --rollback.
	backupSuffix = ".bak"

	// cosignBinary is the publisher-signature verifier we shell out to when present.
	cosignBinary = "cosign"

	// oidcIssuer is the keyless OIDC issuer GoReleaser signs under (GitHub Actions).
	oidcIssuer = "https://token.actions.githubusercontent.com"

	// releaseWorkflowIdentity is the exact GitHub Actions OIDC identity that
	// signs release checksums for a tag.
	releaseWorkflowIdentity = "https://github.com/luckyPipewrench/pipelock/.github/workflows/release.yaml@refs/tags/%s"

	// httpTimeout bounds every network operation.
	httpTimeout = 60 * time.Second

	// maxDownloadBytes caps archive/checksum downloads to defend against a
	// hostile or compromised release server streaming an unbounded body.
	maxDownloadBytes = 256 << 20 // 256 MiB

	// extractedBinaryPerm is intentionally 0o755: a binary MUST be executable.
	// This is the deliberate exception to the project-wide 0o600 file rule.
	extractedBinaryPerm = 0o755
)

// errors returned by the updater. errors.Is-comparable for tests and callers.
var (
	// ErrUpToDate is returned when the installed version is already current.
	ErrUpToDate = errors.New("already up to date")
	// ErrChecksumMismatch is returned when a downloaded archive's SHA256 does
	// not match the published checksum. Fail-closed: no changes applied.
	ErrChecksumMismatch = errors.New("archive checksum does not match published checksums.txt")
	// ErrVersionMismatch is returned when the freshly extracted binary does not
	// report the expected target version. Fail-closed: temp deleted, no changes.
	ErrVersionMismatch = errors.New("downloaded binary reports an unexpected version")
	// ErrSignatureVerify is returned when cosign is present and rejects the
	// publisher signature on checksums.txt. Fail-closed: no changes applied.
	ErrSignatureVerify = errors.New("publisher signature verification failed")
	// ErrSignatureUnavailable is returned when cosign is unavailable and the
	// caller did not explicitly opt into checksum-only update mode.
	ErrSignatureUnavailable = errors.New("publisher signature verification unavailable")
	// ErrUnsupportedPlatform is returned for an OS/arch with no published asset.
	ErrUnsupportedPlatform = errors.New("no release asset for this OS/architecture")
	// ErrAssetNotFound is returned when the release has no matching archive asset.
	ErrAssetNotFound = errors.New("release asset not found")
	// ErrNotWritable is returned when the target binary or its directory is not
	// writable by the current user. Aborts before any destructive action.
	ErrNotWritable = errors.New("target binary path is not writable by the current user")
	// ErrUnsafeArchive is returned when an archive entry attempts path traversal
	// (zip-slip / tar "..") or carries an absolute path.
	ErrUnsafeArchive = errors.New("refusing unsafe archive entry")
	// ErrBinaryTooLarge is returned when an extracted/staged binary exceeds the
	// updater's bounded-copy limit. Fail-closed: no replacement is applied.
	ErrBinaryTooLarge = errors.New("binary exceeds updater size limit")
	// ErrNoBackup is returned by --rollback when no .bak backup exists.
	ErrNoBackup = errors.New("no previous binary backup found to roll back to")
)

// CommandRunner runs an external command and returns combined output. Injected
// so tests can stub cosign without a real binary.
type CommandRunner func(ctx context.Context, name string, args ...string) ([]byte, error)

// defaultCommandRunner shells out for real.
func defaultCommandRunner(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).CombinedOutput() // #nosec G204 -- name is a fixed const (cosign); args are internally constructed
}

// Options configures an update operation. The cobra command fills defaults;
// tests drive these fields directly. Every external seam (release API, target
// path, OS/arch, cosign availability, command runner, output writers) is
// injectable.
type Options struct {
	// APIBase is the GitHub API base URL (no trailing slash). Default: GitHub.
	APIBase string
	// HTTPClient performs all downloads. Default: proxy-honoring client.
	HTTPClient *http.Client
	// TargetPath is the binary to replace. Default: resolved os.Executable().
	TargetPath string
	// CurrentVersion is the running version (cliutil.Version).
	CurrentVersion string
	// TargetVersion pins a specific tag (e.g. "v2.7.0"). Empty = latest.
	TargetVersion string
	// GOOS / GOARCH select the asset. Default: runtime values.
	GOOS, GOARCH string

	// CheckOnly reports status and makes no changes.
	CheckOnly bool
	// AssumeYes skips the interactive confirm (the cobra layer handles the prompt).
	AssumeYes bool
	// JSON requests machine-readable output (handled by the cobra layer).
	JSON bool
	// AllowUnsignedChecksums permits checksum-only updates when cosign is absent.
	// This is intentionally opt-in because checksums downloaded from the same
	// release page prove integrity, not publisher authenticity.
	AllowUnsignedChecksums bool

	// CosignAvailable reports whether a cosign binary is usable. Default: PATH lookup.
	CosignAvailable func() bool
	// RunCommand executes cosign. Default: defaultCommandRunner.
	RunCommand CommandRunner

	// Stdout / Stderr for human messaging. Default: os.Stdout / os.Stderr.
	Stdout, Stderr io.Writer
}

// fillDefaults populates unset fields with real-world defaults. Returns an
// error if the target binary cannot be resolved.
func (o *Options) fillDefaults() error {
	if o.APIBase == "" {
		o.APIBase = defaultAPIBase
	}
	o.APIBase = strings.TrimRight(o.APIBase, "/")
	if o.HTTPClient == nil {
		o.HTTPClient = defaultHTTPClient()
	}
	if o.GOOS == "" {
		o.GOOS = runtime.GOOS
	}
	if o.GOARCH == "" {
		o.GOARCH = runtime.GOARCH
	}
	if o.CosignAvailable == nil {
		o.CosignAvailable = func() bool {
			_, err := exec.LookPath(cosignBinary)
			return err == nil
		}
	}
	if o.RunCommand == nil {
		o.RunCommand = defaultCommandRunner
	}
	if o.Stdout == nil {
		o.Stdout = os.Stdout
	}
	if o.Stderr == nil {
		o.Stderr = os.Stderr
	}
	if o.TargetPath == "" {
		exe, err := os.Executable()
		if err != nil {
			return fmt.Errorf("resolving running binary: %w", err)
		}
		resolved, err := filepath.EvalSymlinks(exe)
		if err != nil {
			return fmt.Errorf("resolving symlinks for %q: %w", exe, err)
		}
		o.TargetPath = resolved
	}
	return nil
}

// defaultHTTPClient honors HTTPS_PROXY/HTTP_PROXY via the environment so the
// updater works inside a pipelock-contained environment.
func defaultHTTPClient() *http.Client {
	return &http.Client{
		Timeout: httpTimeout,
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
		},
	}
}

// release is the subset of the GitHub release JSON we consume.
type release struct {
	TagName string `json:"tag_name"`
	Assets  []struct {
		Name string `json:"name"`
		URL  string `json:"browser_download_url"`
	} `json:"assets"`
}

// Status is the machine-readable result of a check or update.
type Status struct {
	CurrentVersion    string `json:"current_version"`
	LatestVersion     string `json:"latest_version"`
	UpdateAvailable   bool   `json:"update_available"`
	Applied           bool   `json:"applied"`
	TargetPath        string `json:"target_path"`
	BackupPath        string `json:"backup_path,omitempty"`
	SignatureVerified bool   `json:"signature_verified"`
	SignatureSkipped  bool   `json:"signature_skipped"`
	Asset             string `json:"asset,omitempty"`
}

// assetName returns the GoReleaser archive name for the given version/os/arch.
// version must have the leading "v" stripped but KEEP any pre-release suffix
// (e.g. "2.8.0-rc1"), because GoReleaser drops only the "v" in the archive name.
func assetName(version, goos, goarch string) string {
	ext := "tar.gz"
	if goos == "windows" {
		ext = "zip"
	}
	return fmt.Sprintf("%s_%s_%s_%s.%s", binaryName, version, goos, goarch, ext)
}

// fetchRelease retrieves the latest release or a specific tag.
func (o *Options) fetchRelease(ctx context.Context) (*release, error) {
	var url string
	if o.TargetVersion == "" {
		url = fmt.Sprintf("%s/repos/%s/%s/releases/latest", o.APIBase, repoOwner, repoName)
	} else {
		// PathEscape the tag: --version is runtime input and valid Git tags can
		// contain "/" and other reserved path characters.
		url = fmt.Sprintf("%s/repos/%s/%s/releases/tags/%s", o.APIBase, repoOwner, repoName, neturl.PathEscape(o.TargetVersion))
	}
	body, err := o.httpGet(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("fetching release metadata: %w", err)
	}
	var rel release
	if err := json.Unmarshal(body, &rel); err != nil {
		return nil, fmt.Errorf("parsing release metadata: %w", err)
	}
	if rel.TagName == "" {
		return nil, errors.New("release metadata missing tag_name")
	}
	return &rel, nil
}

// httpGet performs a bounded GET with context.
func (o *Options) httpGet(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Accept", "application/octet-stream, application/json")
	resp, err := o.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP GET %s: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP GET %s: status %d", url, resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxDownloadBytes+1))
	if err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}
	if int64(len(data)) > maxDownloadBytes {
		return nil, fmt.Errorf("response from %s exceeds %d byte limit", url, int64(maxDownloadBytes))
	}
	return data, nil
}

// assetURL finds the download URL for the named asset in a release.
func assetURL(rel *release, name string) (string, error) {
	for _, a := range rel.Assets {
		if a.Name == name {
			return a.URL, nil
		}
	}
	return "", fmt.Errorf("%w: %s", ErrAssetNotFound, name)
}
