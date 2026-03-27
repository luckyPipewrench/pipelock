// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
)

// redirectProfileFetchProxy routes HTTP through pipelock's scanner.
const redirectProfileFetchProxy = "fetch-proxy"

// redirectProfileQuarantineWrite diverts writes to a quarantine directory.
const redirectProfileQuarantineWrite = "quarantine-write"

// redirectProfileAppendOnlyLog forces output to a local append-only log file.
const redirectProfileAppendOnlyLog = "append-only-log"

// RedirectManifest describes the operation to redirect. Passed from parent
// via __PIPELOCK_REDIRECT_MANIFEST env var as JSON.
type RedirectManifest struct {
	Profile       string   `json:"profile"`                  // redirect profile name
	Command       []string `json:"command"`                  // original requested command + argv
	Reason        string   `json:"reason"`                   // why the redirect was triggered
	PolicyRule    string   `json:"policy_rule"`              // policy rule that triggered it
	FetchEndpoint string   `json:"fetch_endpoint,omitempty"` // e.g. "http://127.0.0.1:8888/fetch"
	QuarantineDir string   `json:"quarantine_dir,omitempty"` // resolved quarantine directory path
}

// RedirectResult is the machine-readable JSON output from the handler.
type RedirectResult struct {
	Status     string `json:"status"`                // "ok" or "error"
	Profile    string `json:"profile"`               // which profile was executed
	Detail     string `json:"detail,omitempty"`      // human-readable detail
	Error      string `json:"error,omitempty"`       // error message if status=error
	BuildID    string `json:"build_id,omitempty"`    // binary build ID for attestation
	BinaryHash string `json:"binary_hash,omitempty"` // SHA-256 of /proc/self/exe
}

// InternalRedirectCmd returns the internal-redirect cobra command.
func InternalRedirectCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:           "internal-redirect <profile>",
		Short:         "Execute a redirected operation (internal use only)",
		Hidden:        true,
		SilenceUsage:  true,
		SilenceErrors: true,
		Args:          cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			profile := args[0]
			payload := args[1:]

			// Read manifest from parent.
			manifestJSON := os.Getenv("__PIPELOCK_REDIRECT_MANIFEST")
			if manifestJSON == "" {
				return emitRedirectError(cmd, profile, "missing __PIPELOCK_REDIRECT_MANIFEST env var")
			}

			var manifest RedirectManifest
			if err := json.Unmarshal([]byte(manifestJSON), &manifest); err != nil {
				return emitRedirectError(cmd, profile, fmt.Sprintf("invalid manifest JSON: %v", err))
			}

			// Execute based on profile.
			switch profile {
			case redirectProfileFetchProxy:
				return executeFetchProxy(cmd, &manifest, payload)
			case redirectProfileQuarantineWrite:
				return executeQuarantineWrite(cmd, &manifest, payload)
			case redirectProfileAppendOnlyLog:
				return executeAppendOnlyLog(cmd, &manifest)
			default:
				return emitRedirectError(cmd, profile, fmt.Sprintf("unknown redirect profile: %q", profile))
			}
		},
	}
	return cmd
}

// fetchProxyTimeout is the HTTP request timeout for the fetch-proxy handler.
const fetchProxyTimeout = 25 * time.Second

// executeFetchProxy routes an HTTP request through pipelock's own fetch endpoint
// for safe, scanned content retrieval. It extracts the first URL from the tool
// call payload, fetches it via pipelock's /fetch endpoint, and returns the
// scanned content as the redirect result.
func executeFetchProxy(cmd *cobra.Command, manifest *RedirectManifest, payload []string) error {
	if manifest.FetchEndpoint == "" {
		return emitRedirectError(cmd, redirectProfileFetchProxy, "no fetch_endpoint in manifest")
	}

	// Extract first http:// or https:// URL from payload args.
	targetURL := extractURL(strings.Join(payload, " "))
	if targetURL == "" {
		return emitRedirectError(cmd, redirectProfileFetchProxy,
			"no http/https URL found in tool arguments")
	}

	// Call pipelock's own fetch endpoint.
	fetchURL := manifest.FetchEndpoint + "?url=" + url.QueryEscape(targetURL)

	ctx, cancel := context.WithTimeout(context.Background(), fetchProxyTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fetchURL, nil)
	if err != nil {
		return emitRedirectError(cmd, redirectProfileFetchProxy,
			fmt.Sprintf("creating fetch request: %v", err))
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return emitRedirectError(cmd, redirectProfileFetchProxy,
			fmt.Sprintf("fetch request failed: %v", err))
	}
	defer func() { _ = resp.Body.Close() }()

	var fetchResp struct {
		Content     string `json:"content"`
		Error       string `json:"error"`
		Blocked     bool   `json:"blocked"`
		BlockReason string `json:"block_reason"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&fetchResp); err != nil {
		return emitRedirectError(cmd, redirectProfileFetchProxy,
			fmt.Sprintf("decoding fetch response: %v", err))
	}

	if fetchResp.Blocked {
		return emitRedirectError(cmd, redirectProfileFetchProxy,
			fmt.Sprintf("URL blocked by pipelock: %s", fetchResp.BlockReason))
	}
	if fetchResp.Error != "" {
		return emitRedirectError(cmd, redirectProfileFetchProxy,
			fmt.Sprintf("fetch error: %s", fetchResp.Error))
	}

	return emitRedirectResult(cmd, &RedirectResult{
		Status:  "ok",
		Profile: redirectProfileFetchProxy,
		Detail:  fetchResp.Content,
	})
}

// extractURL finds the first http:// or https:// URL in text.
func extractURL(text string) string {
	for _, prefix := range []string{"https://", "http://"} {
		idx := strings.Index(text, prefix)
		if idx < 0 {
			continue
		}
		end := idx + len(prefix)
		for end < len(text) && text[end] != ' ' && text[end] != '"' && text[end] != '\'' && text[end] != '}' {
			end++
		}
		return text[idx:end]
	}
	return ""
}

// maxQuarantineFiles is the safety limit for the quarantine directory.
// Prevents disk exhaustion from sustained redirect traffic.
const maxQuarantineFiles = 1000

// executeQuarantineWrite diverts a write to a quarantine directory for operator
// review. Returns a success-shaped response so the agent does not retry.
func executeQuarantineWrite(cmd *cobra.Command, manifest *RedirectManifest, payload []string) error {
	if manifest.QuarantineDir == "" {
		return emitRedirectError(cmd, redirectProfileQuarantineWrite, "no quarantine_dir in manifest")
	}
	qDir := filepath.Clean(manifest.QuarantineDir)

	// Create dir if it doesn't exist.
	if err := os.MkdirAll(qDir, 0o750); err != nil {
		return emitRedirectError(cmd, redirectProfileQuarantineWrite,
			fmt.Sprintf("creating quarantine dir: %v", err))
	}

	// Check file count limit.
	entries, err := os.ReadDir(qDir)
	if err != nil {
		return emitRedirectError(cmd, redirectProfileQuarantineWrite,
			fmt.Sprintf("reading quarantine dir: %v", err))
	}
	if len(entries) > maxQuarantineFiles {
		return emitRedirectError(cmd, redirectProfileQuarantineWrite,
			fmt.Sprintf("quarantine dir has %d files (limit: %d)", len(entries), maxQuarantineFiles))
	}

	// Build quarantine entry.
	now := time.Now().UTC()
	toolArgs := strings.Join(payload, " ")
	entry := map[string]string{
		"timestamp":   now.Format(time.RFC3339),
		"profile":     redirectProfileQuarantineWrite,
		"policy_rule": manifest.PolicyRule,
		"reason":      manifest.Reason,
		"tool_args":   toolArgs,
	}
	data, err := json.MarshalIndent(entry, "", "  ")
	if err != nil {
		return emitRedirectError(cmd, redirectProfileQuarantineWrite,
			fmt.Sprintf("marshaling quarantine entry: %v", err))
	}

	// Write with timestamp + hash filename.
	h := sha256.Sum256(data)
	filename := fmt.Sprintf("%s-%s.json", now.Format("20060102T150405Z"), hex.EncodeToString(h[:4]))
	path := filepath.Join(qDir, filename)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return emitRedirectError(cmd, redirectProfileQuarantineWrite,
			fmt.Sprintf("writing quarantine file: %v", err))
	}

	return emitRedirectResult(cmd, &RedirectResult{
		Status:  "ok",
		Profile: redirectProfileQuarantineWrite,
		Detail:  "Operation completed (quarantined by pipelock). Payload logged for operator review.",
	})
}

// executeAppendOnlyLog forces log output to a local append-only file.
// NOT YET IMPLEMENTED -- fail closed until Stream 3B wires the calling path.
func executeAppendOnlyLog(cmd *cobra.Command, manifest *RedirectManifest) error {
	return emitRedirectError(cmd, redirectProfileAppendOnlyLog,
		fmt.Sprintf("append-only-log redirect not yet implemented (command: %v, reason: %s)", manifest.Command, manifest.Reason))
}

// emitRedirectResult writes a JSON result to stdout with attestation fields.
func emitRedirectResult(cmd *cobra.Command, result *RedirectResult) error {
	result.BuildID = buildID()
	result.BinaryHash = binaryHash()
	enc := json.NewEncoder(cmd.OutOrStdout())
	enc.SetIndent("", "  ")
	return enc.Encode(result)
}

// emitRedirectError writes an error result and returns a non-zero exit.
func emitRedirectError(cmd *cobra.Command, profile, msg string) error {
	result := &RedirectResult{
		Status:  "error",
		Profile: profile,
		Error:   msg,
	}
	_ = emitRedirectResult(cmd, result)
	return cliutil.ExitCodeError(1, fmt.Errorf("redirect error: %s", msg))
}

// buildID returns the Go build ID for attestation.
func buildID() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown"
	}
	for _, s := range info.Settings {
		if s.Key == "vcs.revision" {
			return s.Value
		}
	}
	return info.Main.Version
}

// binaryHash returns the SHA-256 of /proc/self/exe for attestation.
func binaryHash() string {
	data, err := os.ReadFile("/proc/self/exe")
	if err != nil {
		return "unavailable"
	}
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}
