// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"runtime/debug"

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

// executeFetchProxy routes an HTTP request through pipelock's scanner.
// NOT YET IMPLEMENTED -- fail closed until Stream 3B wires the calling path.
func executeFetchProxy(cmd *cobra.Command, manifest *RedirectManifest, _ []string) error {
	return emitRedirectError(cmd, redirectProfileFetchProxy,
		fmt.Sprintf("fetch-proxy redirect not yet implemented (command: %v, reason: %s)", manifest.Command, manifest.Reason))
}

// executeQuarantineWrite diverts a write to a quarantine directory.
// NOT YET IMPLEMENTED -- fail closed until Stream 3B wires the calling path.
func executeQuarantineWrite(cmd *cobra.Command, manifest *RedirectManifest, _ []string) error {
	return emitRedirectError(cmd, redirectProfileQuarantineWrite,
		fmt.Sprintf("quarantine-write redirect not yet implemented (command: %v, reason: %s)", manifest.Command, manifest.Reason))
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
