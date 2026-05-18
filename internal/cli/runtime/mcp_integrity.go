// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	mcpintegrity "github.com/luckyPipewrench/pipelock/internal/mcp/integrity"
	domsigning "github.com/luckyPipewrench/pipelock/internal/signing"
)

var errMCPIntegrityViolation = errors.New("MCP binary integrity violation")

type mcpIntegrityReport struct {
	OK         bool     `json:"ok"`
	Command    []string `json:"command"`
	Manifest   string   `json:"manifest,omitempty"`
	Signature  string   `json:"signature,omitempty"`
	Signer     string   `json:"signer,omitempty"`
	WorkDir    string   `json:"workdir,omitempty"`
	Entries    []string `json:"entries,omitempty"`
	Reasons    []string `json:"reasons,omitempty"`
	Binary     string   `json:"binary,omitempty"`
	Script     string   `json:"script,omitempty"`
	Suspicious bool     `json:"suspicious,omitempty"`
}

func mcpIntegrityCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "integrity",
		Short: "MCP binary integrity manifest tooling",
		Long: `Generate and verify the manifest consumed by mcp_binary_integrity.

The manifest pins the resolved binary path Pipelock will spawn. For interpreter
commands, it also pins the resolved script path so wrapper enforcement can catch
both interpreter replacement and script drift before launch.`,
	}
	cmd.AddCommand(mcpIntegrityManifestCmd())
	return cmd
}

func mcpIntegrityManifestCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "manifest",
		Short: "Generate and verify MCP binary integrity manifests",
	}
	cmd.AddCommand(mcpIntegrityManifestGenerateCmd())
	cmd.AddCommand(mcpIntegrityManifestVerifyCmd())
	cmd.AddCommand(mcpIntegrityManifestSignCmd())
	cmd.AddCommand(mcpIntegrityManifestVerifySignatureCmd())
	return cmd
}

func mcpIntegrityManifestGenerateCmd() *cobra.Command {
	var outputPath string
	var mergeExisting bool
	var workDir string
	var jsonOutput bool

	cmd := &cobra.Command{
		Use:   "generate --output manifest.json -- <command> [args...]",
		Short: "Generate manifest entries for one MCP server command",
		Long: `Resolve and hash the MCP server command exactly as Pipelock will before
spawning it. The generated manifest pins the resolved executable. If the command
uses a known interpreter or a shebang script, the script file is pinned too.

By default this refuses to overwrite an existing manifest. Use --merge to update
or add entries in an existing manifest.`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if outputPath == "" {
				return fmt.Errorf("--output is required")
			}
			report, err := generateMCPIntegrityManifest(outputPath, args, workDir, mergeExisting)
			if err != nil {
				return err
			}
			if jsonOutput {
				return writeMCPIntegrityJSON(cmd.OutOrStdout(), report)
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Manifest written: %s (%d %s)\n",
				outputPath, len(report.Entries), pluralEntry(len(report.Entries)))
			for _, entry := range report.Entries {
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  %s\n", entry)
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&outputPath, "output", "o", "", "manifest output path")
	cmd.Flags().BoolVar(&mergeExisting, "merge", false, "merge entries into an existing manifest instead of refusing to overwrite")
	cmd.Flags().StringVar(&workDir, "workdir", "", "working directory for resolving relative script arguments")
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "output a machine-readable report")
	return cmd
}

func mcpIntegrityManifestVerifyCmd() *cobra.Command {
	var manifestPath string
	var workDir string
	var jsonOutput bool

	cmd := &cobra.Command{
		Use:   "verify --manifest manifest.json -- <command> [args...]",
		Short: "Verify one MCP server command against a manifest",
		Long: `Resolve and hash the MCP server command exactly as Pipelock will before
spawning it, then compare the resolved executable and any resolved script against
the configured manifest.`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if manifestPath == "" {
				return fmt.Errorf("--manifest is required")
			}
			report, err := verifyMCPIntegrityManifest(manifestPath, args, workDir)
			if err != nil {
				return err
			}
			if jsonOutput {
				if jsonErr := writeMCPIntegrityJSON(cmd.OutOrStdout(), report); jsonErr != nil {
					return jsonErr
				}
			} else if report.OK {
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "MCP binary integrity verified: %s\n", strings.Join(args, " "))
			} else {
				_, _ = fmt.Fprintln(cmd.OutOrStdout(), "MCP binary integrity check failed:")
				for _, reason := range report.Reasons {
					_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  %s\n", reason)
				}
			}
			if !report.OK {
				return cliutil.ExitCodeError(1, errMCPIntegrityViolation)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&manifestPath, "manifest", "", "manifest file path")
	cmd.Flags().StringVar(&workDir, "workdir", "", "working directory for resolving relative script arguments")
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "output a machine-readable report")
	return cmd
}

func mcpIntegrityManifestSignCmd() *cobra.Command {
	var manifestPath string
	var sigPath string
	var signer string
	var keystoreDir string
	var jsonOutput bool

	cmd := &cobra.Command{
		Use:   "sign --manifest manifest.json --signer name",
		Short: "Sign an MCP binary integrity manifest",
		Long: `Create a detached Ed25519 signature for an MCP binary integrity
manifest. The signer is resolved from the Pipelock keystore.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if manifestPath == "" {
				return fmt.Errorf("--manifest is required")
			}
			report, err := signMCPIntegrityManifest(manifestPath, sigPath, signer, keystoreDir)
			if err != nil {
				return err
			}
			if jsonOutput {
				return writeMCPIntegrityJSON(cmd.OutOrStdout(), report)
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "MCP integrity manifest signed: %s\n", report.Manifest)
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Signature: %s\n", report.Signature)
			return nil
		},
	}
	cmd.Flags().StringVar(&manifestPath, "manifest", "", "manifest file path")
	cmd.Flags().StringVar(&sigPath, "sig", "", "signature file path (default <manifest>.sig)")
	cmd.Flags().StringVar(&signer, "signer", "", "signer name (or set PIPELOCK_AGENT)")
	cmd.Flags().StringVar(&keystoreDir, "keystore", "", "keystore directory (default ~/.pipelock)")
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "output a machine-readable report")
	return cmd
}

func mcpIntegrityManifestVerifySignatureCmd() *cobra.Command {
	var manifestPath string
	var sigPath string
	var signer string
	var keystoreDir string
	var jsonOutput bool

	cmd := &cobra.Command{
		Use:   "verify-signature --manifest manifest.json --signer name",
		Short: "Verify an MCP binary integrity manifest signature",
		Long: `Verify a detached Ed25519 signature for an MCP binary integrity
manifest using the configured Pipelock keystore.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if manifestPath == "" {
				return fmt.Errorf("--manifest is required")
			}
			report, err := verifyMCPIntegrityManifestSignature(manifestPath, sigPath, signer, keystoreDir)
			if jsonOutput {
				if jsonErr := writeMCPIntegrityJSON(cmd.OutOrStdout(), report); jsonErr != nil {
					return jsonErr
				}
			} else if report.OK {
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "MCP integrity manifest signature verified: %s\n", report.Manifest)
			} else {
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "MCP integrity manifest signature failed: %s\n", strings.Join(report.Reasons, "; "))
			}
			if err != nil {
				return err
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&manifestPath, "manifest", "", "manifest file path")
	cmd.Flags().StringVar(&sigPath, "sig", "", "signature file path (default <manifest>.sig)")
	cmd.Flags().StringVar(&signer, "signer", "", "signer name (or set PIPELOCK_AGENT)")
	cmd.Flags().StringVar(&keystoreDir, "keystore", "", "keystore directory (default ~/.pipelock)")
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "output a machine-readable report")
	return cmd
}

func generateMCPIntegrityManifest(outputPath string, command []string, workDir string, mergeExisting bool) (mcpIntegrityReport, error) {
	entries, result, err := manifestEntriesForCommand(command, workDir)
	if err != nil {
		return mcpIntegrityReport{}, err
	}

	manifest := &mcpintegrity.Manifest{
		Version: mcpintegrity.ManifestVersion,
		Entries: map[string]string{},
	}
	if mergeExisting {
		existing, loadErr := mcpintegrity.LoadManifest(outputPath)
		if loadErr != nil && !errors.Is(loadErr, os.ErrNotExist) {
			return mcpIntegrityReport{}, fmt.Errorf("loading existing manifest: %w", loadErr)
		}
		if existing != nil {
			manifest = existing
		}
	} else if _, err := os.Stat(filepath.Clean(outputPath)); err == nil {
		return mcpIntegrityReport{}, fmt.Errorf("manifest already exists at %s (use --merge to update it)", outputPath)
	} else if !errors.Is(err, os.ErrNotExist) {
		return mcpIntegrityReport{}, fmt.Errorf("checking existing manifest: %w", err)
	}

	if manifest.Entries == nil {
		manifest.Entries = map[string]string{}
	}
	for path, hash := range entries {
		manifest.Entries[path] = hash
	}
	if err := mcpintegrity.SaveManifest(outputPath, manifest); err != nil {
		return mcpIntegrityReport{}, err
	}

	return reportForResult(true, command, outputPath, workDir, result, sortedEntryPaths(entries), nil), nil
}

func signMCPIntegrityManifest(manifestPath, sigPath, signer, keystoreDir string) (mcpIntegrityReport, error) {
	signerName, err := resolveMCPIntegritySigner(signer)
	if err != nil {
		return mcpIntegrityReport{}, err
	}
	dir, err := cliutil.ResolveKeystoreDir(keystoreDir)
	if err != nil {
		return mcpIntegrityReport{}, err
	}
	ks := domsigning.NewKeystore(dir)
	privKey, err := ks.LoadPrivateKey(signerName)
	if err != nil {
		return mcpIntegrityReport{}, fmt.Errorf("loading key for signer %q: %w", signerName, err)
	}
	sig, err := domsigning.SignFile(manifestPath, privKey)
	if err != nil {
		return mcpIntegrityReport{}, err
	}
	if sigPath == "" {
		sigPath = manifestPath + domsigning.SigExtension
	}
	if err := domsigning.SaveSignature(sig, sigPath); err != nil {
		return mcpIntegrityReport{}, err
	}
	return mcpIntegrityReport{
		OK:        true,
		Manifest:  manifestPath,
		Signature: sigPath,
		Signer:    signerName,
		Reasons:   []string{},
	}, nil
}

func verifyMCPIntegrityManifestSignature(manifestPath, sigPath, signer, keystoreDir string) (mcpIntegrityReport, error) {
	if sigPath == "" {
		sigPath = manifestPath + domsigning.SigExtension
	}
	report := mcpIntegrityReport{
		Manifest:  manifestPath,
		Signature: sigPath,
		Signer:    signer,
		Reasons:   []string{},
	}
	signerName, err := resolveMCPIntegritySigner(signer)
	if err != nil {
		report.Reasons = append(report.Reasons, err.Error())
		return report, err
	}
	report.Signer = signerName
	dir, err := cliutil.ResolveKeystoreDir(keystoreDir)
	if err != nil {
		report.Reasons = append(report.Reasons, err.Error())
		return report, err
	}
	ks := domsigning.NewKeystore(dir)
	pubKey, err := ks.ResolvePublicKey(signerName)
	if err != nil {
		report.Reasons = append(report.Reasons, err.Error())
		return report, err
	}
	if err := domsigning.VerifyFile(manifestPath, sigPath, pubKey); err != nil {
		report.Reasons = append(report.Reasons, err.Error())
		return report, cliutil.ExitCodeError(1, errMCPIntegrityViolation)
	}
	report.OK = true
	return report, nil
}

func resolveMCPIntegritySigner(explicit string) (string, error) {
	name := explicit
	if name == "" {
		name = os.Getenv("PIPELOCK_AGENT")
	}
	if name == "" {
		return "", fmt.Errorf("signer name required: use --signer or set PIPELOCK_AGENT")
	}
	if err := domsigning.ValidateAgentName(name); err != nil {
		return "", err
	}
	return name, nil
}

func verifyMCPIntegrityManifest(manifestPath string, command []string, workDir string) (mcpIntegrityReport, error) {
	manifest, err := mcpintegrity.LoadManifest(manifestPath)
	if err != nil {
		return mcpIntegrityReport{}, err
	}
	cfg := &mcpintegrity.Config{Manifests: manifest.Entries}
	result, err := mcpintegrity.Verify(command, cfg, workDir)
	if err != nil {
		return mcpIntegrityReport{}, err
	}
	return reportForResult(result.Verified, command, manifestPath, workDir, result, nil, result.Reasons), nil
}

func manifestEntriesForCommand(command []string, workDir string) (map[string]string, *mcpintegrity.VerifyResult, error) {
	result, err := mcpintegrity.Resolve(command, workDir)
	if err != nil {
		return nil, nil, err
	}
	// The Suspicious flag in VerifyResult is meaningful only at runtime
	// (the agent's spawn cwd matches workDir). At generate time the
	// operator is intentionally pointing the tool at a binary they want
	// to pin, so "binary lives inside workDir" is not a warning; it is
	// the expected case. Surfacing it would train operators to ignore
	// the flag, weakening the runtime signal. Zero it out here.
	result.Suspicious = false
	entries := map[string]string{
		result.ResolvedPath: result.ActualHash,
	}
	if result.ScriptPath != "" {
		entries[result.ScriptPath] = result.ScriptHash
	}
	return entries, result, nil
}

func reportForResult(ok bool, command []string, manifestPath string, workDir string, result *mcpintegrity.VerifyResult, entries []string, reasons []string) mcpIntegrityReport {
	report := mcpIntegrityReport{
		OK:         ok,
		Command:    append([]string(nil), command...),
		Manifest:   manifestPath,
		WorkDir:    workDir,
		Entries:    append([]string(nil), entries...),
		Reasons:    append([]string(nil), reasons...),
		Binary:     result.ResolvedPath,
		Script:     result.ScriptPath,
		Suspicious: result.Suspicious,
	}
	if report.Reasons == nil {
		report.Reasons = []string{}
	}
	return report
}

func sortedEntryPaths(entries map[string]string) []string {
	paths := make([]string, 0, len(entries))
	for path := range entries {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	return paths
}

func writeMCPIntegrityJSON(out io.Writer, report mcpIntegrityReport) error {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal MCP integrity report: %w", err)
	}
	_, _ = fmt.Fprintln(out, string(data))
	return nil
}

func pluralEntry(n int) string {
	if n == 1 {
		return "entry"
	}
	return "entries"
}
