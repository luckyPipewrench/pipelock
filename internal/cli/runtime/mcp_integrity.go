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
)

var errMCPIntegrityViolation = errors.New("MCP binary integrity violation")

type mcpIntegrityReport struct {
	OK         bool     `json:"ok"`
	Command    []string `json:"command"`
	Manifest   string   `json:"manifest,omitempty"`
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
	result, err := mcpintegrity.Verify(command, &mcpintegrity.Config{Manifests: map[string]string{}}, workDir)
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
