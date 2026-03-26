// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package assess

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	"github.com/luckyPipewrench/pipelock/internal/config"
)

// configLabelDefaults is the sentinel config label used when no config file
// is specified and built-in defaults are used.
const configLabelDefaults = "defaults"

// Cmd is the parent command grouping all assess subcommands.
func Cmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "assess",
		Short: "Run a security assessment and produce a signed evidence bundle",
		Long: `Orchestrate pipelock's security primitives (simulate, audit score,
verify-install, discover) into a reproducible, signed evidence bundle.

Three phases: init creates the run directory, run executes all checks,
finalize synthesizes the report and optionally signs it.

Examples:
  pipelock assess init --config pipelock.yaml
  pipelock assess run assessment-a1b2c3d4/
  pipelock assess finalize assessment-a1b2c3d4/
  pipelock assess verify assessment-a1b2c3d4/`,
	}
	cmd.AddCommand(assessInitCmd())
	cmd.AddCommand(assessRunCmd())
	cmd.AddCommand(assessFinalizeCmd())
	cmd.AddCommand(assessVerifyCmd())
	cmd.AddCommand(assessStatusCmd())
	return cmd
}

// assessInitCmd creates and initializes an assessment run directory.
func assessInitCmd() *cobra.Command {
	var configFile string
	var outputDir string
	var jsonOutput bool

	cmd := &cobra.Command{
		Use:   "init",
		Short: "Initialize a new assessment run directory",
		Long: `Validate the pipelock config, create the run directory, and write
manifest.json with status "initialized".

The output directory defaults to assessment-<uuid-prefix>/ in the
current working directory.

Examples:
  pipelock assess init --config pipelock.yaml
  pipelock assess init --config pipelock.yaml --output-dir my-assessment/
  pipelock assess init --json`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			dir, err := runAssessInit(configFile, outputDir)
			if err != nil {
				return err
			}

			if jsonOutput {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(map[string]string{"run_dir": dir})
			}

			_, _ = fmt.Fprintln(cmd.OutOrStdout(), dir)
			return nil
		},
	}

	cmd.Flags().StringVarP(&configFile, "config", "c", "", "config file path (default: built-in defaults)")
	cmd.Flags().StringVar(&outputDir, "output-dir", "", "explicit output directory name (default: assessment-<uuid-prefix>)")
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "machine-readable output")

	return cmd
}

// runAssessInit is the testable core of assess init.
// Returns the run directory path on success.
func runAssessInit(configFile, outputDir string) (string, error) {
	// Step 1: validate config loads.
	if configFile != "" {
		if _, err := config.Load(configFile); err != nil {
			return "", cliutil.ExitCodeError(1, fmt.Errorf("loading config: %w", err))
		}
	}

	// Step 2: canonicalize config path and compute SHA-256 of config file bytes.
	// Absolute paths ensure run and finalize work from any cwd.
	configHash := ""
	configLabel := configLabelDefaults
	if configFile != "" {
		absPath, err := filepath.Abs(configFile)
		if err != nil {
			return "", cliutil.ExitCodeError(1, fmt.Errorf("resolving config path: %w", err))
		}
		configFile = absPath

		data, err := os.ReadFile(filepath.Clean(configFile))
		if err != nil {
			return "", cliutil.ExitCodeError(1, fmt.Errorf("reading config file: %w", err))
		}
		sum := sha256.Sum256(data)
		configHash = hex.EncodeToString(sum[:])
		configLabel = configFile
	}

	// Step 3: generate UUID V4.
	runID, err := newUUIDV4()
	if err != nil {
		return "", cliutil.ExitCodeError(2, fmt.Errorf("generating run ID: %w", err))
	}

	// Step 4: resolve output directory.
	if outputDir == "" {
		// Use first 8 chars of UUID (without hyphens).
		prefix := strings.ReplaceAll(runID, "-", "")[:8]
		outputDir = "assessment-" + prefix
	}

	// Step 5: refuse to clobber an existing directory.
	if _, err := os.Stat(outputDir); err == nil {
		return "", cliutil.ExitCodeError(2, fmt.Errorf("directory already exists: %s", outputDir))
	}

	// Step 6: create output directory and evidence/ subdirectory.
	if err := os.MkdirAll(outputDir, 0o750); err != nil {
		return "", cliutil.ExitCodeError(2, fmt.Errorf("creating run directory: %w", err))
	}
	evidenceDir := filepath.Join(outputDir, "evidence")
	if err := os.MkdirAll(evidenceDir, 0o750); err != nil {
		return "", cliutil.ExitCodeError(2, fmt.Errorf("creating evidence directory: %w", err))
	}

	// Step 7: try to detect git commit.
	gitCommit := detectGitCommit()

	// Step 8: populate and write manifest.
	manifest := AssessManifest{
		SchemaVersion:   assessSchemaVersion,
		Version:         cliutil.Version,
		BuildSHA:        BuildSHA,
		RunID:           runID,
		ConfigFile:      configLabel,
		ConfigHash:      configHash,
		LicenseTier:     assessTierFree, // finalize updates based on actual license
		StartedAt:       time.Now().UTC(),
		GitCommit:       gitCommit,
		Platform:        runtime.GOOS + "/" + runtime.GOARCH,
		Status:          assessStatusInitialized,
		ScoringVersion:  assessScoringVersion,
		RendererVersion: assessRendererVersion,
	}

	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return "", cliutil.ExitCodeError(2, fmt.Errorf("marshaling manifest: %w", err))
	}

	manifestPath := filepath.Join(outputDir, "manifest.json")
	if err := os.WriteFile(manifestPath, data, 0o600); err != nil {
		return "", cliutil.ExitCodeError(2, fmt.Errorf("writing manifest: %w", err))
	}

	return outputDir, nil
}

// newUUIDV4 generates a random UUID version 4 per RFC 4122.
func newUUIDV4() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	// Set version 4 (bits 76-79 of byte 6).
	b[6] = (b[6] & 0x0f) | 0x40
	// Set variant bits (bits 70-71 of byte 8).
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

// detectGitCommit attempts to read the current git HEAD commit.
// Returns empty string if git is unavailable or not in a repo.
func detectGitCommit() string {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "git", "rev-parse", "HEAD").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// BuildSHA is the git commit hash of the binary build, set via ldflags.
// Falls back to "unknown" when not set at build time.
var BuildSHA = "unknown"
