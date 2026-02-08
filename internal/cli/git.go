package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/gitprotect"
)

// ErrSecretsFound is returned when pipelock git scan-diff detects secrets.
var ErrSecretsFound = errors.New("secrets found in diff")

func gitCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "git",
		Short: "Git-aware security commands",
		Long: `Git integration for pre-push secret scanning and hook management.

Examples:
  git diff HEAD~1 | pipelock git scan-diff
  pipelock git install-hooks`,
	}

	cmd.AddCommand(scanDiffCmd())
	cmd.AddCommand(installHooksCmd())
	return cmd
}

func scanDiffCmd() *cobra.Command {
	var configFile string

	cmd := &cobra.Command{
		Use:   "scan-diff",
		Short: "Scan a unified diff for secrets",
		Long: `Reads a unified diff from stdin and scans added lines for DLP pattern matches.

Designed for use in git hooks or CI pipelines. Exit code 1 if secrets are found.

Examples:
  git diff HEAD~1 | pipelock git scan-diff
  git diff --cached | pipelock git scan-diff --config pipelock.yaml`,
		RunE: func(_ *cobra.Command, _ []string) error {
			cfg, err := loadConfigOrDefault(configFile)
			if err != nil {
				return err
			}

			diffData, err := io.ReadAll(os.Stdin)
			if err != nil {
				return fmt.Errorf("reading diff from stdin: %w", err)
			}

			if len(diffData) == 0 {
				fmt.Fprintln(os.Stderr, "No diff content on stdin.")
				return nil
			}

			patterns := gitprotect.CompileDLPPatterns(cfg.DLP.Patterns)
			findings := gitprotect.ScanDiff(string(diffData), patterns)

			fmt.Fprint(os.Stderr, gitprotect.FormatFindings(findings))

			if len(findings) > 0 {
				return ErrSecretsFound
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&configFile, "config", "c", "", "config file path")
	return cmd
}

func installHooksCmd() *cobra.Command {
	var configFile string
	var binary string
	var force bool

	cmd := &cobra.Command{
		Use:   "install-hooks",
		Short: "Install git pre-push hook for secret scanning",
		Long: `Writes a pre-push hook to .git/hooks/pre-push that runs pipelock git scan-diff
before each push. The hook blocks pushes if secrets are detected (fail-closed).

If .git/hooks/pre-push already exists, use --force to overwrite it.

Examples:
  pipelock git install-hooks
  pipelock git install-hooks --config /etc/pipelock.yaml
  pipelock git install-hooks --force`,
		RunE: func(_ *cobra.Command, _ []string) error {
			gitDir, err := findGitDir()
			if err != nil {
				return err
			}

			hookPath := filepath.Join(gitDir, "hooks", "pre-push")

			if !force {
				if _, err := os.Stat(hookPath); err == nil {
					return fmt.Errorf("hook already exists at %s (use --force to overwrite)", hookPath)
				}
			}

			if binary == "" {
				binary = "pipelock"
			}

			hookContent := gitprotect.GeneratePrePushHook(binary, configFile)

			hooksDir := filepath.Join(gitDir, "hooks")
			if err := os.MkdirAll(hooksDir, 0o750); err != nil {
				return fmt.Errorf("creating hooks directory: %w", err)
			}

			if err := os.WriteFile(hookPath, []byte(hookContent), 0o755); err != nil { //nolint:gosec // hooks must be executable
				return fmt.Errorf("writing hook: %w", err)
			}

			fmt.Fprintf(os.Stderr, "Installed pre-push hook at %s\n", hookPath)
			return nil
		},
	}

	cmd.Flags().StringVarP(&configFile, "config", "c", "", "config file path for the hook to use")
	cmd.Flags().StringVar(&binary, "binary", "", "path to pipelock binary (default: pipelock in PATH)")
	cmd.Flags().BoolVar(&force, "force", false, "overwrite existing hook")
	return cmd
}

func loadConfigOrDefault(path string) (*config.Config, error) {
	if path != "" {
		return config.Load(path)
	}
	return config.Defaults(), nil
}

func findGitDir() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("getting working directory: %w", err)
	}

	for {
		gitPath := filepath.Join(dir, ".git")
		if info, err := os.Stat(gitPath); err == nil && info.IsDir() {
			return gitPath, nil
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("not a git repository (no .git directory found)")
		}
		dir = parent
	}
}
