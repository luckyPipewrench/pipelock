package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

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
	var jsonOutput bool
	var excludePaths []string
	var verbose bool

	cmd := &cobra.Command{
		Use:   "scan-diff",
		Short: "Scan a unified diff for secrets",
		Long: `Reads a unified diff from stdin and scans added lines for DLP pattern matches.

Designed for use in git hooks or CI pipelines. Exit code 1 if secrets are found.

Examples:
  git diff HEAD~1 | pipelock git scan-diff
  git diff --cached | pipelock git scan-diff --config pipelock.yaml
  git diff HEAD~1 | pipelock git scan-diff --json
  git diff HEAD~1 | pipelock git scan-diff --exclude vendor/ --exclude "*.generated.go"`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := loadConfigOrDefault(configFile)
			if err != nil {
				return err
			}

			const maxDiffSize = 100 * 1024 * 1024 // 100 MB
			diffData, err := io.ReadAll(io.LimitReader(os.Stdin, maxDiffSize+1))
			if err != nil {
				return fmt.Errorf("reading diff from stdin: %w", err)
			}
			if len(diffData) > maxDiffSize {
				return fmt.Errorf("diff exceeds maximum size of %d bytes", maxDiffSize)
			}

			if len(diffData) == 0 {
				if jsonOutput {
					_, _ = fmt.Fprintln(cmd.OutOrStdout(), "[]")
					return nil
				}
				_, _ = fmt.Fprintln(cmd.ErrOrStderr(), "No diff content on stdin.")
				return nil
			}

			patterns := gitprotect.CompileDLPPatterns(cfg.DLP.Patterns)
			findings, scanErr := gitprotect.ScanDiff(string(diffData), patterns)
			if scanErr != nil {
				_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "Warning: %v\n", scanErr)
			}

			// Suppression: inline comments and config entries
			findings, suppressed, reasons := suppressGitFindings(findings, cfg.Suppress)
			if verbose && len(suppressed) > 0 {
				printSuppressedGit(cmd.ErrOrStderr(), suppressed, reasons)
			}

			// Filter excluded paths from findings
			if len(excludePaths) > 0 {
				filtered := findings[:0:0]
				for _, f := range findings {
					if f.File != "" && shouldExclude(f.File, excludePaths) {
						continue
					}
					filtered = append(filtered, f)
				}
				findings = filtered
			}

			if jsonOutput {
				data, jsonErr := gitprotect.FindingsJSON(findings)
				if jsonErr != nil {
					return fmt.Errorf("encoding findings: %w", jsonErr)
				}
				_, _ = fmt.Fprintln(cmd.OutOrStdout(), string(data)) //nolint:gosec // G705: CLI output, not web
			} else {
				_, _ = fmt.Fprint(cmd.ErrOrStderr(), gitprotect.FormatFindings(findings)) //nolint:gosec // G705: CLI output, not web
			}

			if len(findings) > 0 {
				return ErrSecretsFound
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&configFile, "config", "c", "", "config file path")
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "output findings as JSON")
	cmd.Flags().StringArrayVar(&excludePaths, "exclude", nil, "exclude paths from findings (glob or directory prefix, repeatable)")
	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "print suppressed findings to stderr")
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
		RunE: func(cmd *cobra.Command, _ []string) error {
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

			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Installed pre-push hook at %s\n", hookPath)
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
		info, err := os.Stat(gitPath)
		if err == nil {
			if info.IsDir() {
				return gitPath, nil
			}
			// .git is a file (worktree/submodule): parse "gitdir: <path>"
			resolved, err := resolveGitFile(gitPath, dir)
			if err != nil {
				return "", err
			}
			return resolved, nil
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("not a git repository (no .git directory found)")
		}
		dir = parent
	}
}

// resolveGitFile reads a .git file (used by worktrees/submodules) and
// returns the absolute path to the actual git directory.
func resolveGitFile(gitFilePath, baseDir string) (string, error) {
	data, err := os.ReadFile(gitFilePath) //nolint:gosec // reading .git pointer file
	if err != nil {
		return "", fmt.Errorf("reading .git file: %w", err)
	}
	content := strings.TrimSpace(string(data))
	if !strings.HasPrefix(content, "gitdir: ") {
		return "", fmt.Errorf("invalid .git file: expected 'gitdir: <path>', got %q", content)
	}
	gitdir := strings.TrimPrefix(content, "gitdir: ")
	if !filepath.IsAbs(gitdir) {
		gitdir = filepath.Join(baseDir, gitdir)
	}
	gitdir = filepath.Clean(gitdir)
	if info, err := os.Stat(gitdir); err != nil || !info.IsDir() {
		return "", fmt.Errorf("gitdir path %q does not exist or is not a directory", gitdir)
	}
	return gitdir, nil
}
