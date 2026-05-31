// Package scan implements the `pipelock scan` command: it inspects files for
// invisible-Unicode and bidi-control injection (the supply-chain vector that
// hides instructions in agent-context files). It complements the network
// scanner - pipelock the proxy never sees files at rest, so this surfaces the
// local-file half of the attack and lets pre-commit hooks and CI gate on it.
package scan

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	"github.com/luckyPipewrench/pipelock/internal/filescan"
)

// Exit codes (distinct so CI wrappers can tell findings from a broken scan):
//
//	0 = clean, 1 = findings at/above the gating severity, 2 = scan/IO/config error.
const (
	exitFindings = 1
	exitError    = 2
)

// severityRank orders severities for threshold gating (higher = more severe).
var severityRank = map[filescan.Severity]int{
	filescan.SeverityLow:  1,
	filescan.SeverityMed:  2,
	filescan.SeverityHigh: 3,
}

// Cmd builds the `pipelock scan` command.
func Cmd() *cobra.Command {
	var (
		jsonOutput  bool
		maxBytes    int64
		exclude     []string
		minSeverity string
		includeDeps bool
		failOnSkip  bool
	)

	cmd := &cobra.Command{
		Use:   "scan [path...]",
		Short: "Scan files for invisible-Unicode / bidi-control injection",
		Long: `Scan files or directories for hidden Unicode characters used to inject
instructions into agent-context files (CLAUDE.md, .cursorrules, AGENTS.md,
skill definitions) — zero-width, bidi-override, tag, and control characters a
human reviewer cannot see. This is the local-file half of supply-chain prompt
injection; the network proxy cannot see files at rest.

Findings carry a severity (high/medium/low) because not every invisible
character is equally suspicious in a file: a leading BOM, an emoji ZWJ, or a
soft hyphen in prose are low; a right-to-left override or tag character inside
an instruction file is high. Use --min-severity to control what causes a
non-zero exit. The default gates on high severity and reports lower severities.

Exit codes: 0 = no gated findings; 1 = findings at/above --min-severity;
2 = scan/config error, an explicitly named file was skipped (binary, symlink,
oversized), or --fail-on-skip and any file was skipped.

Examples:
  pipelock scan                          # scan the current directory
  pipelock scan CLAUDE.md .cursorrules
  pipelock scan ~/.claude/skills --json
  pipelock scan . --min-severity medium  # also gate on suspicious-but-contextual chars
  pipelock scan . --fail-on-skip         # fail CI if anything went uninspected
  pipelock scan . --include-deps         # also scan vendored/node_modules context`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			threshold, ok := severityRank[filescan.Severity(minSeverity)]
			if !ok {
				return cliutil.ExitCodeError(exitError,
					fmt.Errorf("invalid --min-severity %q (want high, medium, or low)", minSeverity))
			}
			explicitArgs := len(args) > 0
			if !explicitArgs {
				args = []string{"."}
			}

			res, err := filescan.ScanPaths(args, filescan.Options{
				MaxFileBytes:     maxBytes,
				ExtraExcludeDirs: exclude,
				IncludeDepDirs:   includeDeps,
			})
			if err != nil {
				return cliutil.ExitCodeError(exitError, err)
			}

			if jsonOutput {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetEscapeHTML(false)
				enc.SetIndent("", "  ")
				if encErr := enc.Encode(res); encErr != nil {
					return cliutil.ExitCodeError(exitError, encErr)
				}
			} else {
				w := bufio.NewWriter(cmd.OutOrStdout())
				res.WriteReport(w)
			}

			if failOnSkip && len(res.Skipped) > 0 {
				return cliutil.ExitCodeError(exitError,
					fmt.Errorf("scan skipped %d file(s); rerun without --fail-on-skip to allow skips", len(res.Skipped)))
			}
			if explicitSkipped := explicitlySkippedFiles(args, res.Skipped); explicitSkipped > 0 {
				return cliutil.ExitCodeError(exitError,
					fmt.Errorf("scan skipped %d explicitly requested file(s)", explicitSkipped))
			}

			gating := 0
			for _, f := range res.Findings {
				if severityRank[f.Severity] >= threshold {
					gating++
				}
			}
			if gating > 0 {
				return cliutil.ExitCodeError(exitFindings,
					fmt.Errorf("%w: %d at/above %s in %d file(s)",
						filescan.ErrFindings, gating, minSeverity, res.FilesScanned))
			}
			return nil
		},
	}

	cmd.Flags().BoolVar(&jsonOutput, "json", false, "emit findings as JSON")
	cmd.Flags().Int64Var(&maxBytes, "max-bytes", 0, "skip files larger than N bytes (default 5 MiB)")
	cmd.Flags().StringSliceVar(&exclude, "exclude", nil, "additional directory names to skip")
	cmd.Flags().StringVar(&minSeverity, "min-severity", "high", "minimum severity that causes a non-zero exit (high|medium|low)")
	cmd.Flags().BoolVar(&includeDeps, "include-deps", false, "also scan dependency/VCS dirs (node_modules, vendor, .git, ...)")
	cmd.Flags().BoolVar(&failOnSkip, "fail-on-skip", false, "exit 2 if any file is skipped")

	return cmd
}

func explicitlySkippedFiles(args []string, skipped []filescan.Skip) int {
	if len(skipped) == 0 {
		return 0
	}
	explicitFiles := map[string]struct{}{}
	for _, arg := range args {
		clean := filepath.Clean(arg)
		info, err := os.Lstat(clean)
		if err != nil || info.IsDir() {
			continue
		}
		explicitFiles[clean] = struct{}{}
	}
	if len(explicitFiles) == 0 {
		return 0
	}
	var n int
	for _, sk := range skipped {
		if _, ok := explicitFiles[filepath.Clean(sk.Path)]; ok {
			n++
		}
	}
	return n
}
