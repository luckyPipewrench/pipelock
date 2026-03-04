package cli

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/preflight"
)

func preflightCmd() *cobra.Command {
	var jsonOutput bool
	var ciMode bool
	var noColor bool
	var excludePaths []string

	cmd := &cobra.Command{
		Use:   "preflight [directory]",
		Short: "Scan repo for dangerous AI agent config before opening it",
		Long: `Scan a repository for dangerous AI agent configuration files (hooks, MCP
servers, env overrides) that could execute arbitrary code when an IDE opens
the project.

Detects 5 attack classes: hook RCE, MCP server RCE, credential redirect,
auto-approval weakening, and command obfuscation.

Examples:
  pipelock preflight .
  pipelock preflight ./untrusted-repo --ci
  pipelock preflight . --json
  pipelock preflight . --exclude .claude/commands/`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var opts []preflight.Option
			if ciMode {
				opts = append(opts, preflight.WithCI())
			}

			report, err := preflight.Scan(args[0], opts...)
			if err != nil {
				return ExitCodeError(2, err)
			}
			report.Version = Version

			// Filter excludes
			if len(excludePaths) > 0 {
				filtered := report.Findings[:0:0]
				for _, f := range report.Findings {
					if f.File != "" && shouldExclude(f.File, excludePaths) {
						continue
					}
					filtered = append(filtered, f)
				}
				report.Findings = filtered
				report.RecomputeSummary()
			}

			if jsonOutput {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				if err := enc.Encode(report); err != nil {
					return err
				}
			} else {
				color := useColor() && !noColor
				printPreflightReport(cmd, report, color)
			}

			// CI gate: exit 1 if critical or high findings (checked for both output formats)
			if ciMode && (report.Summary.Critical > 0 || report.Summary.High > 0) {
				return ExitCodeError(1, fmt.Errorf("preflight found %d critical and %d high severity finding(s)",
					report.Summary.Critical, report.Summary.High))
			}

			return nil
		},
	}

	cmd.Flags().BoolVar(&jsonOutput, "json", false, "output findings as JSON")
	cmd.Flags().BoolVar(&ciMode, "ci", false, "CI gate mode: exit 1 on critical/high findings, warn on committed local settings")
	cmd.Flags().BoolVar(&noColor, "no-color", false, "disable color output")
	cmd.Flags().StringArrayVar(&excludePaths, "exclude", nil, "exclude paths from findings (repeatable)")

	return cmd
}

func printPreflightReport(cmd *cobra.Command, r *preflight.Report, color bool) {
	w := cmd.ErrOrStderr()

	_, _ = fmt.Fprintln(w, "Pipelock Preflight Scan")
	_, _ = fmt.Fprintln(w, "======================")
	_, _ = fmt.Fprintln(w)
	_, _ = fmt.Fprintf(w, "Directory: %s\n", r.Directory)
	_, _ = fmt.Fprintf(w, "Files scanned: %d\n", len(r.FilesScanned))
	_, _ = fmt.Fprintln(w)

	if len(r.Findings) == 0 {
		_, _ = fmt.Fprintln(w, "  No findings. Repository config looks clean.")
		return
	}

	_, _ = fmt.Fprintln(w, "Findings:")
	_, _ = fmt.Fprintln(w)

	for _, f := range r.Findings {
		tag := severityTag(f.Severity, color)
		msg := fmt.Sprintf("  %s %s", tag, f.Message)
		if f.File != "" {
			msg += fmt.Sprintf(" (%s", f.File)
			if f.Line > 0 {
				msg += fmt.Sprintf(":%d", f.Line)
			}
			msg += ")"
		}
		_, _ = fmt.Fprintln(w, msg)
	}

	_, _ = fmt.Fprintln(w)
	_, _ = fmt.Fprintf(w, "Summary: %d critical, %d high, %d warning, %d info\n",
		r.Summary.Critical, r.Summary.High, r.Summary.Warning, r.Summary.Info)
}

func severityTag(sev string, color bool) string {
	if !color {
		return "[" + strings.ToUpper(sev) + "]"
	}
	switch sev {
	case preflight.SevCritical:
		return "\033[1;31m[CRITICAL]\033[0m"
	case preflight.SevHigh:
		return "\033[1;33m[HIGH]\033[0m"
	case preflight.SevWarning:
		return "\033[0;33m[WARNING]\033[0m"
	default:
		return "\033[0;36m[INFO]\033[0m"
	}
}
