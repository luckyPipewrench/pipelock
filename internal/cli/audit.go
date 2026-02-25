package cli

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/projectscan"
)

func auditCmd() *cobra.Command {
	var output string
	var jsonOutput bool
	var excludePaths []string
	var configFile string
	var verbose bool

	cmd := &cobra.Command{
		Use:   "audit [directory]",
		Short: "Scan a project and generate a suggested security config",
		Long: `Scan a project directory for security risks and generate a suggested Pipelock config.

Detects agent type, programming languages, package ecosystems, MCP servers,
and secrets in environment variables and config files.

Examples:
  pipelock audit .
  pipelock audit ./my-project -o pipelock-suggested.yaml
  pipelock audit ./my-project --json
  pipelock audit . --exclude vendor/ --exclude "*.generated.go"
  pipelock audit . --config pipelock.yaml --verbose`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			report, err := projectscan.Scan(args[0])
			if err != nil {
				return err
			}

			// Load config for suppress entries (if provided)
			cfg, cfgErr := loadConfigOrDefault(configFile)
			if cfgErr != nil {
				return cfgErr
			}

			// Suppression: inline comments and config entries
			var suppressed []projectscan.Finding
			var reasons []suppressResult
			report.Findings, suppressed, reasons = suppressProjectFindings(report.Findings, cfg.Suppress)
			if verbose && len(suppressed) > 0 {
				printSuppressedProject(cmd.ErrOrStderr(), suppressed, reasons)
			}
			if len(suppressed) > 0 {
				report.AdjustScoreForFindings()
			}

			// Filter excluded paths from findings and recompute scores
			if len(excludePaths) > 0 {
				filtered := report.Findings[:0:0]
				for _, f := range report.Findings {
					if f.File != "" && shouldExclude(f.File, excludePaths) {
						continue
					}
					filtered = append(filtered, f)
				}
				report.Findings = filtered
				report.AdjustScoreForFindings()
			}

			if jsonOutput {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(report)
			}

			printReport(cmd, report)

			if report.Config != nil {
				cfgYAML, err := report.Config.RenderYAML()
				if err != nil {
					return err
				}

				if output != "" {
					if err := os.WriteFile(output, []byte(cfgYAML), 0o600); err != nil {
						return fmt.Errorf("writing config: %w", err)
					}
					cmd.PrintErrln()
					cmd.PrintErrf("Config written to: %s\n", output)
					cmd.PrintErrln("Review and rename to pipelock.yaml when ready.")
				} else {
					cmd.PrintErrln()
					cmd.PrintErrln("Suggested config (use -o to write to file):")
					cmd.PrintErrln("---")
					_, _ = fmt.Fprint(cmd.OutOrStdout(), cfgYAML)
				}
			}

			return nil
		},
	}

	cmd.Flags().StringVarP(&output, "output", "o", "", "write suggested config to file")
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "output findings as JSON")
	cmd.Flags().StringArrayVar(&excludePaths, "exclude", nil, "exclude paths from findings (glob or directory prefix, repeatable)")
	cmd.Flags().StringVarP(&configFile, "config", "c", "", "config file path (for suppress entries)")
	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "print suppressed findings to stderr")

	return cmd
}

func printReport(cmd *cobra.Command, r *projectscan.Report) {
	cmd.PrintErrln("Pipelock Security Audit")
	cmd.PrintErrln("=======================")
	cmd.PrintErrln()

	cmd.PrintErrf("Directory:  %s\n", r.Dir)
	cmd.PrintErrf("Agent type: %s\n", r.AgentType)
	if len(r.Languages) > 0 {
		cmd.PrintErrf("Languages:  %s\n", joinMax(r.Languages, 5))
	}
	if len(r.Ecosystems) > 0 {
		cmd.PrintErrf("Ecosystems: %s\n", joinMax(r.Ecosystems, 5))
	}

	cmd.PrintErrln()
	cmd.PrintErrln("Findings:")
	cmd.PrintErrln()

	criticals := 0
	warnings := 0
	infos := 0

	for _, f := range r.Findings {
		var prefix string
		switch f.Severity {
		case "critical":
			prefix = "  [CRITICAL] "
			criticals++
		case "warning":
			prefix = "  [WARNING]  "
			warnings++
		default:
			prefix = "  [INFO]     "
			infos++
		}

		msg := prefix + f.Message
		if f.File != "" {
			msg += fmt.Sprintf(" (%s", f.File)
			if f.Line > 0 {
				msg += fmt.Sprintf(":%d", f.Line)
			}
			msg += ")"
		}
		cmd.PrintErrln(msg)
	}

	if len(r.Findings) == 0 {
		cmd.PrintErrln("  No findings.")
	}

	cmd.PrintErrln()
	cmd.PrintErrf("Security Score: %d/100 (unprotected)\n", r.Score)
	cmd.PrintErrf("  With suggested config: %d/100\n", r.ScoreWith)
	cmd.PrintErrf("  Criticals: %d  Warnings: %d  Info: %d\n", criticals, warnings, infos)
}

func joinMax(items []string, limit int) string {
	if len(items) <= limit {
		return join(items)
	}
	return join(items[:limit]) + fmt.Sprintf(" (+%d more)", len(items)-limit)
}

func join(items []string) string {
	result := ""
	for i, item := range items {
		if i > 0 {
			result += ", "
		}
		result += item
	}
	return result
}
