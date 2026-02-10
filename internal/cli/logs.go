package cli

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

func logsCmd() *cobra.Command {
	var logFile string
	var last int
	var filter string
	var follow bool

	cmd := &cobra.Command{
		Use:   "logs",
		Short: "View Pipelock audit logs",
		Long: `View, filter, and tail audit log entries.

Examples:
  pipelock logs --file pipelock-audit.log
  pipelock logs --file pipelock-audit.log --last 20
  pipelock logs --file pipelock-audit.log --filter blocked
  pipelock logs --file pipelock-audit.log -f`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if logFile == "" {
				return errLogFileRequired
			}

			f, err := os.Open(logFile) //nolint:gosec // G304: path from user flag
			if err != nil {
				return fmt.Errorf("opening log file: %w", err)
			}
			defer f.Close() //nolint:errcheck // read-only file

			var lines []string
			sc := bufio.NewScanner(f)
			for sc.Scan() {
				line := sc.Text()
				if filter != "" && !matchFilter(line, filter) {
					continue
				}
				lines = append(lines, line)
			}
			if err := sc.Err(); err != nil {
				return fmt.Errorf("reading log file: %w", err)
			}

			// Apply --last N
			if last > 0 && len(lines) > last {
				lines = lines[len(lines)-last:]
			}

			for _, line := range lines {
				cmd.Println(line)
			}

			if follow {
				cmd.PrintErrln("--- following (Ctrl+C to stop) ---")
				reader := bufio.NewReader(f)
				for {
					select {
					case <-cmd.Context().Done():
						return nil
					default:
					}
					line, err := reader.ReadString('\n')
					if err != nil {
						if err == io.EOF {
							time.Sleep(250 * time.Millisecond)
							continue
						}
						return err
					}
					line = strings.TrimRight(line, "\n")
					if filter != "" && !matchFilter(line, filter) {
						continue
					}
					cmd.Println(line)
				}
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&logFile, "file", "", "audit log file path")
	cmd.Flags().IntVarP(&last, "last", "n", 0, "show only the last N entries")
	cmd.Flags().StringVar(&filter, "filter", "", "filter by event type (allowed, blocked, error, anomaly)")
	cmd.Flags().BoolVarP(&follow, "follow", "f", false, "follow the log file for new entries")

	return cmd
}

var errLogFileRequired = errors.New("--file is required (specify the audit log file path)")

// matchFilter checks if a JSON log line matches the event type filter.
func matchFilter(line, filter string) bool {
	var entry map[string]any
	if err := json.Unmarshal([]byte(line), &entry); err != nil {
		// If it's not JSON, do a simple string match
		return strings.Contains(line, filter)
	}
	if event, ok := entry["event"].(string); ok {
		return event == filter
	}
	return false
}
