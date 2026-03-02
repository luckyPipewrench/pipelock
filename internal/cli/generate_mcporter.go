package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"time"

	"github.com/spf13/cobra"
)

func generateMcporterCmd() *cobra.Command {
	var inputFile, outputFile, pipelockBin, configPath string
	var inPlace, backup bool

	cmd := &cobra.Command{
		Use:   "mcporter",
		Short: "Wrap MCP servers with pipelock scanning",
		Long: `Read a JSON file with a top-level "mcpServers" object and wrap each
server entry with pipelock's MCP proxy for bidirectional scanning.

The input must be a JSON object like: {"mcpServers": {"name": {...}, ...}}.
Any file matching this shape works. Other keys are preserved as-is.

Servers already wrapped with pipelock are detected and skipped.
Environment variables from server entries are converted to --env flags.
HTTP/WS upstream URLs use --upstream instead of -- subprocess mode.

The output is idempotent: running the command twice produces identical results.

Examples:
  pipelock generate mcporter -i servers.json
  pipelock generate mcporter -i servers.json -o wrapped.json
  pipelock generate mcporter -i servers.json --in-place --backup`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if inPlace && outputFile != "" {
				return fmt.Errorf("--in-place and --output are mutually exclusive")
			}

			data, err := os.ReadFile(inputFile) //nolint:gosec // user-provided input file
			if err != nil {
				return fmt.Errorf("reading input: %w", err)
			}

			var raw map[string]json.RawMessage
			if err := json.Unmarshal(data, &raw); err != nil {
				return fmt.Errorf("parsing JSON: %w", err)
			}

			serversRaw, ok := raw["mcpServers"]
			if !ok {
				return fmt.Errorf("no top-level \"mcpServers\" key in %s; expected {\"mcpServers\": {\"name\": {...}, ...}}", inputFile)
			}

			var servers map[string]json.RawMessage
			if err := json.Unmarshal(serversRaw, &servers); err != nil {
				return fmt.Errorf("parsing mcpServers: %w", err)
			}

			wrapped := make(map[string]interface{}, len(servers))
			for name, sRaw := range servers {
				entry, wrapErr := wrapServerEntry(sRaw, pipelockBin, configPath)
				if wrapErr != nil {
					return fmt.Errorf("server %q: %w", name, wrapErr)
				}
				if entry.skipped {
					_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "pipelock: %s: already wrapped, skipping\n", name)
				}
				wrapped[name] = entry.value
			}

			// Rebuild full document preserving non-mcpServers keys.
			output := make(map[string]interface{})
			for k, v := range raw {
				if k == "mcpServers" {
					continue
				}
				var parsed interface{}
				if err := json.Unmarshal(v, &parsed); err != nil {
					return fmt.Errorf("preserving key %q: %w", k, err)
				}
				output[k] = parsed
			}
			output["mcpServers"] = wrapped

			result, err := json.MarshalIndent(output, "", "  ")
			if err != nil {
				return fmt.Errorf("marshaling output: %w", err)
			}
			result = append(result, '\n')

			if inPlace {
				return atomicWriteFile(inputFile, result, backup)
			}

			if outputFile != "" {
				if err := os.WriteFile(outputFile, result, 0o600); err != nil {
					return fmt.Errorf("writing output: %w", err)
				}
				_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "Wrapped config written to %s\n", outputFile)
				return nil
			}

			_, err = cmd.OutOrStdout().Write(result)
			return err
		},
	}

	cmd.Flags().StringVarP(&inputFile, "input", "i", "", "input file path (required)")
	_ = cmd.MarkFlagRequired("input")
	cmd.Flags().StringVarP(&outputFile, "output", "o", "", "output file path (default: stdout)")
	cmd.Flags().BoolVar(&inPlace, "in-place", false, "modify input file in-place (atomic write)")
	cmd.Flags().BoolVar(&backup, "backup", false, "create .bak before in-place modification")
	cmd.Flags().StringVar(&pipelockBin, "pipelock-bin", "pipelock", "path to pipelock binary in output")
	cmd.Flags().StringVarP(&configPath, "config", "c", "pipelock.yaml", "path to pipelock config in output")
	return cmd
}

type wrappedEntry struct {
	value   interface{}
	skipped bool
}

func wrapServerEntry(raw json.RawMessage, pipelockBin, configPath string) (wrappedEntry, error) {
	var entry map[string]interface{}
	if err := json.Unmarshal(raw, &entry); err != nil {
		return wrappedEntry{}, fmt.Errorf("parsing server entry: %w", err)
	}

	// URL-based server (HTTP/WS upstream).
	if urlVal, ok := entry["url"]; ok {
		urlStr, isStr := urlVal.(string)
		if !isStr {
			return wrappedEntry{}, fmt.Errorf("\"url\" field must be a string, got %T", urlVal)
		}
		// Check if already wrapped (url entries don't have command).
		if _, hasCmd := entry["command"]; hasCmd {
			cmdStr, _ := entry["command"].(string)
			argsRaw, _ := entry["args"].([]interface{})
			args, argsErr := toStringSlice(argsRaw)
			if argsErr != nil {
				return wrappedEntry{}, fmt.Errorf("url server args: %w", argsErr)
			}
			if isAlreadyWrapped(cmdStr, args) {
				return wrappedEntry{value: entry, skipped: true}, nil
			}
		}
		envMap, _ := entry["env"].(map[string]interface{})
		result := wrapUpstreamEntry(urlStr, envMap, pipelockBin, configPath)
		copyExtraFields(result, entry, "command", "args", "env", "url")
		return wrappedEntry{value: result}, nil
	}

	// Command-based server (stdio subprocess).
	cmdVal, hasCmd := entry["command"]
	if !hasCmd {
		return wrappedEntry{value: entry}, nil
	}
	cmdStr, isStr := cmdVal.(string)
	if !isStr {
		return wrappedEntry{}, fmt.Errorf("\"command\" field must be a string, got %T", cmdVal)
	}

	argsRaw, _ := entry["args"].([]interface{})
	args, argsErr := toStringSlice(argsRaw)
	if argsErr != nil {
		return wrappedEntry{}, fmt.Errorf("args: %w", argsErr)
	}

	if isAlreadyWrapped(cmdStr, args) {
		return wrappedEntry{value: entry, skipped: true}, nil
	}

	envMap, _ := entry["env"].(map[string]interface{})
	result := wrapStdioEntry(cmdStr, args, envMap, pipelockBin, configPath)
	copyExtraFields(result, entry, "command", "args", "env")
	return wrappedEntry{value: result}, nil
}

func wrapStdioEntry(command string, args []string, envMap map[string]interface{}, pipelockBin, configPath string) map[string]interface{} {
	wrappedArgs := []string{"mcp", "proxy", "--config", configPath}

	// Add --env flags for each environment variable in sorted order
	// for deterministic output (Go map iteration is non-deterministic).
	// Skip keys that look like flags to prevent argument injection
	// (e.g., env key "--config" would inject a second --config flag).
	envKeys := make([]string, 0, len(envMap))
	for key := range envMap {
		envKeys = append(envKeys, key)
	}
	sort.Strings(envKeys)
	for _, key := range envKeys {
		if len(key) == 0 || key[0] == '-' {
			continue
		}
		wrappedArgs = append(wrappedArgs, "--env", key)
	}

	// Separator and original command.
	wrappedArgs = append(wrappedArgs, "--")
	wrappedArgs = append(wrappedArgs, command)
	wrappedArgs = append(wrappedArgs, args...)

	result := map[string]interface{}{
		"command": pipelockBin,
		"args":    wrappedArgs,
	}

	// Preserve env block (pipelock uses --env to pass through, but the
	// client still needs to provide the values).
	if len(envMap) > 0 {
		result["env"] = envMap
	}

	return result
}

func wrapUpstreamEntry(url string, envMap map[string]interface{}, pipelockBin, configPath string) map[string]interface{} {
	args := []string{"mcp", "proxy", "--config", configPath}

	// Add --env flags in sorted order for deterministic output.
	envKeys := make([]string, 0, len(envMap))
	for key := range envMap {
		envKeys = append(envKeys, key)
	}
	sort.Strings(envKeys)
	for _, key := range envKeys {
		if len(key) == 0 || key[0] == '-' {
			continue
		}
		args = append(args, "--env", key)
	}

	args = append(args, "--upstream", url)

	result := map[string]interface{}{
		"command": pipelockBin,
		"args":    args,
	}
	if len(envMap) > 0 {
		result["env"] = envMap
	}
	return result
}

// copyExtraFields copies fields from src to dst that aren't in the managed set.
// This preserves per-server fields like metadata, disabled, and alwaysAllow
// that clients (e.g. Claude Code) set on server entries.
func copyExtraFields(dst, src map[string]interface{}, managed ...string) {
	skip := make(map[string]bool, len(managed))
	for _, k := range managed {
		skip[k] = true
	}
	for k, v := range src {
		if skip[k] {
			continue
		}
		dst[k] = v
	}
}

const (
	mcporterBinaryName = "pipelock"
	mcporterSubMCP     = "mcp"
	mcporterSubProxy   = "proxy"
)

func isAlreadyWrapped(command string, args []string) bool {
	if filepath.Base(command) != mcporterBinaryName {
		return false
	}
	foundMCP := false
	for _, a := range args {
		if a == "--" {
			break
		}
		if !foundMCP && a == mcporterSubMCP {
			foundMCP = true
			continue
		}
		if foundMCP && a == mcporterSubProxy {
			return true
		}
	}
	return false
}

func toStringSlice(raw []interface{}) ([]string, error) {
	if raw == nil {
		return nil, nil
	}
	result := make([]string, 0, len(raw))
	for i, v := range raw {
		s, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("args[%d]: expected string, got %T", i, v)
		}
		result = append(result, s)
	}
	return result, nil
}

func atomicWriteFile(path string, data []byte, doBackup bool) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stat %s: %w", path, err)
	}

	if doBackup {
		bakData, readErr := os.ReadFile(path) //nolint:gosec // user-provided path
		if readErr != nil {
			return fmt.Errorf("reading original for backup: %w", readErr)
		}
		if writeErr := os.WriteFile(path+".bak", bakData, info.Mode()); writeErr != nil {
			return fmt.Errorf("creating backup: %w", writeErr)
		}
	}

	tmpFile := path + ".tmp." + strconv.FormatInt(time.Now().UnixNano(), 36)
	if err := os.WriteFile(tmpFile, data, info.Mode()); err != nil {
		return fmt.Errorf("writing temp file: %w", err)
	}
	if err := os.Rename(tmpFile, path); err != nil {
		_ = os.Remove(tmpFile)
		return fmt.Errorf("atomic rename: %w", err)
	}
	return nil
}
