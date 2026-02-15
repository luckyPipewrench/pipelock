package cli

import (
	"errors"
	"fmt"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/hitl"
	"github.com/luckyPipewrench/pipelock/internal/mcp"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// ErrInjectionDetected is returned when pipelock mcp scan detects prompt injection.
var ErrInjectionDetected = errors.New("prompt injection detected")

func mcpCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "mcp",
		Short: "MCP (Model Context Protocol) security scanning",
		Long: `Scan MCP JSON-RPC 2.0 responses for prompt injection before they reach the agent.

Examples:
  mcp-server | pipelock mcp scan
  mcp-server | pipelock mcp scan --json --config pipelock.yaml`,
	}

	cmd.AddCommand(mcpScanCmd())
	cmd.AddCommand(mcpProxyCmd())
	return cmd
}

func mcpScanCmd() *cobra.Command {
	var configFile string
	var jsonOutput bool

	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Scan MCP responses from stdin for prompt injection",
		Long: `Reads newline-delimited MCP JSON-RPC 2.0 responses from stdin and scans
text content blocks for prompt injection patterns.

Exit code 0 if all responses are clean, 1 if any injection is detected.
In text mode, only findings are printed. In JSON mode, every line produces a verdict.

Examples:
  mcp-server | pipelock mcp scan
  pipelock mcp scan --json --config pipelock.yaml < responses.jsonl`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := loadConfigOrDefault(configFile)
			if err != nil {
				return err
			}

			// Ensure response scanning is enabled — that's the command's purpose.
			if !cfg.ResponseScanning.Enabled {
				_, _ = fmt.Fprintln(cmd.ErrOrStderr(), "warning: response scanning was disabled in config, enabling with defaults")
				cfg.ResponseScanning = config.Defaults().ResponseScanning
			}

			sc := scanner.New(cfg)
			defer sc.Close()

			found, err := mcp.ScanStream(cmd.InOrStdin(), cmd.OutOrStdout(), sc, jsonOutput)
			if err != nil {
				return err
			}
			if found {
				return ErrInjectionDetected
			}

			return nil
		},
	}

	cmd.Flags().StringVarP(&configFile, "config", "c", "", "config file path")
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "output results as JSON (one object per line)")
	return cmd
}

func mcpProxyCmd() *cobra.Command {
	var configFile string

	cmd := &cobra.Command{
		Use:   "proxy [flags] -- COMMAND [ARGS...]",
		Short: "Proxy an MCP server, scanning responses for prompt injection",
		Long: `Launches an MCP server subprocess and proxies its stdio transport with
bidirectional scanning:

  - Responses (server→client) are scanned for prompt injection before forwarding.
  - Requests (client→server) are scanned for DLP leaks and injection in tool arguments.

Response action is controlled by response_scanning.action (warn/block/strip/ask).
Request action is controlled by mcp_input_scanning.action (warn/block).

Input scanning is auto-enabled unless explicitly configured in your config file.
Use this as a drop-in wrapper in your MCP client configuration.

Examples:
  pipelock mcp proxy -- npx @modelcontextprotocol/server-filesystem /tmp
  pipelock mcp proxy --config pipelock.yaml -- python my_server.py

Claude Desktop config:
  {
    "mcpServers": {
      "filesystem": {
        "command": "pipelock",
        "args": ["mcp", "proxy", "--", "npx", "-y", "@modelcontextprotocol/server-filesystem", "/tmp"]
      }
    }
  }`,
		RunE: func(cmd *cobra.Command, args []string) error {
			dashIdx := cmd.ArgsLenAtDash()
			if dashIdx < 0 || dashIdx >= len(args) {
				return errors.New("no MCP server command specified (use -- to separate)")
			}
			serverCmd := args[dashIdx:]

			cfg, err := loadConfigOrDefault(configFile)
			if err != nil {
				return err
			}

			if !cfg.ResponseScanning.Enabled {
				_, _ = fmt.Fprintln(cmd.ErrOrStderr(), "warning: response scanning was disabled in config, enabling with defaults")
				cfg.ResponseScanning = config.Defaults().ResponseScanning
			}

			// Auto-enable MCP input scanning for proxy mode unless the user explicitly
			// configured the section. Action is only set by ApplyDefaults when Enabled
			// is true, so Action=="" with Enabled=false means unconfigured. OnParseError
			// is always defaulted by ApplyDefaults, so we don't check it here.
			if !cfg.MCPInputScanning.Enabled && cfg.MCPInputScanning.Action == "" {
				_, _ = fmt.Fprintln(cmd.ErrOrStderr(), "pipelock: auto-enabling MCP input scanning for proxy mode")
				cfg.MCPInputScanning.Enabled = true
				cfg.MCPInputScanning.Action = "warn" //nolint:goconst // config action value
			}

			sc := scanner.New(cfg)
			defer sc.Close()

			var approver *hitl.Approver
			if sc.ResponseAction() == "ask" {
				approver = hitl.New(cfg.ResponseScanning.AskTimeoutSeconds)
				defer approver.Close()
			}

			inputCfg := &mcp.InputScanConfig{
				Enabled:      cfg.MCPInputScanning.Enabled,
				Action:       cfg.MCPInputScanning.Action,
				OnParseError: cfg.MCPInputScanning.OnParseError,
			}

			// Auto-enable MCP tool scanning for proxy mode unless explicitly configured.
			if !cfg.MCPToolScanning.Enabled && cfg.MCPToolScanning.Action == "" {
				_, _ = fmt.Fprintln(cmd.ErrOrStderr(), "pipelock: auto-enabling MCP tool scanning for proxy mode")
				cfg.MCPToolScanning.Enabled = true
				cfg.MCPToolScanning.Action = "warn" //nolint:goconst // config action value
				cfg.MCPToolScanning.DetectDrift = true
			}

			var toolCfg *mcp.ToolScanConfig
			if cfg.MCPToolScanning.Enabled {
				toolCfg = &mcp.ToolScanConfig{
					Action:      cfg.MCPToolScanning.Action,
					DetectDrift: cfg.MCPToolScanning.DetectDrift,
				}
			}

			_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "pipelock: proxying MCP server %v (response=%s, input=%s, tools=%s)\n",
				serverCmd, sc.ResponseAction(), inputCfg.Action, cfg.MCPToolScanning.Action)

			ctx, cancel := signal.NotifyContext(
				cmd.Context(),
				syscall.SIGINT,
				syscall.SIGTERM,
			)
			defer cancel()

			return mcp.RunProxy(ctx, cmd.InOrStdin(), cmd.OutOrStdout(), cmd.ErrOrStderr(), serverCmd, sc, approver, inputCfg, toolCfg)
		},
	}

	cmd.Flags().StringVarP(&configFile, "config", "c", "", "config file path")
	return cmd
}
