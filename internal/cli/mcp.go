package cli

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/signal"
	"strings"
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
	var upstreamURL string
	var envVars []string

	cmd := &cobra.Command{
		Use:   "proxy [flags] [-- COMMAND [ARGS...]]",
		Short: "Proxy an MCP server, scanning responses for prompt injection",
		Long: `Launches an MCP server subprocess and proxies its stdio transport with
bidirectional scanning:

  - Responses (server→client) are scanned for prompt injection before forwarding.
  - Requests (client→server) are scanned for DLP leaks and injection in tool arguments.

Response action is controlled by response_scanning.action (warn/block/strip/ask).
Request action is controlled by mcp_input_scanning.action (warn/block).

Input scanning is auto-enabled unless explicitly configured in your config file.
Use this as a drop-in wrapper in your MCP client configuration.

Subprocess (stdio) mode:
  pipelock mcp proxy -- npx @modelcontextprotocol/server-filesystem /tmp
  pipelock mcp proxy --config pipelock.yaml -- python my_server.py

HTTP transport mode:
  pipelock mcp proxy --upstream http://localhost:8080/mcp
  pipelock mcp proxy --upstream https://mcp.example.com/v1 --config pipelock.yaml

Claude Desktop config (local subprocess):
  {
    "mcpServers": {
      "filesystem": {
        "command": "pipelock",
        "args": ["mcp", "proxy", "--", "npx", "-y", "@modelcontextprotocol/server-filesystem", "/tmp"]
      }
    }
  }

Claude Desktop config (remote server):
  {
    "mcpServers": {
      "remote": {
        "command": "pipelock",
        "args": ["mcp", "proxy", "--upstream", "http://host.docker.internal:8080/mcp"]
      }
    }
  }

Environment passthrough (subprocess mode only):
  pipelock mcp proxy --env BRAIN_DIR --env API_URL=http://localhost:8081 -- node server.js

  By default, pipelock strips the child process environment to prevent secret leakage.
  Use --env KEY to pass through a variable from the current environment, or
  --env KEY=VALUE to set it explicitly.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			dashIdx := cmd.ArgsLenAtDash()
			hasSubprocess := dashIdx >= 0 && dashIdx < len(args)
			hasUpstream := upstreamURL != ""

			// Mutual exclusion validation.
			if hasUpstream && hasSubprocess {
				return errors.New("--upstream and subprocess command (--) are mutually exclusive")
			}
			if !hasUpstream && !hasSubprocess {
				return errors.New("specify --upstream URL or -- COMMAND [ARGS...]")
			}

			// Validate upstream URL scheme.
			if hasUpstream {
				u, err := url.Parse(upstreamURL)
				if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
					return fmt.Errorf("invalid upstream URL %q: must be http:// or https:// with a host", upstreamURL)
				}
			}

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
			if sc.ResponseAction() == config.ActionAsk {
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

			// Auto-enable MCP tool call policy for proxy mode unless explicitly configured.
			// Action=="" with Enabled=false and no rules means unconfigured.
			if !cfg.MCPToolPolicy.Enabled && cfg.MCPToolPolicy.Action == "" && len(cfg.MCPToolPolicy.Rules) == 0 {
				_, _ = fmt.Fprintln(cmd.ErrOrStderr(), "pipelock: auto-enabling MCP tool call policy for proxy mode")
				cfg.MCPToolPolicy.Enabled = true
				cfg.MCPToolPolicy.Action = "warn" //nolint:goconst // config action value
				cfg.MCPToolPolicy.Rules = mcp.DefaultToolPolicyRules()
			}

			var policyCfg *mcp.PolicyConfig
			if cfg.MCPToolPolicy.Enabled {
				policyCfg = mcp.NewPolicyConfig(cfg.MCPToolPolicy)
			}

			toolAction := "disabled"
			if toolCfg != nil {
				toolAction = toolCfg.Action
			}
			policyAction := "disabled"
			if policyCfg != nil {
				policyAction = policyCfg.Action
			}
			if hasUpstream {
				if len(envVars) > 0 {
					_, _ = fmt.Fprintln(cmd.ErrOrStderr(), "warning: --env is ignored in HTTP transport mode (no child process)")
				}
				_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "pipelock: proxying upstream %s (response=%s, input=%s, tools=%s, policy=%s)\n",
					upstreamURL, sc.ResponseAction(), inputCfg.Action, toolAction, policyAction)

				ctx, cancel := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM)
				defer cancel()

				return mcp.RunHTTPProxy(ctx, cmd.InOrStdin(), cmd.OutOrStdout(), cmd.ErrOrStderr(), upstreamURL, sc, approver, nil, inputCfg, toolCfg, policyCfg)
			}

			// Parse --env flags into KEY=VALUE pairs for the child process.
			// KEY without value: pass through from current environment.
			// KEY=VALUE: set explicitly.
			// Empty keys, safe-list keys, and dangerous keys are rejected.
			var extraEnv []string
			for _, e := range envVars {
				key, _, hasValue := strings.Cut(e, "=")
				if key == "" {
					return errors.New("--env requires a non-empty variable name")
				}
				if mcp.IsSafeEnvKey(key) {
					return fmt.Errorf("--env %s is already set by pipelock and cannot be overridden", key)
				}
				if mcp.IsDangerousEnvKey(key) {
					return fmt.Errorf("--env %s is blocked: this variable can inject code or redirect traffic in the child process", key)
				}
				if hasValue {
					extraEnv = append(extraEnv, e)
				} else if val, found := os.LookupEnv(e); found {
					extraEnv = append(extraEnv, e+"="+val)
				}
			}
			if len(extraEnv) > 0 {
				keys := make([]string, 0, len(extraEnv))
				for _, e := range extraEnv {
					k, _, _ := strings.Cut(e, "=")
					keys = append(keys, k)
				}
				_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "pipelock: passing %d env var(s) to child process: %s\n",
					len(keys), strings.Join(keys, ", "))
			}

			// Subprocess mode.
			serverCmd := args[dashIdx:]
			_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "pipelock: proxying MCP server %v (response=%s, input=%s, tools=%s, policy=%s)\n",
				serverCmd, sc.ResponseAction(), inputCfg.Action, toolAction, policyAction)

			ctx, cancel := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM)
			defer cancel()

			return mcp.RunProxy(ctx, cmd.InOrStdin(), cmd.OutOrStdout(), cmd.ErrOrStderr(), serverCmd, sc, approver, inputCfg, toolCfg, policyCfg, extraEnv...)
		},
	}

	cmd.Flags().StringVarP(&configFile, "config", "c", "", "config file path")
	cmd.Flags().StringVar(&upstreamURL, "upstream", "", "upstream MCP server URL (Streamable HTTP transport)")
	cmd.Flags().StringArrayVar(&envVars, "env", nil, "pass environment variable to child process (KEY or KEY=VALUE, repeatable)")
	return cmd
}
