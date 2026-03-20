// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/edition"
	"github.com/luckyPipewrench/pipelock/internal/filesentry"
	"github.com/luckyPipewrench/pipelock/internal/hitl"
	"github.com/luckyPipewrench/pipelock/internal/killswitch"
	"github.com/luckyPipewrench/pipelock/internal/mcp"
	"github.com/luckyPipewrench/pipelock/internal/mcp/chains"
	"github.com/luckyPipewrench/pipelock/internal/mcp/policy"
	"github.com/luckyPipewrench/pipelock/internal/mcp/tools"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/proxy"
	"github.com/luckyPipewrench/pipelock/internal/rules"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
	plsentry "github.com/luckyPipewrench/pipelock/internal/sentry"
	session "github.com/luckyPipewrench/pipelock/internal/session"
)

// ErrInjectionDetected is returned when pipelock mcp scan detects prompt injection.
var ErrInjectionDetected = errors.New("prompt injection detected")

// safeWriter wraps an io.Writer with a mutex for concurrent use.
// Used to synchronize file sentry goroutines and RunProxy stderr output.
type safeWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (sw *safeWriter) Write(p []byte) (int, error) {
	sw.mu.Lock()
	defer sw.mu.Unlock()
	return sw.w.Write(p)
}

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

			bundleResult := rules.MergeIntoConfig(cfg, Version)
			for _, e := range bundleResult.Errors {
				_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "pipelock: warning: bundle %s: %s\n", e.Name, e.Reason)
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
	var listenAddr string
	var envVars []string
	var agentName string

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

HTTP transport mode (stdio client, HTTP upstream):
  pipelock mcp proxy --upstream http://localhost:8080/mcp
  pipelock mcp proxy --upstream https://mcp.example.com/v1 --config pipelock.yaml

HTTP reverse proxy mode (HTTP listener, HTTP upstream):
  pipelock mcp proxy --listen 0.0.0.0:8889 --upstream http://localhost:3000/mcp
  pipelock mcp proxy --listen :8889 --upstream http://web:3000/mcp --config pipelock.yaml

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
			hasListen := listenAddr != ""

			// Mutual exclusion validation.
			if hasUpstream && hasSubprocess {
				return errors.New("--upstream and subprocess command (--) are mutually exclusive")
			}
			if hasListen && hasSubprocess {
				return errors.New("--listen and subprocess command (--) are mutually exclusive")
			}
			if hasListen && !hasUpstream {
				return errors.New("--listen requires --upstream")
			}
			if !hasUpstream && !hasSubprocess {
				return errors.New("specify --upstream URL or -- COMMAND [ARGS...]")
			}

			// Validate upstream URL scheme.
			var isWSUpstream bool
			if hasUpstream {
				u, err := url.Parse(upstreamURL)
				if err != nil || u.Host == "" {
					return fmt.Errorf("invalid upstream URL %q: must include a scheme and host", upstreamURL)
				}
				switch u.Scheme {
				case "http", schemeHTTPS:
					// HTTP transport.
				case "ws", "wss":
					isWSUpstream = true
				default:
					return fmt.Errorf("invalid upstream URL %q: scheme must be http, https, ws, or wss", upstreamURL)
				}
			}

			cfg, err := loadConfigOrDefault(configFile)
			if err != nil {
				return err
			}

			// Build edition so _default fallback works the same as HTTP proxy.
			// Bootstrap scanner is used only for edition init; closed before
			// rebuilding with the resolved config.
			bootSC := scanner.New(cfg)
			ed, edErr := edition.NewEditionFunc(cfg, bootSC)
			if edErr != nil {
				bootSC.Close()
				return fmt.Errorf("edition init: %w", edErr)
			}
			defer ed.Close()

			// Resolve agent: known name -> that profile, unknown -> error, empty -> _default.
			resolved, found := ed.LookupProfile(agentName)
			if agentName != "" && !found {
				// Distinguish truly unknown from known-but-expired.
				if known := ed.KnownProfiles(); known[agentName] {
					_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "WARNING: agent profile %q exists but license has expired; using default profile\n", agentName)
				} else {
					bootSC.Close()
					return fmt.Errorf("unknown agent profile %q", agentName)
				}
			}
			cfg = resolved.Config
			bootSC.Close() // done with bootstrap scanner

			// Set up Sentry error reporting
			sentryClient, sentryErr := plsentry.Init(cfg, Version)
			if sentryErr != nil {
				_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "warning: sentry init failed: %v\n", sentryErr)
			}
			if sentryClient != nil {
				defer sentryClient.Close()
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
				cfg.MCPInputScanning.Action = config.ActionBlock
			}

			// Merge community rule bundles before building the scanner.
			bundleResult := rules.MergeIntoConfig(cfg, Version)
			for _, e := range bundleResult.Errors {
				_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "pipelock: warning: bundle %s: %s\n", e.Name, e.Reason)
			}
			extraPoison := rules.ConvertToolPoison(bundleResult.ToolPoison)

			// Rebuild scanner with the (possibly modified) resolved config.
			sc := scanner.New(cfg)
			defer sc.Close()

			ks := killswitch.New(cfg)

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
				cfg.MCPToolScanning.Action = config.ActionWarn
				cfg.MCPToolScanning.DetectDrift = true
			}

			var toolCfg *tools.ToolScanConfig
			if cfg.MCPToolScanning.Enabled {
				toolCfg = &tools.ToolScanConfig{
					Action:      cfg.MCPToolScanning.Action,
					DetectDrift: cfg.MCPToolScanning.DetectDrift,
					ExtraPoison: extraPoison,
				}
				// Wire session binding into tool scanning when enabled.
				if cfg.MCPSessionBinding.Enabled {
					toolCfg.BindingUnknownAction = cfg.MCPSessionBinding.UnknownToolAction
					toolCfg.BindingNoBaselineAction = cfg.MCPSessionBinding.NoBaselineAction
				}
			}

			// Auto-enable MCP tool call policy for proxy mode unless explicitly configured.
			// Action=="" with Enabled=false and no rules means unconfigured.
			if !cfg.MCPToolPolicy.Enabled && cfg.MCPToolPolicy.Action == "" && len(cfg.MCPToolPolicy.Rules) == 0 {
				_, _ = fmt.Fprintln(cmd.ErrOrStderr(), "pipelock: auto-enabling MCP tool call policy for proxy mode")
				cfg.MCPToolPolicy.Enabled = true
				cfg.MCPToolPolicy.Action = config.ActionWarn
				cfg.MCPToolPolicy.Rules = policy.DefaultToolPolicyRules()
			}

			var policyCfg *policy.Config
			if cfg.MCPToolPolicy.Enabled {
				policyCfg = policy.New(cfg.MCPToolPolicy)
			}

			// Initialize chain matcher if tool chain detection is configured.
			var chainMatcher *chains.Matcher
			if cfg.ToolChainDetection.Enabled {
				chainMatcher = chains.New(&cfg.ToolChainDetection)
			}

			// Build CEE deps when cross-request detection is enabled.
			var cee *mcp.CEEDeps
			if cfg.CrossRequestDetection.Enabled {
				m := metrics.New()
				ceeCfg := cfg.CrossRequestDetection
				cee = &mcp.CEEDeps{Config: &ceeCfg, Metrics: m}
				if ceeCfg.EntropyBudget.Enabled {
					cee.Tracker = scanner.NewEntropyTracker(
						ceeCfg.EntropyBudget.BitsPerWindow,
						ceeCfg.EntropyBudget.WindowMinutes*60, // minutes to seconds
					)
				}
				if ceeCfg.FragmentReassembly.Enabled {
					cee.Buffer = scanner.NewFragmentBuffer(
						ceeCfg.FragmentReassembly.MaxBufferBytes,
						10000, // 10K max sessions, matching proxy constant
						ceeCfg.FragmentReassembly.WindowMinutes*60,
					)
				}
			}

			// Create session manager for adaptive enforcement in MCP proxy mode.
			// Uses a dedicated metrics instance for MCP; reuses the same session
			// profiling config as the HTTP proxy. store and adaptiveCfg are nil-safe
			// downstream when session profiling is disabled.
			var store session.Store
			var adaptiveCfg *config.AdaptiveEnforcement
			var mcpMetrics *metrics.Metrics
			if cfg.SessionProfiling.Enabled {
				mcpMetrics = metrics.New()
				sm := proxy.NewSessionManager(&cfg.SessionProfiling, mcpMetrics)
				defer sm.Close()
				store = sm.AsStore()
			}
			if cfg.AdaptiveEnforcement.Enabled {
				adaptiveCfg = &cfg.AdaptiveEnforcement
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

				ctx, cancel := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM)
				defer cancel()

				// HTTP reverse proxy mode: --listen + --upstream.
				if hasListen && isWSUpstream {
					err := fmt.Errorf("--listen with WebSocket upstream (ws/wss) is not yet supported; use stdio mode: pipelock mcp proxy --upstream %s", upstreamURL)
					if sentryClient != nil {
						sentryClient.CaptureError(err)
					}
					return err
				}
				if hasListen {
					mcpLn, lnErr := (&net.ListenConfig{}).Listen(ctx, "tcp", listenAddr)
					if lnErr != nil {
						err := fmt.Errorf("MCP listener bind %s: %w", listenAddr, lnErr)
						if sentryClient != nil {
							sentryClient.CaptureError(err)
						}
						return err
					}
					_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "pipelock: MCP reverse proxy %s -> %s (response=%s, input=%s, tools=%s, policy=%s)\n",
						listenAddr, upstreamURL, sc.ResponseAction(), inputCfg.Action, toolAction, policyAction)
					// Wrap static adaptiveCfg in a function to satisfy the
					// AdaptiveConfigFunc signature. Short-lived: no hot-reload concern.
					adaptiveFn := mcp.AdaptiveConfigFunc(func() *config.AdaptiveEnforcement {
						return adaptiveCfg
					})
					if err := mcp.RunHTTPListenerProxy(ctx, mcpLn, upstreamURL, cmd.ErrOrStderr(), sc, approver, inputCfg, toolCfg, policyCfg, ks, chainMatcher, nil, cee, store, adaptiveFn, mcpMetrics); err != nil {
						if sentryClient != nil {
							sentryClient.CaptureError(err)
						}
						return err
					}
					return nil
				}

				// Stdio-to-WebSocket mode: --upstream ws:// or wss://.
				if isWSUpstream {
					_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "pipelock: proxying WS upstream %s (response=%s, input=%s, tools=%s, policy=%s)\n",
						upstreamURL, sc.ResponseAction(), inputCfg.Action, toolAction, policyAction)
					if err := mcp.RunWSProxy(ctx, cmd.InOrStdin(), cmd.OutOrStdout(), cmd.ErrOrStderr(), upstreamURL, sc, approver, inputCfg, toolCfg, policyCfg, ks, chainMatcher, nil, cee, store, adaptiveCfg, mcpMetrics); err != nil {
						if sentryClient != nil {
							sentryClient.CaptureError(err)
						}
						return err
					}
					return nil
				}

				// Stdio-to-HTTP mode: --upstream only.
				_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "pipelock: proxying upstream %s (response=%s, input=%s, tools=%s, policy=%s)\n",
					upstreamURL, sc.ResponseAction(), inputCfg.Action, toolAction, policyAction)
				if err := mcp.RunHTTPProxy(ctx, cmd.InOrStdin(), cmd.OutOrStdout(), cmd.ErrOrStderr(), upstreamURL, sc, approver, nil, inputCfg, toolCfg, policyCfg, ks, chainMatcher, nil, cee, store, adaptiveCfg, mcpMetrics); err != nil {
					if sentryClient != nil {
						sentryClient.CaptureError(err)
					}
					return err
				}
				return nil
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

			// Wrap stderr in a mutex so file sentry goroutines and RunProxy
			// (which wraps logW in its own syncWriter) don't interleave.
			logW := &safeWriter{w: cmd.ErrOrStderr()}

			// File sentry: watch agent working directories for secret writes.
			// Watches are installed synchronously (Arm) before the child starts
			// to prevent early writes from being missed.
			var lin filesentry.Lineage
			var onChildReady func()
			if cfg.FileSentry.Enabled {
				lin = filesentry.NewLineage()
				// Error handler for non-fatal runtime errors (e.g. failing to watch new dirs).
				onErr := func(err error) {
					_, _ = fmt.Fprintf(logW, "pipelock: [file_sentry] %v\n", err)
				}
				watcher, watchErr := filesentry.NewWatcher(&cfg.FileSentry, sc, lin, onErr)
				if watchErr != nil {
					return fmt.Errorf("file sentry init failed (feature is enabled): %w", watchErr)
				}
				defer func() { _ = watcher.Close() }()

				// Arm synchronously before child launch.
				if armErr := watcher.Arm(); armErr != nil {
					return fmt.Errorf("file sentry failed to arm watches (feature is enabled): %w", armErr)
				}

				// Consume findings: log to stderr and record metrics.
				// Started now so the channel is drained even before the
				// event loop begins (buffered findings from Arm window).
				go func() {
					for f := range watcher.Findings() {
						agent := ""
						if f.IsAgent {
							agent = " (agent process)"
						}
						_, _ = fmt.Fprintf(logW,
							"pipelock: [file_sentry] DLP match in %s: %s (severity=%s)%s\n",
							f.Path, f.PatternName, f.Severity, agent)
						if mcpMetrics != nil {
							mcpMetrics.RecordFileSentryFinding(f.PatternName, f.Severity, f.IsAgent)
						}
					}
				}()
				_, _ = fmt.Fprintf(logW, "pipelock: file sentry watching %d path(s)\n",
					len(cfg.FileSentry.WatchPaths))

				// onChildReady: called by RunProxy after cmd.Start() + TrackPID.
				// Starts the file sentry event loop AFTER the child PID is registered,
				// so attribution is ready before classifying any writes.
				onChildReady = func() {
					go func() {
						if startErr := watcher.Start(ctx); startErr != nil {
							_, _ = fmt.Fprintf(logW, "pipelock: file sentry fatal: %v — cancelling proxy\n", startErr)
							cancel()
						}
					}()
				}
			}

			if err := mcp.RunProxy(ctx, cmd.InOrStdin(), cmd.OutOrStdout(), logW, serverCmd, sc, approver, inputCfg, toolCfg, policyCfg, ks, chainMatcher, nil, cee, store, adaptiveCfg, mcpMetrics, lin, onChildReady, extraEnv...); err != nil {
				if sentryClient != nil {
					sentryClient.CaptureError(err)
				}
				return err
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&configFile, "config", "c", "", "config file path")
	cmd.Flags().StringVar(&upstreamURL, "upstream", "", "upstream MCP server URL (Streamable HTTP transport)")
	cmd.Flags().StringVar(&listenAddr, "listen", "", "listen address for HTTP reverse proxy mode (e.g. 0.0.0.0:8889)")
	cmd.Flags().StringArrayVar(&envVars, "env", nil, "pass environment variable to child process (KEY or KEY=VALUE, repeatable)")
	cmd.Flags().StringVar(&agentName, "agent", "", "agent profile name (resolves to config profile for policy/scanner)")
	return cmd
}
