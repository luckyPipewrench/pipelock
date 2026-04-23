// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"fmt"
	"net/http"
	"net/url"
	"os/signal"
	"slices"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/edition"
	"github.com/luckyPipewrench/pipelock/internal/emit"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
	plsentry "github.com/luckyPipewrench/pipelock/internal/sentry"
)

// Standard HTTP server timeouts. Used by all internal servers (kill switch API,
// metrics, reverse proxy, agent listeners) except the Scan API which uses
// operator-configured values.
const (
	configReloadAuditMethod = "CONFIG_RELOAD"
	dlpWarnAuditMethod      = "DLP_WARN"
	mcpAuditMethod          = "MCP"
	serverReadTimeout       = 10 * time.Second
	serverReadHeaderTimeout = 5 * time.Second
	serverWriteTimeout      = 10 * time.Second
	serverIdleTimeout       = 120 * time.Second
	serverShutdownTimeout   = 5 * time.Second

	// transportUnknown is the fallback transport label when DLPWarnContext
	// does not carry a transport value.
	transportUnknown = "unknown"
)

// dlpWarnLogContext builds the transport-appropriate audit context for a DLP
// warn event. When the transport-specific constructor cannot build a complete
// context, the caller should log the returned error and fall back to the
// best-effort context from dlpWarnFallbackLogContext.
func dlpWarnLogContext(wc scanner.DLPWarnContext) (audit.LogContext, error) {
	switch wc.Transport {
	case "connect":
		return audit.NewConnectLogContext(wc.Target, wc.ClientIP, wc.RequestID, wc.Agent)
	case "mcp_stdio", "mcp_http", "mcp_input", "mcp_http_listener", "mcp_ws":
		method := wc.Method
		if method == "" {
			method = mcpAuditMethod
		}
		return audit.NewMCPLogContext(method, wc.Resource, wc.Agent)
	default:
		return audit.NewHTTPLogContext(wc.Method, wc.URL, wc.ClientIP, wc.RequestID, wc.Agent)
	}
}

func dlpWarnFallbackLogContext(wc scanner.DLPWarnContext) audit.LogContext {
	switch {
	case wc.RequestID != "":
		return audit.NewRequestLogContext(wc.RequestID)
	case wc.Resource != "":
		method := wc.Method
		if method == "" {
			method = mcpAuditMethod
		}
		return audit.NewResourceLogContext(method, wc.Resource)
	case wc.Method != "":
		return audit.NewMethodLogContext(wc.Method)
	case wc.Transport != "":
		return audit.NewMethodLogContext(dlpWarnAuditMethod)
	default:
		return audit.LogContext{}
	}
}

// newHTTPServer creates an http.Server with the standard pipelock timeouts.
// Callers that need non-default values (e.g. reverse proxy WriteTimeout) can
// override individual fields after creation.
func newHTTPServer(handler http.Handler) *http.Server {
	return &http.Server{
		Handler:           handler,
		ReadTimeout:       serverReadTimeout,
		ReadHeaderTimeout: serverReadHeaderTimeout,
		WriteTimeout:      serverWriteTimeout,
		IdleTimeout:       serverIdleTimeout,
	}
}

// RunCmd returns the run cobra command. The RunE closure wires flags into
// a ServerOpts, derives a signal-driven context, and hands off to
// Server.Start. All lifecycle logic lives in Server (see server.go).
func RunCmd() *cobra.Command {
	var configFile string
	var mode string
	var listen string
	var mcpListen string
	var mcpUpstream string
	var reverseProxy bool
	var reverseUpstream string
	var reverseListen string
	var captureOutput string
	var captureDuration time.Duration
	var captureEscrowKey string

	cmd := &cobra.Command{
		Use:   "run [flags]",
		Short: "Start the Pipelock proxy",
		Long: `Start the proxy server that scans and controls agent HTTP traffic.

Supports two proxy modes on the same port:
  - Fetch proxy:   /fetch?url=... (extracts text, scans responses)
  - Forward proxy: CONNECT tunnels + absolute-URI (set HTTPS_PROXY, zero agent changes)

Optionally runs an MCP HTTP listener alongside the fetch proxy. The MCP listener
accepts JSON-RPC POST requests and proxies them to an upstream MCP server with
bidirectional scanning (DLP, injection, tool poisoning, policy).

The proxy runs until interrupted (SIGINT/SIGTERM). When started with --config,
file changes (and SIGHUP on Unix) trigger a hot-reload of config and scanner.

Examples:
  pipelock run                                       # standalone proxy
  pipelock run --config pipelock.yaml                # with config file (hot-reload)
  pipelock run --mode strict --listen 0.0.0.0:9999   # override mode and listen address
  pipelock run --mcp-listen 0.0.0.0:8889 --mcp-upstream http://mcp-server:3000/mcp`,
		RunE: func(cmd *cobra.Command, args []string) error { //nolint:revive // args used via ArgsLenAtDash
			opts := ServerOpts{
				ConfigFile:       configFile,
				Mode:             mode,
				Listen:           listen,
				MCPListen:        mcpListen,
				MCPUpstream:      mcpUpstream,
				ReverseProxy:     reverseProxy,
				ReverseUpstream:  reverseUpstream,
				ReverseListen:    reverseListen,
				CaptureOutput:    captureOutput,
				CaptureDuration:  captureDuration,
				CaptureEscrowKey: captureEscrowKey,
				ModeChanged:      cmd.Flags().Changed("mode"),
				ListenChanged:    cmd.Flags().Changed("listen"),
				Stdout:           cmd.OutOrStdout(),
				Stderr:           cmd.ErrOrStderr(),
			}

			if dashIdx := cmd.ArgsLenAtDash(); dashIdx >= 0 && dashIdx < len(args) {
				opts.AgentArgs = args[dashIdx:]
			}

			srv, err := NewServer(opts)
			if err != nil {
				return err
			}

			// Context with signal handling for graceful shutdown. Uses
			// cmd.Context() as parent so tests can inject a cancellable
			// context.
			ctx, cancel := signal.NotifyContext(
				cmd.Context(),
				syscall.SIGINT,
				syscall.SIGTERM,
			)
			defer cancel()

			return srv.Start(ctx)
		},
	}

	cmd.Flags().StringVarP(&configFile, "config", "c", "", "config file path")
	cmd.Flags().StringVarP(&mode, "mode", "m", "balanced", "operating mode: strict, balanced, audit")
	cmd.Flags().StringVarP(&listen, "listen", "l", "", "listen address (default 127.0.0.1:8888)")
	cmd.Flags().StringVar(&mcpListen, "mcp-listen", "", "MCP HTTP listener address (e.g. 0.0.0.0:8889)")
	cmd.Flags().StringVar(&mcpUpstream, "mcp-upstream", "", "upstream MCP server URL for HTTP listener")
	cmd.Flags().BoolVar(&reverseProxy, "reverse-proxy", false, "enable reverse proxy mode with body scanning")
	cmd.Flags().StringVar(&reverseUpstream, "reverse-upstream", "", "upstream URL for reverse proxy (e.g. http://localhost:7899)")
	cmd.Flags().StringVar(&reverseListen, "reverse-listen", ":8890", "listen address for reverse proxy")
	cmd.Flags().StringVar(&captureOutput, "capture-output", "", "directory to write policy capture files (enables capture mode)")
	cmd.Flags().DurationVar(&captureDuration, "capture-duration", 0, "capture duration (0 = until interrupted)")
	cmd.Flags().StringVar(&captureEscrowKey, "capture-escrow-public-key", "", "X25519 public key (hex) for payload sidecar encryption")

	return cmd
}

// BuildEmitSinks creates emit sinks from the current config.
// Used at startup and during hot-reload.
func BuildEmitSinks(cfg *config.Config) ([]emit.Sink, error) {
	var sinks []emit.Sink

	if cfg.Emit.Webhook.URL != "" {
		var opts []emit.WebhookOption
		opts = append(opts, emit.WithMinSeverity(emit.ParseSeverity(cfg.Emit.Webhook.MinSeverity)))
		if cfg.Emit.Webhook.AuthToken != "" {
			opts = append(opts, emit.WithBearerToken(cfg.Emit.Webhook.AuthToken))
		}
		if cfg.Emit.Webhook.QueueSize > 0 {
			opts = append(opts, emit.WithQueueSize(cfg.Emit.Webhook.QueueSize))
		}
		if cfg.Emit.Webhook.TimeoutSecs > 0 {
			opts = append(opts, emit.WithWebhookTimeout(time.Duration(cfg.Emit.Webhook.TimeoutSecs)*time.Second))
		}
		sinks = append(sinks, emit.NewWebhookSink(cfg.Emit.Webhook.URL, opts...))
	}

	if cfg.Emit.Syslog.Address != "" {
		syslogSink, err := emit.NewSyslogSinkFromConfig(
			cfg.Emit.Syslog.Address,
			cfg.Emit.Syslog.Facility,
			cfg.Emit.Syslog.Tag,
			cfg.Emit.Syslog.MinSeverity,
		)
		if err != nil {
			// Close already-created sinks to prevent goroutine leaks.
			for _, s := range sinks {
				_ = s.Close()
			}
			return nil, fmt.Errorf("creating syslog sink: %w", err)
		}
		sinks = append(sinks, syslogSink)
	}

	if cfg.Emit.OTLP.Endpoint != "" {
		otlpSink, otlpErr := emit.NewOTLPSink(
			cfg.Emit.OTLP.Endpoint,
			cliutil.Version,
			emit.ParseSeverity(cfg.Emit.OTLP.MinSeverity),
			cfg.Emit.OTLP.Headers,
			time.Duration(cfg.Emit.OTLP.TimeoutSeconds)*time.Second,
			cfg.Emit.OTLP.QueueSize,
			cfg.Emit.OTLP.Gzip,
		)
		if otlpErr != nil {
			for _, s := range sinks {
				_ = s.Close()
			}
			return nil, fmt.Errorf("creating otlp sink: %w", otlpErr)
		}
		sinks = append(sinks, otlpSink)
	}

	return sinks, nil
}

// RedactEndpoint strips userinfo, query, and fragment from an endpoint URL
// to prevent leaking tokens/secrets in startup logs.
func RedactEndpoint(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "<invalid>"
	}
	u.User = nil
	u.RawQuery = ""
	u.Fragment = ""
	return u.String()
}

// AgentHandler wraps a proxy handler with a context-injected agent profile.
// Requests through this handler are identified by the bound port, not by
// the X-Pipelock-Agent header, making them spoof-proof.
func AgentHandler(profile string, handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := edition.WithAgentOverride(r.Context(), profile)
		handler.ServeHTTP(w, r.WithContext(ctx))
	})
}

// AgentListenersChanged returns true if any agent's listener addresses differ
// between old and new config. Listener sockets bind at startup and cannot be
// rebound at runtime, so changes require a restart.
func AgentListenersChanged(oldCfg, newCfg *config.Config) bool {
	if len(oldCfg.Agents) != len(newCfg.Agents) {
		// Agent count changed; check if any had listeners.
		for _, p := range oldCfg.Agents {
			if len(p.Listeners) > 0 {
				return true
			}
		}
		for _, p := range newCfg.Agents {
			if len(p.Listeners) > 0 {
				return true
			}
		}
		return false
	}
	for name, oldProfile := range oldCfg.Agents {
		newProfile, ok := newCfg.Agents[name]
		if !ok {
			if len(oldProfile.Listeners) > 0 {
				return true
			}
			continue
		}
		if !slices.Equal(oldProfile.Listeners, newProfile.Listeners) {
			return true
		}
	}
	// Check for new agents with listeners.
	for name, newProfile := range newCfg.Agents {
		if _, ok := oldCfg.Agents[name]; !ok && len(newProfile.Listeners) > 0 {
			return true
		}
	}
	return false
}

// ReloadPanicHandler captures panics during config reload, reports them to
// Sentry, and logs the error. Extracted from the reload goroutine for
// testability.
func ReloadPanicHandler(r any, sentryClient *plsentry.Client, logger *audit.Logger, configFile string) {
	if r == nil {
		return
	}
	reloadErr := fmt.Errorf("scanner construction panic during config reload: %v", r)
	if sentryClient != nil {
		sentryClient.CaptureError(reloadErr)
	}
	logger.LogError(audit.NewResourceLogContext(configReloadAuditMethod, configFile), reloadErr)
}

// PreserveAgentListeners keeps the new config's agent listener state
// consistent with the actually-bound sockets from startup. Three cases:
//
//  1. Agent in both configs: copy old listeners into new entry.
//  2. Listener-bearing agent removed: re-add old entry so the bound
//     socket keeps its policy (prevents fallback to default profile).
//  3. Listener-bearing agent added: strip listeners (can't bind without
//     restart).
func PreserveAgentListeners(oldCfg, newCfg *config.Config) {
	if newCfg.Agents == nil {
		newCfg.Agents = make(map[string]config.AgentProfile)
	}

	// Case 1 + 2: iterate old agents.
	for name, oldProfile := range oldCfg.Agents {
		if newProfile, ok := newCfg.Agents[name]; ok {
			// Case 1: agent in both configs. Preserve old listeners,
			// keep other new config fields.
			newProfile.Listeners = oldProfile.Listeners
			newCfg.Agents[name] = newProfile
		} else if len(oldProfile.Listeners) > 0 {
			// Case 2: listener-bearing agent removed. Socket is still
			// bound, so re-add the full old entry to prevent policy
			// downgrade on the spoof-proof port.
			newCfg.Agents[name] = oldProfile
		}
	}

	// Case 3: new agents with listeners that weren't in old config.
	// Can't bind sockets without restart, so strip the listeners.
	for name, newProfile := range newCfg.Agents {
		if _, ok := oldCfg.Agents[name]; !ok && len(newProfile.Listeners) > 0 {
			newProfile.Listeners = nil
			newCfg.Agents[name] = newProfile
		}
	}
}
