// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package exec implements cooperative, fail-closed command launching.
package exec

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/launchcontract"
	"github.com/luckyPipewrench/pipelock/internal/proxyhealth"
)

type options struct {
	configFile       string
	proxyURL         string
	caFile           string
	noProxy          string
	printEnv         string
	dryRun           bool
	requireIntercept bool
}

type dependencies struct {
	launch      func(*cobra.Command, []string, []string) error
	systemRoots func() ([]byte, error)
	cacheDir    func() (string, error)
}

// Cmd returns the exec command. It does not start or modify the proxy service.
func Cmd() *cobra.Command {
	return newCmd(dependencies{launch: launch, systemRoots: launchcontract.SystemRoots, cacheDir: os.UserCacheDir})
}

func newCmd(deps dependencies) *cobra.Command {
	var opts options
	cmd := &cobra.Command{
		Use:          "exec [flags] -- CMD [ARGS...]",
		Short:        "Launch a cooperative client through a running Pipelock proxy",
		SilenceUsage: true,
		Long: `Check the running proxy and launch a command with proxy and CA environment settings.
Every required check must pass before the command can start. This steers cooperative
clients; it is not containment. Programs can ignore or override these settings.
Use pipelock contain or pipelock sandbox for operating-system enforcement.

With --ca (or a configured CA), TLS interception must be enabled. --require-intercept
also requires a CA. A combined system-roots + Pipelock bundle preserves normal trust.
Node's built-in HTTP/HTTPS and fetch support requires Node 22.21+ or 24.5+.

Examples:
  pipelock exec --config pipelock.yaml -- codex
  pipelock exec --ca ~/.pipelock/ca.pem -- claude
  pipelock exec --dry-run
  pipelock exec --print-env sh`,
		Args: func(cmd *cobra.Command, args []string) error {
			if opts.printEnv != "" && opts.printEnv != "sh" && opts.printEnv != "pwsh" && opts.printEnv != "cmd" && opts.printEnv != "json" {
				return errors.New("--print-env must be sh, pwsh, cmd, or json")
			}
			if len(args) == 0 && !opts.dryRun && opts.printEnv == "" {
				return errors.New("provide a command after --, or use --dry-run/--print-env")
			}
			if len(args) > 0 && cmd.ArgsLenAtDash() != 0 {
				return errors.New("separate the command from exec flags with --")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			resolved, err := resolveOptions(opts, cmd.Flags().Changed("proxy-url"), cmd.Flags().Changed("ca"))
			if err != nil {
				return err
			}
			vars, err := prepare(cmd.Context(), resolved, deps)
			if err != nil {
				return err
			}
			if opts.dryRun || opts.printEnv != "" {
				format := opts.printEnv
				if format == "" {
					format = "json"
				}
				return printEnvironment(cmd.OutOrStdout(), format, os.Environ(), vars)
			}
			return deps.launch(cmd, args, launchcontract.Merge(os.Environ(), vars))
		},
	}
	cmd.Flags().StringVar(&opts.configFile, "config", "", "running proxy config (used for listener and CA defaults)")
	cmd.Flags().StringVar(&opts.proxyURL, "proxy-url", "http://127.0.0.1:8888", "running Pipelock forward proxy URL")
	cmd.Flags().StringVar(&opts.caFile, "ca", "", "Pipelock CA certificate PEM file")
	cmd.Flags().StringVar(&opts.noProxy, "no-proxy", "", "explicit destinations allowed to bypass the proxy (default: none)")
	cmd.Flags().BoolVar(&opts.dryRun, "dry-run", false, "check readiness and print environment as JSON without launching")
	cmd.Flags().StringVar(&opts.printEnv, "print-env", "", "check readiness and print environment: sh, pwsh, cmd, or json")
	cmd.Flags().BoolVar(&opts.requireIntercept, "require-intercept", false, "require TLS interception and a valid CA before launching")
	return cmd
}

func resolveOptions(opts options, proxyOverride, caOverride bool) (options, error) {
	if opts.configFile != "" {
		// This config supplies client defaults, not a second service startup.
		// Inspect it without reading service-owned license material or requiring
		// access to the proxy's private CA key. Live health is authoritative.
		cfg, err := config.LoadForInspection(opts.configFile)
		if err != nil {
			return opts, fmt.Errorf("load --config: %w", err)
		}
		if !proxyOverride {
			host, port, err := net.SplitHostPort(cfg.FetchProxy.Listen)
			if err != nil {
				return opts, fmt.Errorf("resolve config listener; set --proxy-url: %w", err)
			}
			if ip := net.ParseIP(host); host == "" || (ip != nil && ip.IsUnspecified()) {
				host = "127.0.0.1"
			}
			opts.proxyURL = "http://" + net.JoinHostPort(host, port)
		}
		if !caOverride {
			opts.caFile = cfg.TLSInterception.CACertPath
			if opts.caFile == "" && cfg.TLSInterception.Enabled {
				opts.caFile, _, err = cfg.ResolveCAPath()
				if err != nil {
					return opts, fmt.Errorf("resolve configured CA; set --ca explicitly: %w", err)
				}
			}
		}
		opts.requireIntercept = opts.requireIntercept || cfg.TLSInterception.Enabled
	}
	u, err := url.Parse(opts.proxyURL)
	if err != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") || u.Opaque != "" {
		return opts, errors.New("--proxy-url must be an http(s) origin without credentials, path, query, or fragment")
	}
	u.Path = ""
	opts.proxyURL = u.String()
	if strings.ContainsAny(opts.noProxy, "\x00\r\n") {
		return opts, errors.New("--no-proxy cannot contain NUL or newlines")
	}
	if opts.requireIntercept && opts.caFile == "" {
		return opts, errors.New("TLS interception requires a CA file; set --ca or tls_interception.ca_cert in --config (create it with pipelock tls init)")
	}
	return opts, nil
}

func prepare(ctx context.Context, opts options, deps dependencies) ([]launchcontract.Variable, error) {
	var ca []byte
	if opts.caFile != "" {
		var err error
		ca, err = os.ReadFile(filepath.Clean(opts.caFile))
		if err != nil {
			return nil, fmt.Errorf("read --ca %s; fix the path or create a CA with pipelock tls init: %w", opts.caFile, err)
		}
		if err := launchcontract.ValidateCA(ca, time.Now()); err != nil {
			return nil, fmt.Errorf("invalid --ca %s; use the Pipelock CA certificate: %w", opts.caFile, err)
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	// Probe the selected proxy itself, never an inherited proxy or a redirect.
	// This is a readiness connection to the operator's chosen listener.
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := proxyhealth.Get(ctx, client, opts.proxyURL)
	if err != nil {
		return nil, fmt.Errorf("proxy unavailable; start pipelock run and verify --proxy-url: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if err := proxyhealth.CheckLaunch(resp, opts.requireIntercept || len(ca) > 0); err != nil {
		return nil, err
	}
	bundlePath := ""
	if len(ca) > 0 {
		roots, err := deps.systemRoots()
		if err != nil {
			return nil, err
		}
		bundle, err := launchcontract.CombinedBundle(roots, ca)
		if err != nil {
			return nil, err
		}
		cache, err := deps.cacheDir()
		if err != nil {
			return nil, fmt.Errorf("find CA cache; configure an OS user cache directory: %w", err)
		}
		bundlePath, err = launchcontract.WriteBundle(cache, bundle)
		if err != nil {
			return nil, err
		}
	}
	return launchcontract.Vars(launchcontract.Exec, opts.proxyURL, opts.noProxy, bundlePath, opts.caFile), nil
}
