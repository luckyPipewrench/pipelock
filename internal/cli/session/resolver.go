// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package session

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/killswitch"
)

// Environment variable names used by the resolver. Kept here so the
// flag help strings and the fallback chain share a single source.
const (
	envAPIURL     = "PIPELOCK_API_URL"
	envConfigVar  = "PIPELOCK_CONFIG"
	defaultScheme = "http://"
)

// endpoint carries the fully resolved API URL and bearer token. Returned
// by resolveEndpoint and consumed by the HTTP client.
type endpoint struct {
	URL   string
	Token string
}

// resolverDeps bundles the injectable filesystem and environment
// accessors used by resolveEndpoint. Kept as a struct so tests can swap
// out home-dir lookup, stat, and config loading without touching the
// real filesystem or environment.
type resolverDeps struct {
	userHomeDir func() (string, error)
	stat        func(string) (os.FileInfo, error)
	loadConfig  func(string) (*config.Config, error)
	getenv      func(string) string
}

// defaultResolverDeps returns the live production wiring for resolveEndpoint.
func defaultResolverDeps() resolverDeps {
	return resolverDeps{
		userHomeDir: os.UserHomeDir,
		stat:        os.Stat,
		loadConfig:  config.Load,
		getenv:      os.Getenv,
	}
}

// resolveEndpoint derives the API URL and bearer token from (in order):
//  1. explicit CLI flags
//  2. environment variables (PIPELOCK_API_URL, PIPELOCK_KILLSWITCH_API_TOKEN)
//  3. the pipelock config file's kill_switch section
//
// Returns a descriptive error when no token can be located so operators
// get a clear message instead of a 401 from the server. File perms on
// any config path sourced from step (3) are checked here — world-readable
// files are rejected outright per the admin API threat model.
func resolveEndpoint(flags *rootFlags, deps resolverDeps) (endpoint, error) {
	ep := endpoint{
		URL:   flags.apiURL,
		Token: flags.apiToken,
	}

	if ep.URL == "" {
		ep.URL = deps.getenv(envAPIURL)
	}
	if ep.Token == "" {
		ep.Token = deps.getenv(killswitch.EnvAPIToken)
	}

	if ep.URL != "" && ep.Token != "" {
		return normalizeEndpoint(ep), nil
	}

	cfgPath := resolveConfigPath(flags.configPath, deps.userHomeDir, deps.stat, deps.getenv)
	if cfgPath == "" {
		// No config file located and the caller provided neither URL nor
		// token via flags/env — fail with a clear message.
		if ep.Token == "" {
			return endpoint{}, errors.New("admin API token is required: set --api-token, PIPELOCK_KILLSWITCH_API_TOKEN, or point --config at a pipelock config file")
		}
		if ep.URL == "" {
			return endpoint{}, errors.New("admin API URL is required: set --api-url, PIPELOCK_API_URL, or point --config at a pipelock config file")
		}
		return normalizeEndpoint(ep), nil
	}

	if err := checkConfigPerms(cfgPath, deps.stat); err != nil {
		return endpoint{}, err
	}

	cfg, err := deps.loadConfig(filepath.Clean(cfgPath))
	if err != nil {
		return endpoint{}, fmt.Errorf("loading config %s: %w", cfgPath, err)
	}

	if ep.URL == "" && cfg.KillSwitch.APIListen != "" {
		apiURL, err := apiListenToURL(cfg.KillSwitch.APIListen)
		if err != nil {
			return endpoint{}, fmt.Errorf("invalid kill_switch.api_listen %q in %s: %w", cfg.KillSwitch.APIListen, cfgPath, err)
		}
		ep.URL = apiURL
	}
	if ep.Token == "" {
		ep.Token = cfg.KillSwitch.APIToken
	}

	if ep.URL == "" {
		return endpoint{}, fmt.Errorf("no admin API URL: set --api-url, PIPELOCK_API_URL, or kill_switch.api_listen in %s", cfgPath)
	}
	if ep.Token == "" {
		return endpoint{}, fmt.Errorf("no admin API token: set --api-token, PIPELOCK_KILLSWITCH_API_TOKEN, or kill_switch.api_token in %s", cfgPath)
	}

	return normalizeEndpoint(ep), nil
}

// resolveConfigPath returns the best-effort path to the active pipelock
// config file. Checks (in order): explicit flag, PIPELOCK_CONFIG env,
// ~/.config/pipelock/pipelock.yaml, /etc/pipelock/pipelock.yaml.
// Returns empty string when no candidate exists — the caller decides
// whether that is an error.
func resolveConfigPath(explicit string, userHomeDir func() (string, error), stat func(string) (os.FileInfo, error), getenv func(string) string) string {
	if explicit != "" {
		return explicit
	}
	if env := getenv(envConfigVar); env != "" {
		return env
	}
	if userHomeDir != nil {
		if home, err := userHomeDir(); err == nil && home != "" {
			candidate := filepath.Join(home, ".config", "pipelock", "pipelock.yaml")
			if _, err := stat(candidate); err == nil {
				return candidate
			}
		}
	}
	const systemWide = "/etc/pipelock/pipelock.yaml"
	if _, err := stat(systemWide); err == nil {
		return systemWide
	}
	return ""
}

// checkConfigPerms refuses any config file that carries group/world
// permission bits OR an owner-execute bit. The admin API token is a
// shared secret — a loose file perm is treated as a deployment error
// rather than a warning, and an executable config file is a policy
// smell regardless of who can read it (per CLAUDE.md: always 0o600 for
// files, never 0o644/0o755/0o700). The 0o177 mask catches:
//
//	0o100  owner execute  — reject (executable config files never ok)
//	0o070  any group bit  — reject
//	0o007  any world bit  — reject
//
// Allows 0o600 (rw owner) and 0o400 (r owner), which are the only
// reasonable deployment modes for a credential-bearing config.
// Callers inject a stat function for testability.
func checkConfigPerms(path string, stat func(string) (os.FileInfo, error)) error {
	info, err := stat(filepath.Clean(path))
	if err != nil {
		return fmt.Errorf("stat config %s: %w", path, err)
	}
	mode := info.Mode().Perm()
	if mode&0o177 != 0 {
		return fmt.Errorf("config file %s has group/world or owner-execute permission bits set (mode %o); restrict to 0o600 before using it as an admin API source", path, mode)
	}
	return nil
}

// normalizeEndpoint strips trailing slashes from the URL and prepends
// http:// when the caller passed a bare host:port without a scheme.
func normalizeEndpoint(ep endpoint) endpoint {
	ep.URL = ensureScheme(ep.URL)
	for len(ep.URL) > 0 && ep.URL[len(ep.URL)-1] == '/' {
		ep.URL = ep.URL[:len(ep.URL)-1]
	}
	return ep
}

// apiListenToURL converts a bind address (e.g. ":9090", "0.0.0.0:9090",
// "[::]:9090") into a client-usable URL by mapping wildcard/unspecified
// hosts to loopback. The admin API binds to a listen address but clients
// need a concrete host to dial.
func apiListenToURL(listen string) (string, error) {
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return "", err
	}
	switch host {
	case "", "0.0.0.0":
		host = "127.0.0.1"
	case "::":
		host = "::1"
	}
	return defaultScheme + net.JoinHostPort(host, port), nil
}

// ensureScheme prepends http:// when a bare host:port slipped through.
// Leaves https:// URLs and explicit http:// URLs alone so operators can
// point the CLI at a TLS-wrapped admin API when one is configured.
func ensureScheme(s string) string {
	if s == "" {
		return s
	}
	if len(s) >= 7 && s[:7] == defaultScheme {
		return s
	}
	if len(s) >= 8 && s[:8] == "https://" {
		return s
	}
	return defaultScheme + s
}
