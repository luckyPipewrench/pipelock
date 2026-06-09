// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// The runtime contract is the complete set of proxy + CA configuration the
// contained pipelock-agent user needs so that common tooling (curl, python,
// node, git, npm, pip, go, cargo) routes through the Pipelock proxy and trusts
// the Pipelock MITM CA. Before this existed, only clients that honored the
// handful of env vars baked into plk-launch worked; anything that ignored
// HTTPS_PROXY (notably node/undici) or read its own config file looked
// "broken" with a generic network error.
//
// This file is the single source of truth for the contract. plk-launch, the
// /etc/profile.d login-shell script, the pipelock-* utility wrappers, and the
// `contain doctor` self-test all derive from runtimeContractVars so the
// surfaces never drift.

const (
	// contractNoProxy is the exact NO_PROXY/no_proxy value injected for the
	// contained agent. Loopback v4, the localhost name, and loopback v6 (::1)
	// so an IPv6-first client does not try to proxy a local dial. Everything
	// else flows through Pipelock. Any deviation is a policy regression caught
	// by verify probe 7.
	contractNoProxy = "127.0.0.1,localhost,::1"

	// defaultUndiciShimPath is the CommonJS shim node loads via
	// NODE_OPTIONS=--require so its built-in fetch()/undici clients honor
	// HTTPS_PROXY. It lives under the agent-traversable /etc/pipelock/contain
	// directory so the contained user can read it at exec time.
	defaultUndiciShimPath = "/etc/pipelock/contain/undici-shim.cjs"

	// defaultProfileScriptPath exports the full contract for any login shell
	// (e.g. `sudo -iu pipelock-agent`). plk-launch and the wrappers force the
	// contract regardless; this closes the interactive/login-shell gap.
	defaultProfileScriptPath = "/etc/profile.d/pipelock-contain.sh"

	// modeProfileScript is group-readable, not world-readable: the file is
	// owned root:<agent-group> so only the contained agent's login shell can
	// source it. The script holds only public proxy URLs and CA paths, but
	// scoping it to the agent group avoids a repo-wide 0o644 exception and keeps
	// it off every other user's login path.
	modeProfileScript os.FileMode = 0o640

	// modeAgentConfig is owner-only; the per-tool config files live in the
	// agent's home and only the agent reads them.
	modeAgentConfig os.FileMode = 0o600
)

// pipelockUtilityWrappers are the known-good, proxy+CA-correct wrappers placed
// on the contained agent's PATH. Unlike the plk-* allow-list wrappers (which
// gate which agent tools may run), these force a correct runtime contract for
// the common HTTP clients even when the caller's environment is incomplete.
var pipelockUtilityWrappers = []string{"pipelock-curl", "pipelock-python", "pipelock-node"}

// contractVar is one name/value pair in the runtime contract.
type contractVar struct {
	name  string
	value string
}

// proxyURLFor builds the loopback proxy URL baked into the contract.
func proxyURLFor(port int) string {
	return "http://127.0.0.1:" + strconv.Itoa(port)
}

// agentHomeDir returns the contained agent's home directory. Mirrors the
// --home-dir passed to useradd in stepCreateUser. The field is overridable so
// tests can target a tmp dir; it defaults to /home/<agent> via the
// installEnv constructor.
func agentHomeDir(env *installEnv) string {
	if env.agentHome != "" {
		return env.agentHome
	}
	return "/home/" + env.agentUserName
}

// undiciShimPathOrDefault resolves the shim path, tolerating a zero-value
// installEnv (tests that build partial structs).
func undiciShimPathOrDefault(env *installEnv) string {
	if env.undiciShimPath != "" {
		return env.undiciShimPath
	}
	return defaultUndiciShimPath
}

// profileScriptPathOrDefault resolves the profile.d path with the same
// zero-value tolerance.
func profileScriptPathOrDefault(env *installEnv) string {
	if env.profileScriptPath != "" {
		return env.profileScriptPath
	}
	return defaultProfileScriptPath
}

// runtimeContractVars returns the COMPLETE ordered proxy/CA env matrix for the
// contained agent. Order matters: uppercase NO_PROXY precedes lowercase
// no_proxy so verify's extractNoProxy keys off the canonical assignment, and
// the proxy/CA blocks are grouped for readability in the rendered scripts.
//
// Covered surfaces:
//   - generic libs honoring *_PROXY (curl, wget, go, requests-with-env)
//   - python requests/certifi via REQUESTS_CA_BUNDLE
//   - openssl/python ssl via SSL_CERT_FILE
//   - curl/libcurl via CURL_CA_BUNDLE
//   - git via GIT_SSL_CAINFO
//   - cargo via CARGO_HTTP_CAINFO / CARGO_HTTP_PROXY
//   - pip via PIP_CERT
//   - node http/https modules via *_PROXY + NODE_EXTRA_CA_CERTS, and node's
//     built-in fetch()/undici via NODE_USE_ENV_PROXY on node versions that
//     support it, plus the NODE_OPTIONS require shim fallback.
func runtimeContractVars(env *installEnv) []contractVar {
	proxy := proxyURLFor(env.proxyPort)
	caBundle := env.caBundlePath
	nodeCA := env.caExportPath
	shim := undiciShimPathOrDefault(env)

	return []contractVar{
		// Proxy (upper + lower; clients disagree on which they read).
		{"HTTP_PROXY", proxy},
		{"http_proxy", proxy},
		{"HTTPS_PROXY", proxy},
		{"https_proxy", proxy},
		{"ALL_PROXY", proxy},
		{"all_proxy", proxy},
		{"NO_PROXY", contractNoProxy},
		{"no_proxy", contractNoProxy},
		// CA trust for the Pipelock MITM CA across tool ecosystems.
		{"SSL_CERT_FILE", caBundle},
		{"REQUESTS_CA_BUNDLE", caBundle},
		{"CURL_CA_BUNDLE", caBundle},
		{"GIT_SSL_CAINFO", caBundle},
		{"CARGO_HTTP_CAINFO", caBundle},
		{"PIP_CERT", caBundle},
		// node trusts an APPENDED CA file (not a replacement bundle).
		{"NODE_EXTRA_CA_CERTS", nodeCA},
		// Older node fetch()/undici ignores *_PROXY unless a global dispatcher
		// is installed; the shim does that at startup when undici is available.
		{"NODE_OPTIONS", "--require " + shim},
		// Newer node fetch()/undici honors *_PROXY natively when this flag exists.
		{"NODE_USE_ENV_PROXY", "1"},
	}
}

// shellSafeValue reports whether v can appear unquoted after `env NAME=` in a
// bash command. Conservative: anything outside this set gets single-quoted.
func shellSafeValue(v string) bool {
	if v == "" {
		return false
	}
	for _, r := range v {
		switch {
		case r >= 'a' && r <= 'z',
			r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9':
			continue
		}
		switch r {
		case '_', '.', '/', ':', ',', '=', '@', '%', '+', '-':
			continue
		default:
			return false
		}
	}
	return true
}

// envAssign renders a single `NAME=value` token safe for `env` in bash. Values
// with shell-significant characters (e.g. the space in NODE_OPTIONS) are
// single-quoted; the common proxy URLs and paths render bare.
func envAssign(name, value string) string {
	if shellSafeValue(value) {
		return name + "=" + value
	}
	return name + "=" + shellQuote(value)
}

// launchExecEnvLines renders the `exec env \`-style block that plk-launch uses
// to run the resolved tool under the full runtime contract. HOME and PATH are
// handled specially (HOME is fixed, PATH expands the AGENT_PATH shell var), so
// they bracket the generated contract assignments.
func launchExecEnvLines(env *installEnv) []string {
	lines := []string{
		"exec env \\",
		"    " + envAssign("HOME", agentHomeDir(env)) + " \\",
	}
	for _, v := range runtimeContractVars(env) {
		lines = append(lines, "    "+envAssign(v.name, v.value)+" \\")
	}
	lines = append(lines,
		`    PATH="$AGENT_PATH" \`,
		`    "$TARGET" "$@"`,
	)
	return lines
}

// renderProfileScript renders /etc/profile.d/pipelock-contain.sh. Sourced by
// login shells of the contained agent; exports the same contract plus the
// agent PATH so an interactive `sudo -iu pipelock-agent` session is also
// proxy-correct.
func renderProfileScript(env *installEnv) string {
	lines := []string{
		"# Managed by `pipelock contain install`. Edits are clobbered on next install.",
		"# Sourced from /etc/profile.d; only the contained agent should inherit",
		"# the Pipelock proxy + CA runtime contract.",
		"_pipelock_contain_user=\"$(id -un 2>/dev/null || true)\"",
		"if [ \"$_pipelock_contain_user\" != " + shellQuote(env.agentUserName) + " ]; then",
		"    return 0 2>/dev/null || exit 0",
		"fi",
		"unset _pipelock_contain_user",
		"PATH=" + shellQuote(agentExecPath(env.agentUserName)),
		"export PATH",
	}
	for _, v := range runtimeContractVars(env) {
		lines = append(lines, "export "+v.name+"="+shellQuote(v.value))
	}
	return strings.Join(lines, "\n") + "\n"
}

// renderUndiciShim is the static CommonJS shim node loads via
// NODE_OPTIONS=--require. It installs a global undici ProxyAgent so node's
// built-in fetch() and undici-based clients honor HTTPS_PROXY. Best-effort: if
// undici is not a resolvable module, http/https-module traffic still honors
// the proxy via the *_PROXY env vars, so the shim degrades silently. The
// upstream TLS cert (signed by the Pipelock CA) is trusted via
// NODE_EXTRA_CA_CERTS, so the proxied request validates.
func renderUndiciShim() string {
	return `'use strict';
// Managed by ` + "`pipelock contain install`" + `. Installs a global undici
// ProxyAgent so node's built-in fetch() and undici clients route through the
// Pipelock proxy. node ignores HTTPS_PROXY for fetch() unless a global
// dispatcher is set. Best-effort: if undici cannot be required, http/https
// module traffic still honors the *_PROXY env vars.
try {
  const undici = require('undici');
  const proxy =
    process.env.HTTPS_PROXY ||
    process.env.https_proxy ||
    process.env.HTTP_PROXY ||
    process.env.http_proxy ||
    process.env.ALL_PROXY ||
    process.env.all_proxy;
  if (
    proxy &&
    undici &&
    typeof undici.setGlobalDispatcher === 'function' &&
    typeof undici.ProxyAgent === 'function'
  ) {
    undici.setGlobalDispatcher(new undici.ProxyAgent(proxy));
  }
} catch (err) {
  // undici not installed as a resolvable module; nothing to do.
}
`
}

// renderUtilityWrapper emits a known-good wrapper that forces the full runtime
// contract before exec'ing the real tool, so the tool is proxy+CA-correct even
// when the caller's environment is incomplete. The real binary is resolved via
// the agent PATH at runtime (command -v) so the wrapper does not hardcode a
// distro-specific path. `tool` is the binary to run (curl/python3/node); the
// wrapper is named pipelock-<short>.
func renderUtilityWrapper(env *installEnv, tool string) string {
	var assigns []string
	for _, v := range runtimeContractVars(env) {
		assigns = append(assigns, "    "+envAssign(v.name, v.value)+" \\")
	}
	header := []string{
		"#!/bin/bash",
		"# Managed by `pipelock contain install`. Edits are clobbered on next install.",
		"# Forces the Pipelock proxy + CA runtime contract, then execs " + tool + ".",
		"set -euo pipefail",
		"",
		"AGENT_PATH=" + agentExecPath(env.agentUserName),
		`BIN="$(PATH="$AGENT_PATH" command -v ` + tool + `)" || {`,
		`    echo "pipelock wrapper: ` + tool + ` not found in PATH" >&2`,
		`    exit 127`,
		`}`,
		"",
		"exec env \\",
		"    " + envAssign("HOME", agentHomeDir(env)) + " \\",
	}
	footer := []string{
		`    PATH="$AGENT_PATH" \`,
		`    "$BIN" "$@"`,
		"",
	}
	return strings.Join(append(append(header, assigns...), footer...), "\n")
}

// realToolForUtilityWrapper maps a pipelock-<short> wrapper name to the binary
// it should resolve and exec.
func realToolForUtilityWrapper(name string) (string, bool) {
	switch name {
	case "pipelock-curl":
		return "curl", true
	case "pipelock-python":
		return "python3", true
	case "pipelock-node":
		return "node", true
	default:
		return "", false
	}
}

// ---------------------------------------------------------------------------
// Per-tool config files written into the agent home. These cover the
// non-env exec paths: git/npm/pip/cargo read their own config regardless of
// whether a process inherited the proxy env, so a bare
// `sudo -u pipelock-agent git clone ...` is proxy-correct.
// ---------------------------------------------------------------------------

// agentToolConfig is one config file rendered into the agent home.
type agentToolConfig struct {
	rel    string // path relative to the agent home
	render func(env *installEnv) string
}

func agentToolConfigs() []agentToolConfig {
	return []agentToolConfig{
		{".gitconfig", renderAgentGitConfig},
		{".npmrc", renderAgentNpmrc},
		{filepath.Join(".config", "pip", "pip.conf"), renderAgentPipConf},
		{filepath.Join(".cargo", "config.toml"), renderAgentCargoConfig},
	}
}

func renderAgentGitConfig(env *installEnv) string {
	proxy := proxyURLFor(env.proxyPort)
	return strings.Join([]string{
		"# Managed by `pipelock contain install`. Edits are clobbered on next install.",
		"[http]",
		"\tproxy = " + proxy,
		"\tsslCAInfo = " + env.caBundlePath,
		"[https]",
		"\tproxy = " + proxy,
		"",
	}, "\n")
}

func renderAgentNpmrc(env *installEnv) string {
	proxy := proxyURLFor(env.proxyPort)
	return strings.Join([]string{
		"# Managed by `pipelock contain install`. Edits are clobbered on next install.",
		"proxy=" + proxy,
		"https-proxy=" + proxy,
		"cafile=" + env.caBundlePath,
		"",
	}, "\n")
}

func renderAgentPipConf(env *installEnv) string {
	proxy := proxyURLFor(env.proxyPort)
	return strings.Join([]string{
		"# Managed by `pipelock contain install`. Edits are clobbered on next install.",
		"[global]",
		"proxy = " + proxy,
		"cert = " + env.caBundlePath,
		"",
	}, "\n")
}

func renderAgentCargoConfig(env *installEnv) string {
	proxy := proxyURLFor(env.proxyPort)
	return strings.Join([]string{
		"# Managed by `pipelock contain install`. Edits are clobbered on next install.",
		"[http]",
		"proxy = \"" + proxy + "\"",
		"cainfo = \"" + env.caBundlePath + "\"",
		"",
	}, "\n")
}

// ---------------------------------------------------------------------------
// Install steps for the runtime contract artifacts.
// ---------------------------------------------------------------------------

// stepWriteUndiciShim writes the node undici shim. It must run BEFORE the
// launch wrapper and profile script are USED at runtime (the contract sets
// NODE_OPTIONS=--require <shim>; a missing file would make every node
// invocation fail), so it is ordered before stepWriteLaunchWrapper.
func stepWriteUndiciShim() step {
	return step{
		name: "write-undici-shim",
		desc: "write node undici proxy shim (" + defaultUndiciShimPath + ")",
		apply: func(_ context.Context, env *installEnv) (bool, error) {
			path := undiciShimPathOrDefault(env)
			// The /etc/pipelock/contain dir is created + chmod'd by
			// stepWriteToolsList, which precedes this step; mkdirAll here is a
			// no-op safety net so the step is order-independent.
			if err := env.mkdirAll(filepath.Dir(path), modeDirTraversable); err != nil {
				return false, fmt.Errorf("mkdir %s: %w", filepath.Dir(path), err)
			}
			body := renderUndiciShim()
			if existing, err := env.readFile(path); err == nil && string(existing) == body {
				// Re-assert mode on rerun: NODE_OPTIONS=--require points here, so
				// an unreadable shim would break every node invocation.
				if cerr := env.chmod(path, modeAllowListReadable); cerr != nil {
					return false, fmt.Errorf("chmod %s: %w", path, cerr)
				}
				return false, nil
			}
			if err := backupAndWrite(env, path, []byte(body), modeAllowListReadable); err != nil {
				return false, err
			}
			return true, nil
		},
		undo: func(_ context.Context, env *installEnv) error {
			return restoreBackup(env, undiciShimPathOrDefault(env))
		},
	}
}

// stepWriteProfileScript writes /etc/profile.d/pipelock-contain.sh so login
// shells of the contained agent inherit the contract.
func stepWriteProfileScript() step {
	return step{
		name: "write-profile-script",
		desc: "write login-shell runtime contract (" + defaultProfileScriptPath + ")",
		apply: func(_ context.Context, env *installEnv) (bool, error) {
			path := profileScriptPathOrDefault(env)
			// Owned root:<agent-group> so only the agent can source it. Group is
			// the agent's primary group (useradd --user-group => gid == agent).
			_, gid, err := uidGidFor(env, env.agentUserName)
			if err != nil {
				return false, fmt.Errorf("resolve %s group: %w", env.agentUserName, err)
			}
			if err := env.mkdirAll(filepath.Dir(path), modeDirTraversable); err != nil {
				return false, fmt.Errorf("mkdir %s: %w", filepath.Dir(path), err)
			}
			body := renderProfileScript(env)
			if existing, rerr := env.readFile(path); rerr == nil && string(existing) == body {
				// Re-assert mode + ownership on rerun so a drifted profile script
				// can't silently stop applying to the agent.
				if err := env.chmod(path, modeProfileScript); err != nil {
					return false, fmt.Errorf("chmod %s: %w", path, err)
				}
				if err := env.chown(path, 0, gid); err != nil {
					return false, fmt.Errorf("chown %s: %w", path, err)
				}
				return false, nil
			}
			if err := backupAndWrite(env, path, []byte(body), modeProfileScript); err != nil {
				return false, err
			}
			if err := env.chown(path, 0, gid); err != nil {
				return false, fmt.Errorf("chown %s: %w", path, err)
			}
			return true, nil
		},
		undo: func(_ context.Context, env *installEnv) error {
			return restoreBackup(env, profileScriptPathOrDefault(env))
		},
	}
}

// stepWriteUtilityWrappers writes the pipelock-curl/python/node known-good
// wrappers onto the agent PATH.
func stepWriteUtilityWrappers() step {
	var touched []string
	return step{
		name: "write-utility-wrappers",
		desc: "write pipelock-curl/python/node proxy-correct wrappers",
		apply: func(_ context.Context, env *installEnv) (bool, error) {
			touched = nil
			for _, name := range pipelockUtilityWrappers {
				tool, ok := realToolForUtilityWrapper(name)
				if !ok {
					return false, fmt.Errorf("unknown utility wrapper %q", name)
				}
				path := filepath.Join(env.wrapperDir, name)
				body := renderUtilityWrapper(env, tool)
				restoreTouched := func(cause error) (bool, error) {
					errs := []error{cause}
					for i := len(touched) - 1; i >= 0; i-- {
						if rerr := restoreBackup(env, touched[i]); rerr != nil {
							errs = append(errs, rerr)
						}
					}
					return false, errors.Join(errs...)
				}
				if existing, err := env.readFile(path); err == nil && string(existing) == body {
					// Re-assert the executable bit on rerun so a drifted wrapper
					// can't become non-executable.
					if cerr := env.chmod(path, modeWrapperExec); cerr != nil {
						return restoreTouched(fmt.Errorf("chmod %s: %w", path, cerr))
					}
					continue
				}
				if err := backupAndWrite(env, path, []byte(body), modeWrapperExec); err != nil {
					return restoreTouched(fmt.Errorf("write %s: %w", path, err))
				}
				touched = append(touched, path)
			}
			return len(touched) > 0, nil
		},
		undo: func(_ context.Context, env *installEnv) error {
			var errs []error
			for i := len(touched) - 1; i >= 0; i-- {
				if err := restoreBackup(env, touched[i]); err != nil {
					errs = append(errs, err)
				}
			}
			return errors.Join(errs...)
		},
	}
}

// stepWriteAgentToolConfigs writes git/npm/pip/cargo config into the agent
// home so config-reading tools are proxy-correct on every exec path, including
// a bare `sudo -u pipelock-agent <tool>` that inherits no proxy env. Files are
// owned by the agent (0600) so only the agent reads them.
func stepWriteAgentToolConfigs() step {
	var touched []string
	return step{
		name: "write-agent-tool-configs",
		desc: "write git/npm/pip/cargo proxy config into the agent home",
		apply: func(_ context.Context, env *installEnv) (bool, error) {
			touched = nil
			uid, gid, err := uidGidFor(env, env.agentUserName)
			if err != nil {
				return false, fmt.Errorf("resolve %s uid: %w", env.agentUserName, err)
			}
			home := agentHomeDir(env)
			restore := func(cause error) (bool, error) {
				errs := []error{cause}
				for i := len(touched) - 1; i >= 0; i-- {
					if rerr := restoreBackup(env, touched[i]); rerr != nil {
						errs = append(errs, rerr)
					}
				}
				return false, errors.Join(errs...)
			}
			for _, cfg := range agentToolConfigs() {
				path := filepath.Join(home, cfg.rel)
				dir := filepath.Dir(path)
				if err := ensureAgentConfigDir(env, dir, uid, gid); err != nil {
					return restore(err)
				}
				body := cfg.render(env)
				if existing, err := env.readFile(path); err == nil && string(existing) == body {
					// Re-assert ownership without following a swapped symlink.
					if cerr := chownAgentConfigFile(env, path, uid, gid); cerr != nil {
						return restore(fmt.Errorf("chown %s: %w", path, cerr))
					}
					continue
				}
				if err := backupAndWrite(env, path, []byte(body), modeAgentConfig); err != nil {
					return restore(fmt.Errorf("write %s: %w", path, err))
				}
				if err := chownAgentConfigFile(env, path, uid, gid); err != nil {
					return restore(fmt.Errorf("chown %s: %w", path, err))
				}
				touched = append(touched, path)
			}
			return len(touched) > 0, nil
		},
		undo: func(_ context.Context, env *installEnv) error {
			var errs []error
			for i := len(touched) - 1; i >= 0; i-- {
				if err := restoreBackup(env, touched[i]); err != nil {
					errs = append(errs, err)
				}
			}
			return errors.Join(errs...)
		},
	}
}

func chownAgentConfigFile(env *installEnv, path string, uid, gid int) error {
	clean := filepath.Clean(path)
	if err := ensureAgentConfigLeaf(env, clean); err != nil {
		return err
	}
	if err := env.lchown(clean, uid, gid); err != nil {
		return err
	}
	return ensureAgentConfigLeaf(env, clean)
}

func ensureAgentConfigLeaf(env *installEnv, path string) error {
	info, err := env.lstat(path)
	if err != nil {
		return fmt.Errorf("stat %s: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s is a symlink; refusing privileged chown", path)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%s exists and is not a regular file", path)
	}
	return nil
}

func ensureAgentConfigDir(env *installEnv, dir string, uid, gid int) error {
	cleanHome := filepath.Clean(agentHomeDir(env))
	cleanDir := filepath.Clean(dir)
	if !filepath.IsAbs(cleanHome) || !filepath.IsAbs(cleanDir) {
		return fmt.Errorf("agent config dir %s must be absolute under %s", cleanDir, cleanHome)
	}
	rel, err := filepath.Rel(cleanHome, cleanDir)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return fmt.Errorf("agent config dir %s is outside agent home %s", cleanDir, cleanHome)
	}
	if err := ensureSafeDirectory(env, cleanDir); err != nil {
		return err
	}
	if err := env.mkdirAll(cleanDir, modeDirPrivate); err != nil {
		return fmt.Errorf("mkdir %s: %w", cleanDir, err)
	}

	cur := cleanHome
	if err := chownAgentConfigDir(env, cur, uid, gid); err != nil {
		return err
	}
	if rel == "." {
		return nil
	}
	for _, part := range strings.Split(rel, string(os.PathSeparator)) {
		cur = filepath.Join(cur, part)
		if err := chownAgentConfigDir(env, cur, uid, gid); err != nil {
			return err
		}
	}
	return nil
}

func chownAgentConfigDir(env *installEnv, dir string, uid, gid int) error {
	info, err := env.lstat(dir)
	if err != nil {
		return fmt.Errorf("stat %s: %w", dir, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s is a symlink; refusing privileged chown", dir)
	}
	if !info.IsDir() {
		return fmt.Errorf("%s exists and is not a directory", dir)
	}
	if err := env.lchown(dir, uid, gid); err != nil {
		return fmt.Errorf("chown %s: %w", dir, err)
	}
	return nil
}
