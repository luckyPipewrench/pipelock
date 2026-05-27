// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package hermes

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"

	"gopkg.in/yaml.v3"

	"github.com/luckyPipewrench/pipelock/internal/mcpwrap"
)

const (
	// DefaultHermesConfigSubpath is the per-user Hermes config file pipelock
	// edits, resolved against the operator's HOME.
	DefaultHermesConfigSubpath = ".hermes/config.yaml"

	// terminalKey is the config.yaml section configuring Hermes' command
	// execution backend.
	terminalKey = "terminal"
	// backendKey selects the terminal execution backend.
	backendKey = "backend"
	// envPassthroughKey lists env var names forwarded into sandboxed tool
	// execution (terminal + execute_code).
	envPassthroughKey = "env_passthrough"
	// dockerForwardEnvKey lists env var names forwarded specifically to the
	// docker backend.
	dockerForwardEnvKey = "docker_forward_env"
	// mcpServersKey is the config.yaml section declaring MCP servers.
	mcpServersKey = "mcp_servers"

	// pluginsKey is the config.yaml section configuring Hermes' plugin loader.
	pluginsKey = "plugins"
	// enabledKey is the opt-in allow-list under plugins: Hermes loads a
	// standalone plugin only when its registry key/name appears here
	// (hermes_cli/plugins.py _get_enabled_plugins + discover_and_load gating).
	enabledKey = "enabled"

	// backendDocker is the terminal backend that uses dockerForwardEnvKey in
	// addition to envPassthroughKey.
	backendDocker = "docker"
)

// pluginRegistryName is the name pipelock writes into plugins.enabled and the
// name field of the embedded plugin.yaml. Hermes matches plugins.enabled
// entries against the plugin's registry key OR its manifest name; pinning both
// to this constant makes the enable check deterministic regardless of the
// install directory name.
const pluginRegistryName = "pipelock"

// proxyEnvNames are the environment variable names forwarded to Hermes
// terminal backends so sandboxed tool execution inherits pipelock's proxy and
// CA trust. These are NAMES only — the values must be set in Hermes' own
// environment for traffic to actually route through pipelock. Terminal
// proxying is therefore cooperative, not binary-enforced.
//
// Both upper and lower case variants are included because different tools and
// runtimes read different casings (Go/libcurl honor both; many honor only one).
var proxyEnvNames = []string{
	"HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY", "NO_PROXY",
	"https_proxy", "http_proxy", "all_proxy", "no_proxy",
	"NODE_EXTRA_CA_CERTS", // Node.js TLS trust
	"SSL_CERT_FILE",       // OpenSSL / Python ssl
	"REQUESTS_CA_BUNDLE",  // Python requests
	"CURL_CA_BUNDLE",      // libcurl
}

// ResolveDefaultHermesConfig returns the default config.yaml path computed
// from the supplied home directory. It does not touch the filesystem.
func ResolveDefaultHermesConfig(home string) string {
	return filepath.Join(home, DefaultHermesConfigSubpath)
}

// hermesConfig wraps a parsed ~/.hermes/config.yaml as a generic map so
// unknown top-level keys survive the round-trip. yaml.v3 marshals map keys in
// sorted order, so re-running install produces stable output (idempotent).
// Comments are not preserved; the .bak file written on save retains the
// original verbatim.
type hermesConfig struct {
	path    string
	root    map[string]interface{}
	existed bool
}

// loadHermesConfig reads the config at path. A missing file yields an empty
// config that save() will create. A present-but-unparseable file is an error
// (refuse to clobber something we can't understand).
func loadHermesConfig(path string) (*hermesConfig, error) {
	clean := filepath.Clean(path)
	data, err := os.ReadFile(clean)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return &hermesConfig{path: clean, root: map[string]interface{}{}, existed: false}, nil
		}
		return nil, fmt.Errorf("hermes: read %s: %w", clean, err)
	}

	root := map[string]interface{}{}
	if len(data) > 0 {
		if err := yaml.Unmarshal(data, &root); err != nil {
			return nil, fmt.Errorf("hermes: parse %s: %w", clean, err)
		}
		if root == nil {
			root = map[string]interface{}{}
		}
	}
	return &hermesConfig{path: clean, root: root, existed: true}, nil
}

// save writes the config back to disk. When backup is true and the file
// already existed, the prior content is rotated to `<path>.bak.<unix-nanos>`
// first. The parent directory is created if missing.
func (c *hermesConfig) save(backup bool) (string, error) {
	dir := filepath.Dir(c.path)
	if err := os.MkdirAll(dir, pluginDirPerm); err != nil {
		return "", fmt.Errorf("hermes: create %s: %w", dir, err)
	}

	var backupPath string
	if backup && c.existed {
		bp, err := rotateExisting(c.path)
		if err != nil {
			return "", err
		}
		backupPath = bp
	}

	out, err := yaml.Marshal(c.root)
	if err != nil {
		return "", fmt.Errorf("hermes: marshal config: %w", err)
	}
	if err := writeFileAtomic(c.path, out); err != nil {
		return "", err
	}
	c.existed = true
	return backupPath, nil
}

// backend returns the configured terminal backend, defaulting to "local"
// when the terminal section or backend key is absent.
func (c *hermesConfig) backend() string {
	term, ok := c.root[terminalKey].(map[string]interface{})
	if !ok {
		return "local"
	}
	b, ok := term[backendKey].(string)
	if !ok || b == "" {
		return "local"
	}
	return b
}

// injectTerminalEnv adds the pipelock proxy env names to terminal.env_passthrough
// (and docker_forward_env when the backend is docker), additively and without
// duplicates. Returns the names newly added (empty when already present).
func (c *hermesConfig) injectTerminalEnv() []string {
	term, ok := c.root[terminalKey].(map[string]interface{})
	if !ok {
		term = map[string]interface{}{}
		c.root[terminalKey] = term
	}

	added := mergeStringList(term, envPassthroughKey, proxyEnvNames)
	if c.backend() == backendDocker {
		// docker_forward_env additions are reported too, deduped against
		// what env_passthrough already added so the caller sees each name once.
		dockerAdded := mergeStringList(term, dockerForwardEnvKey, proxyEnvNames)
		added = unionStrings(added, dockerAdded)
	}
	return added
}

// removeTerminalEnv removes the pipelock proxy env names from both
// terminal.env_passthrough and docker_forward_env. Returns the names removed.
// Lists that become empty are deleted; an empty terminal section is left in
// place (it may hold operator settings we never touched).
func (c *hermesConfig) removeTerminalEnv() []string {
	term, ok := c.root[terminalKey].(map[string]interface{})
	if !ok {
		return nil
	}
	removed := removeStringList(term, envPassthroughKey, proxyEnvNames)
	dockerRemoved := removeStringList(term, dockerForwardEnvKey, proxyEnvNames)
	return unionStrings(removed, dockerRemoved)
}

// terminalEnvPresent reports the proxy env names currently present in
// terminal.env_passthrough. Used by verify.
func (c *hermesConfig) terminalEnvPresent() []string {
	term, ok := c.root[terminalKey].(map[string]interface{})
	if !ok {
		return nil
	}
	envHave := toStringSet(term[envPassthroughKey])
	dockerHave := toStringSet(term[dockerForwardEnvKey])
	requireDockerForward := c.backend() == backendDocker

	var present []string
	for _, name := range proxyEnvNames {
		if !envHave[name] {
			continue
		}
		if requireDockerForward && !dockerHave[name] {
			continue
		}
		present = append(present, name)
	}
	return present
}

// terminalEnvPassthroughPresent reports proxy names present in only
// terminal.env_passthrough. Tests use it to distinguish the raw Hermes field
// from terminalEnvPresent's backend-effective view.
func (c *hermesConfig) terminalEnvPassthroughPresent() []string {
	term, ok := c.root[terminalKey].(map[string]interface{})
	if !ok {
		return nil
	}
	have := toStringSet(term[envPassthroughKey])
	var present []string
	for _, name := range proxyEnvNames {
		if have[name] {
			present = append(present, name)
		}
	}
	return present
}

// noProxyValue returns the configured NO_PROXY-equivalent value if the
// operator set it as an actual value (not just passthrough name) anywhere we
// can see it. Hermes config only forwards names, so this inspects the process
// environment the install/verify run sees. Returns "" when unset.
func noProxyValue() string {
	for _, k := range []string{"NO_PROXY", "no_proxy"} {
		if v := os.Getenv(k); v != "" {
			return v
		}
	}
	return ""
}

// mcpServers returns the live mcp_servers map from the config, or nil when the
// section is absent or malformed. Mutations to the returned map (or its server
// entries) are reflected by save().
func (c *hermesConfig) mcpServers() map[string]interface{} {
	servers, _ := c.root[mcpServersKey].(map[string]interface{})
	return servers
}

// pluginsSection returns the plugins mapping. When create is true and the
// section is absent it is created. An existing plugins value that is not a
// mapping is an error: Hermes ignores a malformed plugins section entirely
// (opt-in default), and silently overwriting operator config we cannot parse
// would be surprising and could disable plugins they enabled by hand.
func (c *hermesConfig) pluginsSection(create bool) (map[string]interface{}, error) {
	raw, ok := c.root[pluginsKey]
	if !ok || raw == nil {
		if !create {
			return nil, nil
		}
		m := map[string]interface{}{}
		c.root[pluginsKey] = m
		return m, nil
	}
	m, ok := raw.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("hermes: config %s has a non-mapping %q section; refusing to edit %s.%s",
			c.path, pluginsKey, pluginsKey, enabledKey)
	}
	return m, nil
}

// enablePlugin ensures the pipelock plugin is present in plugins.enabled,
// additively (existing entries are preserved). Returns whether it was newly
// added.
func (c *hermesConfig) enablePlugin() (bool, error) {
	plugins, err := c.pluginsSection(true)
	if err != nil {
		return false, err
	}
	current, err := c.enabledPlugins(plugins)
	if err != nil {
		return false, err
	}
	for _, name := range current {
		if name == pluginRegistryName {
			return false, nil
		}
	}
	current = append(current, pluginRegistryName)
	plugins[enabledKey] = toInterfaceSlice(current)
	return true, nil
}

// disablePlugin removes the pipelock plugin from plugins.enabled. Returns
// whether it was present. removeStringList deletes the enabled key when the
// list empties; an otherwise-empty plugins section is left in place (it may
// hold operator keys).
func (c *hermesConfig) disablePlugin() (bool, error) {
	plugins, err := c.pluginsSection(false)
	if err != nil {
		return false, err
	}
	if plugins == nil {
		return false, nil
	}
	current, err := c.enabledPlugins(plugins)
	if err != nil {
		return false, err
	}
	if len(current) == 0 {
		return false, nil
	}
	kept := current[:0]
	removed := false
	for _, name := range current {
		if name == pluginRegistryName {
			removed = true
			continue
		}
		kept = append(kept, name)
	}
	if !removed {
		return false, nil
	}
	if len(kept) == 0 {
		delete(plugins, enabledKey)
	} else {
		plugins[enabledKey] = toInterfaceSlice(kept)
	}
	return true, nil
}

// pluginEnabled reports whether the pipelock plugin appears in plugins.enabled.
// Mirrors Hermes' gating: a malformed/absent section means nothing is enabled.
func (c *hermesConfig) pluginEnabled() bool {
	plugins, ok := c.root[pluginsKey].(map[string]interface{})
	if !ok {
		return false
	}
	return toStringSet(plugins[enabledKey])[pluginRegistryName]
}

// enabledPlugins returns plugins.enabled as a strict string list. This is
// deliberately stricter than mergeStringList: silently replacing a malformed
// enabled list could disable operator-managed plugins we cannot preserve.
func (c *hermesConfig) enabledPlugins(plugins map[string]interface{}) ([]string, error) {
	raw, ok := plugins[enabledKey]
	if !ok || raw == nil {
		return nil, nil
	}
	items, ok := raw.([]interface{})
	if !ok {
		return nil, fmt.Errorf("hermes: config %s has a non-list %s.%s; refusing to edit plugin enablement",
			c.path, pluginsKey, enabledKey)
	}
	out := make([]string, 0, len(items))
	for i, item := range items {
		s, ok := item.(string)
		if !ok {
			return nil, fmt.Errorf("hermes: config %s has a non-string entry at %s.%s[%d]; refusing to edit plugin enablement",
				c.path, pluginsKey, enabledKey, i)
		}
		out = append(out, s)
	}
	return out, nil
}

// wrappedMCPServerCount counts mcp_servers entries already wrapped by pipelock.
func (c *hermesConfig) wrappedMCPServerCount() int {
	n := 0
	for _, raw := range c.mcpServers() {
		if s, ok := raw.(map[string]interface{}); ok && mcpwrap.IsWrapped(s) {
			n++
		}
	}
	return n
}

// sortedKeys returns the map keys sorted, for deterministic iteration so wrap
// output and sidecar ordering are stable across runs.
func sortedKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// mergeStringList ensures every value in add is present in m[key], which is
// treated as a YAML string list. Missing or non-list values are replaced with
// a fresh list. Returns the values newly appended.
func mergeStringList(m map[string]interface{}, key string, add []string) []string {
	have := toStringSet(m[key])
	current := toStringSlice(m[key])

	var added []string
	for _, v := range add {
		if !have[v] {
			current = append(current, v)
			have[v] = true
			added = append(added, v)
		}
	}
	if len(added) > 0 || m[key] != nil {
		m[key] = toInterfaceSlice(current)
	}
	return added
}

// removeStringList removes every value in del from m[key]. Deletes the key
// entirely when the resulting list is empty. Returns the values removed.
func removeStringList(m map[string]interface{}, key string, del []string) []string {
	current := toStringSlice(m[key])
	if len(current) == 0 {
		return nil
	}
	delSet := make(map[string]bool, len(del))
	for _, d := range del {
		delSet[d] = true
	}

	var kept, removed []string
	for _, v := range current {
		if delSet[v] {
			removed = append(removed, v)
			continue
		}
		kept = append(kept, v)
	}
	if len(removed) == 0 {
		return nil
	}
	if len(kept) == 0 {
		delete(m, key)
	} else {
		m[key] = toInterfaceSlice(kept)
	}
	return removed
}

// toStringSlice coerces a YAML-decoded value into a []string, dropping
// non-string elements. yaml.v3 decodes lists as []interface{}.
func toStringSlice(v interface{}) []string {
	items, ok := v.([]interface{})
	if !ok {
		return nil
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func toStringSet(v interface{}) map[string]bool {
	out := map[string]bool{}
	for _, s := range toStringSlice(v) {
		out[s] = true
	}
	return out
}

func toInterfaceSlice(in []string) []interface{} {
	out := make([]interface{}, len(in))
	for i, s := range in {
		out[i] = s
	}
	return out
}

// unionStrings returns the sorted unique union of two string slices.
func unionStrings(a, b []string) []string {
	set := map[string]bool{}
	for _, s := range a {
		set[s] = true
	}
	for _, s := range b {
		set[s] = true
	}
	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}
