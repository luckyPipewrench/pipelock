// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package hermes

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadHermesConfig_Missing(t *testing.T) {
	t.Parallel()

	cfg, err := loadHermesConfig(filepath.Join(t.TempDir(), "nope.yaml"))
	if err != nil {
		t.Fatalf("loadHermesConfig(missing): %v", err)
	}
	if cfg.existed {
		t.Fatal("missing file reported as existed")
	}
	if len(cfg.root) != 0 {
		t.Fatalf("missing file produced non-empty root: %v", cfg.root)
	}
}

func TestLoadHermesConfig_Unparseable(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "bad.yaml")
	if err := os.WriteFile(path, []byte("\tnot: [valid"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := loadHermesConfig(path); err == nil {
		t.Fatal("unparseable config did not error")
	}
}

func TestHermesConfig_SaveRoundTripPreservesUnknownKeys(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "config.yaml")
	seed := "model: gpt-4\ncustom:\n  nested: keep-me\n"
	if err := os.WriteFile(path, []byte(seed), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}

	cfg, err := loadHermesConfig(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	cfg.injectTerminalEnv()
	backup, err := cfg.save(true)
	if err != nil {
		t.Fatalf("save: %v", err)
	}
	if backup == "" {
		t.Fatal("save of existing file produced no backup")
	}

	reloaded, err := loadHermesConfig(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if reloaded.root["model"] != "gpt-4" {
		t.Fatalf("model key lost: %v", reloaded.root["model"])
	}
	custom, ok := reloaded.root["custom"].(map[string]interface{})
	if !ok || custom["nested"] != "keep-me" {
		t.Fatalf("custom nested key lost: %v", reloaded.root["custom"])
	}
}

func TestHermesConfig_InjectLocalBackend(t *testing.T) {
	t.Parallel()

	cfg := &hermesConfig{root: map[string]interface{}{}}
	added := cfg.injectTerminalEnv()
	if len(added) != len(proxyEnvNames) {
		t.Fatalf("added %d names, want %d", len(added), len(proxyEnvNames))
	}
	if cfg.backend() != "local" {
		t.Fatalf("backend = %q, want local", cfg.backend())
	}
	// Idempotent: second call adds nothing.
	if again := cfg.injectTerminalEnv(); len(again) != 0 {
		t.Fatalf("re-inject added %d names, want 0", len(again))
	}
}

func TestHermesConfig_InjectDockerBackendAddsForwardEnv(t *testing.T) {
	t.Parallel()

	cfg := &hermesConfig{root: map[string]interface{}{
		terminalKey: map[string]interface{}{backendKey: backendDocker},
	}}
	cfg.injectTerminalEnv()

	term := cfg.root[terminalKey].(map[string]interface{})
	if _, ok := term[dockerForwardEnvKey]; !ok {
		t.Fatal("docker backend did not get docker_forward_env")
	}
	if got := len(toStringSlice(term[dockerForwardEnvKey])); got != len(proxyEnvNames) {
		t.Fatalf("docker_forward_env has %d, want %d", got, len(proxyEnvNames))
	}
	if got := len(cfg.terminalEnvPresent()); got != len(proxyEnvNames) {
		t.Fatalf("effective docker env present = %d, want %d", got, len(proxyEnvNames))
	}
}

func TestHermesConfig_DockerEffectiveEnvRequiresForwardEnv(t *testing.T) {
	t.Parallel()

	env := make([]interface{}, len(proxyEnvNames))
	for i, name := range proxyEnvNames {
		env[i] = name
	}
	cfg := &hermesConfig{root: map[string]interface{}{
		terminalKey: map[string]interface{}{
			backendKey:        backendDocker,
			envPassthroughKey: env,
		},
	}}

	if got := len(cfg.terminalEnvPassthroughPresent()); got != len(proxyEnvNames) {
		t.Fatalf("raw env_passthrough present = %d, want %d", got, len(proxyEnvNames))
	}
	if got := cfg.terminalEnvPresent(); len(got) != 0 {
		t.Fatalf("effective docker env present without docker_forward_env = %v, want none", got)
	}
}

func TestHermesConfig_InjectPreservesExistingEntries(t *testing.T) {
	t.Parallel()

	cfg := &hermesConfig{root: map[string]interface{}{
		terminalKey: map[string]interface{}{
			envPassthroughKey: []interface{}{"GITHUB_TOKEN"},
		},
	}}
	cfg.injectTerminalEnv()

	term := cfg.root[terminalKey].(map[string]interface{})
	got := toStringSet(term[envPassthroughKey])
	if !got["GITHUB_TOKEN"] {
		t.Fatal("pre-existing GITHUB_TOKEN was dropped")
	}
	if !got["HTTPS_PROXY"] {
		t.Fatal("HTTPS_PROXY not added")
	}
}

func TestHermesConfig_RemoveTerminalEnv(t *testing.T) {
	t.Parallel()

	cfg := &hermesConfig{root: map[string]interface{}{}}
	cfg.injectTerminalEnv()
	// Seed an operator entry that must survive removal.
	term := cfg.root[terminalKey].(map[string]interface{})
	term[envPassthroughKey] = append([]interface{}{"GITHUB_TOKEN"}, term[envPassthroughKey].([]interface{})...)

	removed := cfg.removeTerminalEnv()
	if len(removed) == 0 {
		t.Fatal("removeTerminalEnv removed nothing")
	}
	remaining := toStringSet(cfg.root[terminalKey].(map[string]interface{})[envPassthroughKey])
	if !remaining["GITHUB_TOKEN"] {
		t.Fatal("removal dropped the operator's GITHUB_TOKEN")
	}
	if remaining["HTTPS_PROXY"] {
		t.Fatal("HTTPS_PROXY survived removal")
	}
}

func TestHermesConfig_RemoveEmptiesDeletesKey(t *testing.T) {
	t.Parallel()

	cfg := &hermesConfig{root: map[string]interface{}{}}
	cfg.injectTerminalEnv()
	cfg.removeTerminalEnv()

	term := cfg.root[terminalKey].(map[string]interface{})
	if _, ok := term[envPassthroughKey]; ok {
		t.Fatal("env_passthrough key should be deleted when fully emptied")
	}
}

func TestStringListHelpers(t *testing.T) {
	t.Parallel()

	if got := toStringSlice([]interface{}{"a", 1, "b"}); len(got) != 2 {
		t.Fatalf("toStringSlice dropped non-strings wrong: %v", got)
	}
	if got := toStringSlice("not a list"); got != nil {
		t.Fatalf("toStringSlice(non-list) = %v, want nil", got)
	}
	u := unionStrings([]string{"b", "a"}, []string{"a", "c"})
	if len(u) != 3 || u[0] != "a" || u[2] != "c" {
		t.Fatalf("unionStrings sorted-unique wrong: %v", u)
	}
}

func TestHermesConfig_EnablePlugin_CreatesSection(t *testing.T) {
	t.Parallel()

	cfg := &hermesConfig{root: map[string]interface{}{}}
	if cfg.pluginEnabled() {
		t.Fatal("plugin reported enabled on empty config")
	}
	added, err := cfg.enablePlugin()
	if err != nil {
		t.Fatalf("enablePlugin: %v", err)
	}
	if !added {
		t.Fatal("enablePlugin reported no change on first enable")
	}
	if !cfg.pluginEnabled() {
		t.Fatal("plugin not enabled after enablePlugin")
	}
	// Idempotent: a second enable reports no change.
	again, err := cfg.enablePlugin()
	if err != nil {
		t.Fatalf("re-enable: %v", err)
	}
	if again {
		t.Fatal("re-enable falsely reported a change")
	}
}

func TestHermesConfig_EnablePlugin_PreservesOtherPlugins(t *testing.T) {
	t.Parallel()

	cfg := &hermesConfig{root: map[string]interface{}{
		pluginsKey: map[string]interface{}{
			enabledKey: []interface{}{"disk-cleanup", "image_gen/openai"},
		},
	}}
	if _, err := cfg.enablePlugin(); err != nil {
		t.Fatalf("enablePlugin: %v", err)
	}
	plugins := cfg.root[pluginsKey].(map[string]interface{})
	got := toStringSet(plugins[enabledKey])
	for _, want := range []string{"disk-cleanup", "image_gen/openai", pluginRegistryName} {
		if !got[want] {
			t.Fatalf("enabled set missing %q: %v", want, got)
		}
	}
}

func TestHermesConfig_DisablePlugin_RemovesOnlyPipelock(t *testing.T) {
	t.Parallel()

	cfg := &hermesConfig{root: map[string]interface{}{
		pluginsKey: map[string]interface{}{
			enabledKey: []interface{}{"disk-cleanup", pluginRegistryName},
		},
	}}
	removed, err := cfg.disablePlugin()
	if err != nil {
		t.Fatalf("disablePlugin: %v", err)
	}
	if !removed {
		t.Fatal("disablePlugin reported nothing removed")
	}
	if cfg.pluginEnabled() {
		t.Fatal("plugin still enabled after disable")
	}
	plugins := cfg.root[pluginsKey].(map[string]interface{})
	if !toStringSet(plugins[enabledKey])["disk-cleanup"] {
		t.Fatal("disable dropped the operator's other plugin")
	}
}

func TestHermesConfig_DisablePlugin_AbsentIsNoOp(t *testing.T) {
	t.Parallel()

	cfg := &hermesConfig{root: map[string]interface{}{}}
	removed, err := cfg.disablePlugin()
	if err != nil {
		t.Fatalf("disablePlugin on empty config: %v", err)
	}
	if removed {
		t.Fatal("disablePlugin falsely reported a removal on empty config")
	}
}

func TestHermesConfig_PluginsSection_MalformedErrors(t *testing.T) {
	t.Parallel()

	// A non-mapping plugins value (a list here) must not be silently
	// clobbered: refuse to edit and surface an error.
	cfg := &hermesConfig{path: "config.yaml", root: map[string]interface{}{
		pluginsKey: []interface{}{"oops-this-is-a-list"},
	}}
	if _, err := cfg.enablePlugin(); err == nil {
		t.Fatal("enablePlugin did not error on a non-mapping plugins section")
	}
	if _, err := cfg.disablePlugin(); err == nil {
		t.Fatal("disablePlugin did not error on a non-mapping plugins section")
	}
	// A malformed section means nothing is enabled, per Hermes' own gating.
	if cfg.pluginEnabled() {
		t.Fatal("pluginEnabled true for a malformed plugins section")
	}
}

func TestHermesConfig_EnabledListMalformedErrors(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		root map[string]interface{}
	}{
		{
			name: "scalar enabled value",
			root: map[string]interface{}{
				pluginsKey: map[string]interface{}{
					enabledKey: "disk-cleanup",
				},
			},
		},
		{
			name: "non-string enabled entry",
			root: map[string]interface{}{
				pluginsKey: map[string]interface{}{
					enabledKey: []interface{}{"disk-cleanup", 7},
				},
			},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			cfg := &hermesConfig{path: "config.yaml", root: tc.root}
			if _, err := cfg.enablePlugin(); err == nil {
				t.Fatal("enablePlugin did not error on malformed plugins.enabled")
			}
			if _, err := cfg.disablePlugin(); err == nil {
				t.Fatal("disablePlugin did not error on malformed plugins.enabled")
			}
		})
	}
}

func TestResolveDefaultHermesConfig(t *testing.T) {
	t.Parallel()

	got := ResolveDefaultHermesConfig("/home/agent")
	want := filepath.Join("/home/agent", DefaultHermesConfigSubpath)
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}
