// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"context"
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// contractEnvMap collapses the ordered contract into name->value for lookup.
func contractEnvMap(env *installEnv) map[string]string {
	m := make(map[string]string)
	for _, v := range runtimeContractVars(env) {
		m[v.name] = v.value
	}
	return m
}

func TestRuntimeContractVars_CoversAllSurfaces(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	m := contractEnvMap(env)
	proxy := "http://127.0.0.1:8888"

	wantProxy := []string{
		"HTTP_PROXY", "http_proxy",
		"HTTPS_PROXY", "https_proxy",
		"ALL_PROXY", "all_proxy",
	}
	for _, name := range wantProxy {
		if m[name] != proxy {
			t.Errorf("%s = %q, want %q", name, m[name], proxy)
		}
	}
	if m["NO_PROXY"] != contractNoProxy || m["no_proxy"] != contractNoProxy {
		t.Errorf("NO_PROXY/no_proxy = %q/%q, want %q", m["NO_PROXY"], m["no_proxy"], contractNoProxy)
	}
	if !strings.Contains(contractNoProxy, "::1") {
		t.Errorf("contractNoProxy %q missing IPv6 loopback ::1", contractNoProxy)
	}

	caBundleVars := []string{"SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "GIT_SSL_CAINFO", "CARGO_HTTP_CAINFO", "PIP_CERT"}
	for _, name := range caBundleVars {
		if m[name] != env.caBundlePath {
			t.Errorf("%s = %q, want CA bundle %q", name, m[name], env.caBundlePath)
		}
	}
	if m["NODE_EXTRA_CA_CERTS"] != env.caExportPath {
		t.Errorf("NODE_EXTRA_CA_CERTS = %q, want node CA %q", m["NODE_EXTRA_CA_CERTS"], env.caExportPath)
	}
	if want := "--require " + env.undiciShimPath; m["NODE_OPTIONS"] != want {
		t.Errorf("NODE_OPTIONS = %q, want %q", m["NODE_OPTIONS"], want)
	}
	if m["NODE_USE_ENV_PROXY"] != "1" {
		t.Errorf("NODE_USE_ENV_PROXY = %q, want 1", m["NODE_USE_ENV_PROXY"])
	}
}

func TestRuntimeContractVars_UppercaseNoProxyPrecedesLowercase(t *testing.T) {
	// verify's extractNoProxy keys off the first NO_PROXY= assignment; the
	// canonical uppercase form must come first.
	env, _, _ := newFakeEnv(t)
	upper, lower := -1, -1
	for i, v := range runtimeContractVars(env) {
		switch v.name {
		case "NO_PROXY":
			upper = i
		case "no_proxy":
			lower = i
		}
	}
	if upper == -1 || lower == -1 {
		t.Fatalf("missing NO_PROXY assignments: upper=%d lower=%d", upper, lower)
	}
	if upper >= lower {
		t.Errorf("NO_PROXY (idx %d) must precede no_proxy (idx %d)", upper, lower)
	}
}

func TestShellSafeValue(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"http://127.0.0.1:8888", true},
		{"/etc/pipelock/combined-ca.pem", true},
		{"127.0.0.1,localhost,::1", true},
		{"--require /etc/pipelock/contain/undici-shim.cjs", false}, // space
		{"a b", false},
		{"", false},
		{"a'b", false},
		{"a$b", false},
	}
	for _, c := range cases {
		if got := shellSafeValue(c.in); got != c.want {
			t.Errorf("shellSafeValue(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestEnvAssign_QuotesUnsafeValues(t *testing.T) {
	if got := envAssign("HTTPS_PROXY", "http://127.0.0.1:8888"); got != "HTTPS_PROXY=http://127.0.0.1:8888" {
		t.Errorf("safe value got %q", got)
	}
	got := envAssign("NODE_OPTIONS", "--require /x/shim.cjs")
	if !strings.HasPrefix(got, "NODE_OPTIONS='") || !strings.Contains(got, "--require /x/shim.cjs") {
		t.Errorf("unsafe value not single-quoted: %q", got)
	}
}

func TestLaunchExecEnvLines_Shape(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	lines := launchExecEnvLines(env)
	joined := strings.Join(lines, "\n")
	if lines[0] != "exec env \\" {
		t.Errorf("first line = %q, want 'exec env \\'", lines[0])
	}
	for _, want := range []string{
		"HOME=" + agentHomeDir(env),
		"HTTPS_PROXY=http://127.0.0.1:8888",
		`PATH="$AGENT_PATH"`,
		`"$TARGET" "$@"`,
		"NODE_OPTIONS='--require " + env.undiciShimPath + "'",
		"NODE_USE_ENV_PROXY=1",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("launch exec env missing %q", want)
		}
	}
	// Every continuation line except the last must end with a backslash.
	for i, l := range lines[:len(lines)-1] {
		if !strings.HasSuffix(l, "\\") {
			t.Errorf("line %d %q lacks trailing backslash", i, l)
		}
	}
}

func TestRenderProfileScript_ParsesUnderBashAndExports(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	body := renderProfileScript(env)
	for _, want := range []string{
		"if [ \"$_pipelock_contain_user\" != 'pipelock-agent' ]; then",
		"export HTTPS_PROXY=",
		"export NO_PROXY=",
		"export NODE_OPTIONS=",
		"export NODE_USE_ENV_PROXY=",
		"export PATH",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("profile script missing %q", want)
		}
	}
	if _, err := os.Stat("/bin/bash"); err != nil {
		t.Skip("bash unavailable")
	}
	tmp := filepath.Join(t.TempDir(), "pipelock-contain.sh")
	writeScriptFixture(t, tmp, body)
	if res := execRealCommand(t, "/bin/bash", "-n", tmp); res.exit != 0 {
		t.Fatalf("bash -n rejected profile script:\n%s\n--- script ---\n%s", res.output, body)
	}
}

func TestRenderProfileScript_DoesNotAffectNonAgentLoginShell(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	tmp := filepath.Join(t.TempDir(), "pipelock-contain.sh")
	writeScriptFixture(t, tmp, renderProfileScript(env))
	res := execRealCommand(t, "/bin/bash", "-c", "unset HTTPS_PROXY NODE_OPTIONS NODE_USE_ENV_PROXY; source "+shellQuote(tmp)+"; printf '%s|%s|%s' \"${HTTPS_PROXY:-}\" \"${NODE_OPTIONS:-}\" \"${NODE_USE_ENV_PROXY:-}\"")
	if res.exit != 0 {
		t.Fatalf("source profile script: %s", res.output)
	}
	if got := strings.TrimSpace(res.output); got != "||" {
		t.Fatalf("non-agent shell inherited contract: %q", got)
	}
}

func TestRenderProfileScript_AppliesToAgentLoginShell(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	dir := t.TempDir()
	fakeID := filepath.Join(dir, "id")
	if err := os.WriteFile(fakeID, []byte("#!/bin/sh\nprintf '%s\\n' pipelock-agent\n"), 0o700); err != nil { //nolint:gosec // test helper must be executable so the sourced profile script finds it via PATH.
		t.Fatalf("write fake id: %v", err)
	}
	tmp := filepath.Join(dir, "pipelock-contain.sh")
	writeScriptFixture(t, tmp, renderProfileScript(env))

	script := "PATH=" + shellQuote(dir+":/usr/bin:/bin") + "; unset HTTPS_PROXY NODE_OPTIONS NODE_USE_ENV_PROXY; source " + shellQuote(tmp) + "; printf '%s|%s|%s|%s' \"$HTTPS_PROXY\" \"$NODE_OPTIONS\" \"$NODE_USE_ENV_PROXY\" \"$PATH\""
	res := execRealCommand(t, "/bin/bash", "-c", script)
	if res.exit != 0 {
		t.Fatalf("source profile script: %s", res.output)
	}
	out := strings.TrimSpace(res.output)
	if !strings.Contains(out, "http://127.0.0.1:8888|--require "+env.undiciShimPath+"|1|"+agentExecPath(env.agentUserName)) {
		t.Fatalf("agent shell did not inherit expected contract: %q", out)
	}
}

func TestRenderUndiciShim_HasGlobalDispatcher(t *testing.T) {
	shim := renderUndiciShim()
	for _, want := range []string{"setGlobalDispatcher", "ProxyAgent", "require('undici')", "try {", "catch"} {
		if !strings.Contains(shim, want) {
			t.Errorf("undici shim missing %q", want)
		}
	}
	// Validate JS syntax if node is available.
	if _, err := os.Stat("/usr/bin/node"); err != nil {
		if _, err := os.Stat("/usr/local/bin/node"); err != nil {
			t.Skip("node unavailable for --check")
		}
	}
	tmp := filepath.Join(t.TempDir(), "undici-shim.cjs")
	if err := os.WriteFile(tmp, []byte(shim), 0o600); err != nil {
		t.Fatalf("write shim: %v", err)
	}
	res := execRealCommand(t, "node", "--check", tmp)
	if res.exit != 0 {
		t.Fatalf("node --check rejected shim:\n%s", res.output)
	}
}

func TestRenderUtilityWrapper_ParsesUnderBash(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	for _, name := range pipelockUtilityWrappers {
		tool, ok := realToolForUtilityWrapper(name)
		if !ok {
			t.Fatalf("no tool mapping for %s", name)
		}
		body := renderUtilityWrapper(env, tool)
		for _, want := range []string{
			"command -v " + tool,
			"exec env \\",
			`"$BIN" "$@"`,
			"HTTPS_PROXY=http://127.0.0.1:8888",
		} {
			if !strings.Contains(body, want) {
				t.Errorf("%s wrapper missing %q", name, want)
			}
		}
		if _, err := os.Stat("/bin/bash"); err == nil {
			tmp := filepath.Join(t.TempDir(), name)
			writeScriptFixture(t, tmp, body)
			if res := execRealCommand(t, "/bin/bash", "-n", tmp); res.exit != 0 {
				t.Fatalf("bash -n rejected %s:\n%s\n--- script ---\n%s", name, res.output, body)
			}
		}
	}
}

func TestRealToolForUtilityWrapper(t *testing.T) {
	cases := map[string]string{
		"pipelock-curl":   "curl",
		"pipelock-python": "python3",
		"pipelock-node":   "node",
	}
	for name, want := range cases {
		got, ok := realToolForUtilityWrapper(name)
		if !ok || got != want {
			t.Errorf("realToolForUtilityWrapper(%q) = %q,%v want %q,true", name, got, ok, want)
		}
	}
	if _, ok := realToolForUtilityWrapper("pipelock-bogus"); ok {
		t.Errorf("unknown wrapper unexpectedly mapped")
	}
}

func TestRenderAgentToolConfigs_HaveProxyAndCA(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	proxy := "http://127.0.0.1:8888"
	cases := []struct {
		name   string
		body   string
		proxy  string
		caHint string
	}{
		{"gitconfig", renderAgentGitConfig(env), proxy, env.caBundlePath},
		{"npmrc", renderAgentNpmrc(env), proxy, env.caBundlePath},
		{"pip.conf", renderAgentPipConf(env), proxy, env.caBundlePath},
		{"cargo", renderAgentCargoConfig(env), proxy, env.caBundlePath},
	}
	for _, c := range cases {
		if !strings.Contains(c.body, c.proxy) {
			t.Errorf("%s missing proxy %q:\n%s", c.name, c.proxy, c.body)
		}
		if !strings.Contains(c.body, c.caHint) {
			t.Errorf("%s missing CA %q:\n%s", c.name, c.caHint, c.body)
		}
	}
}

func TestAgentHomeDir_OverrideAndDefault(t *testing.T) {
	env := &installEnv{agentUserName: "pipelock-agent"}
	if got := agentHomeDir(env); got != "/home/pipelock-agent" {
		t.Errorf("default agentHomeDir = %q", got)
	}
	env.agentHome = "/tmp/agenthome"
	if got := agentHomeDir(env); got != "/tmp/agenthome" {
		t.Errorf("override agentHomeDir = %q", got)
	}
}

// ---------------------------------------------------------------------------
// Install step tests.
// ---------------------------------------------------------------------------

func TestStepWriteUndiciShim_WritesIdempotentAndUndo(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	s := stepWriteUndiciShim()

	applied, err := s.apply(context.Background(), env)
	if err != nil || !applied {
		t.Fatalf("first apply: applied=%v err=%v", applied, err)
	}
	data, err := os.ReadFile(env.undiciShimPath)
	if err != nil {
		t.Fatalf("read shim: %v", err)
	}
	if !strings.Contains(string(data), "setGlobalDispatcher") {
		t.Errorf("shim content unexpected:\n%s", data)
	}

	// Second apply is a no-op (idempotent).
	applied, err = s.apply(context.Background(), env)
	if err != nil || applied {
		t.Fatalf("idempotent apply: applied=%v err=%v", applied, err)
	}

	if err := s.undo(context.Background(), env); err != nil {
		t.Fatalf("undo: %v", err)
	}
	if _, err := os.Stat(env.undiciShimPath); err == nil {
		t.Errorf("shim survived undo")
	}
}

func TestStepWriteProfileScript_WritesIdempotent(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	s := stepWriteProfileScript()

	applied, err := s.apply(context.Background(), env)
	if err != nil || !applied {
		t.Fatalf("first apply: applied=%v err=%v", applied, err)
	}
	if _, err := os.Stat(env.profileScriptPath); err != nil {
		t.Fatalf("profile not written: %v", err)
	}
	applied, err = s.apply(context.Background(), env)
	if err != nil || applied {
		t.Fatalf("idempotent apply: applied=%v err=%v", applied, err)
	}
}

func TestStepWriteProfileScript_FailsWhenAgentMissing(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	env.lookupUser = func(name string) (*user.User, error) { return nil, user.UnknownUserError(name) }
	if _, err := stepWriteProfileScript().apply(context.Background(), env); err == nil {
		t.Fatalf("expected error when agent group unresolvable")
	}
}

func TestStepWriteProfileScript_RerunReassertsModeAndSurfacesErrors(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	s := stepWriteProfileScript()
	if _, err := s.apply(context.Background(), env); err != nil {
		t.Fatalf("first apply: %v", err)
	}
	// Rerun with a failing chmod must surface the error (mode re-enforcement).
	env.chmod = func(string, os.FileMode) error { return errors.New("ro fs") }
	if _, err := s.apply(context.Background(), env); err == nil {
		t.Fatalf("expected idempotent chmod error to surface")
	}
}

func TestRuntimeSteps_RerunChmodErrorsSurface(t *testing.T) {
	failChmod := func(string, os.FileMode) error { return errors.New("ro fs") }

	t.Run("undici shim", func(t *testing.T) {
		env, _, _ := newFakeEnv(t)
		s := stepWriteUndiciShim()
		if _, err := s.apply(context.Background(), env); err != nil {
			t.Fatalf("first apply: %v", err)
		}
		env.chmod = failChmod
		if _, err := s.apply(context.Background(), env); err == nil {
			t.Fatalf("expected idempotent chmod error")
		}
	})
	t.Run("utility wrappers", func(t *testing.T) {
		env, _, _ := newFakeEnv(t)
		if err := os.MkdirAll(env.wrapperDir, 0o750); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		s := stepWriteUtilityWrappers()
		if _, err := s.apply(context.Background(), env); err != nil {
			t.Fatalf("first apply: %v", err)
		}
		env.chmod = failChmod
		if _, err := s.apply(context.Background(), env); err == nil {
			t.Fatalf("expected idempotent chmod error")
		}
	})
	t.Run("agent configs", func(t *testing.T) {
		env, _, _ := newFakeEnv(t)
		s := stepWriteAgentToolConfigs()
		if _, err := s.apply(context.Background(), env); err != nil {
			t.Fatalf("first apply: %v", err)
		}
		env.lchown = func(string, int, int) error { return errors.New("ro fs") }
		if _, err := s.apply(context.Background(), env); err == nil {
			t.Fatalf("expected idempotent lchown error")
		}
	})
}

func TestStepWriteUtilityWrappers_WritesAllThree(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	if err := os.MkdirAll(env.wrapperDir, 0o750); err != nil {
		t.Fatalf("mkdir wrapperDir: %v", err)
	}
	s := stepWriteUtilityWrappers()
	applied, err := s.apply(context.Background(), env)
	if err != nil || !applied {
		t.Fatalf("apply: applied=%v err=%v", applied, err)
	}
	for _, name := range pipelockUtilityWrappers {
		p := filepath.Join(env.wrapperDir, name)
		if _, err := os.Stat(p); err != nil {
			t.Errorf("wrapper %s not written: %v", name, err)
		}
	}
	// Idempotent re-apply.
	applied, err = s.apply(context.Background(), env)
	if err != nil || applied {
		t.Fatalf("idempotent apply: applied=%v err=%v", applied, err)
	}
	if err := s.undo(context.Background(), env); err != nil {
		t.Fatalf("undo: %v", err)
	}
}

func TestStepWriteAgentToolConfigs_WritesAndChowns(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	env.chown = func(path string, _, _ int) error {
		t.Fatalf("agent config path used symlink-following chown: %s", path)
		return nil
	}
	var lchowned []string
	env.lchown = func(path string, _, _ int) error {
		lchowned = append(lchowned, filepath.Clean(path))
		return nil
	}

	s := stepWriteAgentToolConfigs()
	applied, err := s.apply(context.Background(), env)
	if err != nil || !applied {
		t.Fatalf("apply: applied=%v err=%v", applied, err)
	}
	for _, cfg := range agentToolConfigs() {
		p := filepath.Join(env.agentHome, cfg.rel)
		if _, err := os.Stat(p); err != nil {
			t.Errorf("config %s not written: %v", cfg.rel, err)
		}
	}
	if len(lchowned) == 0 {
		t.Errorf("expected lchown calls for agent-owned configs")
	}
	for _, want := range []string{
		env.agentHome,
		filepath.Join(env.agentHome, ".config"),
		filepath.Join(env.agentHome, ".config", "pip"),
		filepath.Join(env.agentHome, ".cargo"),
	} {
		if !slices.Contains(lchowned, filepath.Clean(want)) {
			t.Errorf("expected lchown for %s; got %v", want, lchowned)
		}
	}
	for _, cfg := range agentToolConfigs() {
		want := filepath.Join(env.agentHome, cfg.rel)
		if !slices.Contains(lchowned, filepath.Clean(want)) {
			t.Errorf("expected lchown for %s; got %v", want, lchowned)
		}
	}
	// Re-apply is a no-op (files unchanged), but still chowns existing files.
	applied, err = s.apply(context.Background(), env)
	if err != nil || applied {
		t.Fatalf("idempotent apply: applied=%v err=%v", applied, err)
	}
}

func TestStepWriteAgentToolConfigs_RejectsFileSymlinkSwapBeforeChown(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	target := filepath.Join(t.TempDir(), "target")
	if err := os.WriteFile(target, []byte("do not chown"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	realWrite := env.writeFile
	swapped := false
	env.writeFile = func(path string, contents []byte, mode os.FileMode) error {
		if err := realWrite(path, contents, mode); err != nil {
			return err
		}
		if !swapped && strings.HasSuffix(filepath.Clean(path), ".gitconfig") {
			swapped = true
			if err := os.Remove(path); err != nil {
				t.Fatalf("remove written config: %v", err)
			}
			if err := os.Symlink(target, path); err != nil {
				t.Skipf("symlink unavailable: %v", err)
			}
		}
		return nil
	}
	env.chown = func(path string, _, _ int) error {
		t.Fatalf("agent config path used symlink-following chown: %s", path)
		return nil
	}

	s := stepWriteAgentToolConfigs()
	if _, err := s.apply(context.Background(), env); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("expected symlink-swap rejection, got %v", err)
	}
	if !swapped {
		t.Fatal("test did not exercise symlink swap")
	}
}

func TestChownAgentConfigFile_SecurityBranches(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	dir := t.TempDir()
	file := filepath.Join(dir, "config")
	if err := os.WriteFile(file, []byte("config"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	t.Run("lchown error surfaces", func(t *testing.T) {
		env2 := *env
		env2.lchown = func(string, int, int) error { return errAnyChown() }
		if err := chownAgentConfigFile(&env2, file, 988, 988); err == nil || !strings.Contains(err.Error(), "operation not permitted") {
			t.Fatalf("expected lchown error, got %v", err)
		}
	})

	t.Run("missing leaf surfaces stat error", func(t *testing.T) {
		if err := chownAgentConfigFile(env, filepath.Join(dir, "missing"), 988, 988); err == nil || !strings.Contains(err.Error(), "stat") {
			t.Fatalf("expected stat error, got %v", err)
		}
	})

	t.Run("non-regular leaf rejected", func(t *testing.T) {
		subdir := filepath.Join(dir, "subdir")
		if err := os.Mkdir(subdir, 0o700); err != nil {
			t.Fatalf("mkdir subdir: %v", err)
		}
		if err := chownAgentConfigFile(env, subdir, 988, 988); err == nil || !strings.Contains(err.Error(), "not a regular file") {
			t.Fatalf("expected non-regular rejection, got %v", err)
		}
	})
}

func TestEnsureAgentConfigDir_RejectsSymlinkParent(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	if err := os.MkdirAll(env.agentHome, 0o750); err != nil {
		t.Fatalf("mkdir home: %v", err)
	}
	target := filepath.Join(t.TempDir(), "target")
	if err := os.MkdirAll(target, 0o750); err != nil {
		t.Fatalf("mkdir target: %v", err)
	}
	if err := os.Symlink(target, filepath.Join(env.agentHome, ".config")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	err := ensureAgentConfigDir(env, filepath.Join(env.agentHome, ".config", "pip"), 988, 988)
	if err == nil || !strings.Contains(err.Error(), "symlink parent") {
		t.Fatalf("expected symlink-parent rejection, got %v", err)
	}
	if _, err := os.Stat(filepath.Join(target, "pip")); err == nil {
		t.Fatalf("mkdir followed symlink parent and created %s", filepath.Join(target, "pip"))
	}
}

func TestEnsureAgentConfigDir_RejectsOutsideHome(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	if err := os.MkdirAll(env.agentHome, 0o750); err != nil {
		t.Fatalf("mkdir home: %v", err)
	}
	// A target outside the agent home must be refused before any mkdir/chown.
	err := ensureAgentConfigDir(env, "/etc/pipelock/evil", 988, 988)
	if err == nil || !strings.Contains(err.Error(), "outside agent home") {
		t.Fatalf("expected outside-home rejection, got %v", err)
	}
}

func TestChownAgentConfigDir_SecurityBranches(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	base := t.TempDir()

	t.Run("rejects symlink", func(t *testing.T) {
		realDir := filepath.Join(base, "real")
		if err := os.MkdirAll(realDir, 0o750); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		link := filepath.Join(base, "link")
		if err := os.Symlink(realDir, link); err != nil {
			t.Skipf("symlink unavailable: %v", err)
		}
		if err := chownAgentConfigDir(env, link, 988, 988); err == nil || !strings.Contains(err.Error(), "symlink") {
			t.Fatalf("expected symlink rejection, got %v", err)
		}
	})
	t.Run("rejects non-directory", func(t *testing.T) {
		f := filepath.Join(base, "afile")
		if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		if err := chownAgentConfigDir(env, f, 988, 988); err == nil || !strings.Contains(err.Error(), "not a directory") {
			t.Fatalf("expected non-directory rejection, got %v", err)
		}
	})
	t.Run("lstat error on missing path", func(t *testing.T) {
		if err := chownAgentConfigDir(env, filepath.Join(base, "nope"), 988, 988); err == nil {
			t.Fatalf("expected lstat error on missing path")
		}
	})
	t.Run("chown error surfaces", func(t *testing.T) {
		env2, _, _ := newFakeEnv(t)
		env2.lchown = func(string, int, int) error { return errAnyChown() }
		dir := filepath.Join(base, "ok")
		if err := os.MkdirAll(dir, 0o750); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := chownAgentConfigDir(env2, dir, 988, 988); err == nil || !strings.Contains(err.Error(), "chown") {
			t.Fatalf("expected chown error, got %v", err)
		}
	})
	t.Run("uses no-follow chown hook", func(t *testing.T) {
		env2, _, _ := newFakeEnv(t)
		dir := filepath.Join(base, "nofollow")
		if err := os.MkdirAll(dir, 0o750); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		env2.chown = func(string, int, int) error {
			t.Fatal("chown follows symlinks and must not be used for agent config dirs")
			return nil
		}
		var lchowned []string
		env2.lchown = func(path string, _, _ int) error {
			lchowned = append(lchowned, filepath.Clean(path))
			return nil
		}
		if err := chownAgentConfigDir(env2, dir, 988, 988); err != nil {
			t.Fatalf("chownAgentConfigDir: %v", err)
		}
		if !slices.Contains(lchowned, filepath.Clean(dir)) {
			t.Fatalf("expected lchown on %s, got %v", dir, lchowned)
		}
	})
}

func errAnyChown() error { return errors.New("operation not permitted") }

func TestStepWriteAgentToolConfigs_FailsWhenAgentMissing(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	env.lookupUser = func(name string) (*user.User, error) { return nil, user.UnknownUserError(name) }
	s := stepWriteAgentToolConfigs()
	if _, err := s.apply(context.Background(), env); err == nil {
		t.Fatalf("expected error when agent uid unresolvable")
	}
}

func TestStepWriteAgentToolConfigs_WriteErrorRollsBack(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	realWrite := env.writeFile
	var n int
	// Fail the second config write to exercise the rollback-on-error path.
	env.writeFile = func(p string, b []byte, m os.FileMode) error {
		n++
		if n == 2 {
			return errors.New("disk full")
		}
		return realWrite(p, b, m)
	}
	s := stepWriteAgentToolConfigs()
	if _, err := s.apply(context.Background(), env); err == nil {
		t.Fatalf("expected write error to surface")
	}
}

func TestStepWriteAgentToolConfigs_ChownErrorFails(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	env.lchown = func(string, int, int) error { return errors.New("not permitted") }
	s := stepWriteAgentToolConfigs()
	if _, err := s.apply(context.Background(), env); err == nil {
		t.Fatalf("expected chown error to surface")
	}
}

func TestRuntimeSteps_WriteErrorsSurface(t *testing.T) {
	failWrite := func(string, []byte, os.FileMode) error { return errors.New("disk full") }
	t.Run("undici shim", func(t *testing.T) {
		env, _, _ := newFakeEnv(t)
		env.writeFile = failWrite
		if _, err := stepWriteUndiciShim().apply(context.Background(), env); err == nil {
			t.Fatalf("expected write error")
		}
	})
	t.Run("profile script", func(t *testing.T) {
		env, _, _ := newFakeEnv(t)
		env.writeFile = failWrite
		if _, err := stepWriteProfileScript().apply(context.Background(), env); err == nil {
			t.Fatalf("expected write error")
		}
	})
}

func TestRuntimeSteps_MkdirErrorsSurface(t *testing.T) {
	failMkdir := func(string, os.FileMode) error { return errors.New("read-only fs") }

	t.Run("undici shim", func(t *testing.T) {
		env, _, _ := newFakeEnv(t)
		env.mkdirAll = failMkdir
		if _, err := stepWriteUndiciShim().apply(context.Background(), env); err == nil {
			t.Fatalf("expected mkdir error")
		}
	})
	t.Run("profile script", func(t *testing.T) {
		env, _, _ := newFakeEnv(t)
		env.mkdirAll = failMkdir
		if _, err := stepWriteProfileScript().apply(context.Background(), env); err == nil {
			t.Fatalf("expected mkdir error")
		}
	})
	t.Run("agent configs", func(t *testing.T) {
		env, _, _ := newFakeEnv(t)
		realMkdir := env.mkdirAll
		env.mkdirAll = func(p string, m os.FileMode) error {
			if strings.Contains(p, "pip") {
				return errors.New("read-only fs")
			}
			return realMkdir(p, m)
		}
		if _, err := stepWriteAgentToolConfigs().apply(context.Background(), env); err == nil {
			t.Fatalf("expected mkdir error")
		}
	})
}

func TestStepWriteUtilityWrappers_WriteErrorRollsBack(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	if err := os.MkdirAll(env.wrapperDir, 0o750); err != nil {
		t.Fatalf("mkdir wrapperDir: %v", err)
	}
	realWrite := env.writeFile
	var n int
	env.writeFile = func(p string, b []byte, m os.FileMode) error {
		n++
		if n == 2 {
			return errors.New("disk full")
		}
		return realWrite(p, b, m)
	}
	s := stepWriteUtilityWrappers()
	if _, err := s.apply(context.Background(), env); err == nil {
		t.Fatalf("expected write error to surface")
	}
}
