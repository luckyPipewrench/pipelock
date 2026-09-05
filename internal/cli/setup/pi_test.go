// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const piTestProxyURL = "http://127.0.0.1:18889"

func TestPiInstallAndRemovePreserveSettings(t *testing.T) {
	t.Setenv(piConfigDirEnv, t.TempDir())
	settingsPath, err := piSettingsPath()
	if err != nil {
		t.Fatalf("piSettingsPath: %v", err)
	}
	if err := os.WriteFile(settingsPath, []byte(`{"theme":"dark","future":{"enabled":true},"httpProxy":"http://previous.example:8080"}`), 0o600); err != nil {
		t.Fatalf("seed settings: %v", err)
	}
	configPath := writePiPipelockConfig(t, piTestProxyURL)

	if _, _, err := runPiCommand(t, "install", "--config", configPath, "--proxy", piTestProxyURL); err != nil {
		t.Fatalf("install: %v", err)
	}
	settings := readPiSettingsForTest(t, settingsPath)
	if got := stringValue(t, settings[piHTTPProxyKey]); got != piTestProxyURL {
		t.Fatalf("httpProxy = %q, want %q", got, piTestProxyURL)
	}
	if got := stringValue(t, settings["theme"]); got != "dark" {
		t.Fatalf("theme = %q, want dark", got)
	}
	var future map[string]bool
	if err := json.Unmarshal(settings["future"], &future); err != nil || !future["enabled"] {
		t.Fatalf("future setting was not preserved: %s, %v", settings["future"], err)
	}
	if info, err := os.Stat(piStatePath(settingsPath)); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("state permissions = %v, %v; want 0600", info, err)
	}

	settings["theme"] = json.RawMessage(`"light"`)
	data, err := marshalPiSettings(settings)
	if err != nil {
		t.Fatalf("marshal post-install change: %v", err)
	}
	if err := os.WriteFile(settingsPath, data, 0o600); err != nil {
		t.Fatalf("write post-install change: %v", err)
	}
	if _, _, err := runPiCommand(t, "remove"); err != nil {
		t.Fatalf("remove: %v", err)
	}
	settings = readPiSettingsForTest(t, settingsPath)
	if got := stringValue(t, settings[piHTTPProxyKey]); got != "http://previous.example:8080" {
		t.Fatalf("restored httpProxy = %q", got)
	}
	if got := stringValue(t, settings["theme"]); got != "light" {
		t.Fatalf("post-install setting was overwritten: %q", got)
	}
	if _, err := os.Stat(piStatePath(settingsPath)); !os.IsNotExist(err) {
		t.Fatalf("state remains after remove: %v", err)
	}
}

func TestPiInstallAndRemoveWhenNoPriorProxy(t *testing.T) {
	t.Setenv(piConfigDirEnv, t.TempDir())
	settingsPath, err := piSettingsPath()
	if err != nil {
		t.Fatalf("piSettingsPath: %v", err)
	}
	configPath := writePiPipelockConfig(t, piTestProxyURL)
	if _, _, err := runPiCommand(t, "install", "--config", configPath, "--proxy", piTestProxyURL); err != nil {
		t.Fatalf("install: %v", err)
	}
	if _, _, err := runPiCommand(t, "remove"); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if _, err := os.Stat(settingsPath); !os.IsNotExist(err) {
		t.Fatalf("new settings file remained after remove: %v", err)
	}
}

func TestPiDryRunDoesNotWriteSettingsOrState(t *testing.T) {
	t.Setenv(piConfigDirEnv, t.TempDir())
	settingsPath, err := piSettingsPath()
	if err != nil {
		t.Fatalf("piSettingsPath: %v", err)
	}
	configPath := writePiPipelockConfig(t, piTestProxyURL)
	stdout, _, err := runPiCommand(t, "install", "--config", configPath, "--proxy", piTestProxyURL, "--dry-run")
	if err != nil {
		t.Fatalf("dry-run install: %v", err)
	}
	if !strings.Contains(stdout, piHTTPProxyKey) || !strings.Contains(stdout, piTestProxyURL) {
		t.Fatalf("dry-run output did not show change: %s", stdout)
	}
	if _, err := os.Stat(settingsPath); !os.IsNotExist(err) {
		t.Fatalf("settings written by dry run: %v", err)
	}
	if _, err := os.Stat(piStatePath(settingsPath)); !os.IsNotExist(err) {
		t.Fatalf("state written by dry run: %v", err)
	}
}

func TestPiRemoveDryRunAndMissingState(t *testing.T) {
	t.Run("dry run", func(t *testing.T) {
		t.Setenv(piConfigDirEnv, t.TempDir())
		settingsPath, err := piSettingsPath()
		if err != nil {
			t.Fatalf("piSettingsPath: %v", err)
		}
		configPath := writePiPipelockConfig(t, piTestProxyURL)
		if _, _, err := runPiCommand(t, "install", "--config", configPath, "--proxy", piTestProxyURL); err != nil {
			t.Fatalf("install: %v", err)
		}
		stdout, _, err := runPiCommand(t, "remove", "--dry-run")
		if err != nil || !strings.Contains(stdout, "Would restore") {
			t.Fatalf("dry-run remove = %q, %v", stdout, err)
		}
		if got := stringValue(t, readPiSettingsForTest(t, settingsPath)[piHTTPProxyKey]); got != piTestProxyURL {
			t.Fatalf("dry-run changed proxy to %q", got)
		}
		if state, found, err := readPiState(piStatePath(settingsPath)); err != nil || !found || state.Phase != piStatePhaseActive {
			t.Fatalf("dry-run changed state: %#v, %t, %v", state, found, err)
		}
	})
	t.Run("missing state", func(t *testing.T) {
		t.Setenv(piConfigDirEnv, t.TempDir())
		_, _, err := runPiCommand(t, "remove")
		if err == nil || !strings.Contains(err.Error(), "no Pi integration state") {
			t.Fatalf("remove error = %v, want missing-state refusal", err)
		}
	})
}

func TestPiInstallIsIdempotentAndRefusesAmbiguousState(t *testing.T) {
	t.Setenv(piConfigDirEnv, t.TempDir())
	settingsPath, err := piSettingsPath()
	if err != nil {
		t.Fatalf("piSettingsPath: %v", err)
	}
	configPath := writePiPipelockConfig(t, piTestProxyURL)
	if _, _, err := runPiCommand(t, "install", "--config", configPath, "--proxy", piTestProxyURL); err != nil {
		t.Fatalf("install: %v", err)
	}
	stdout, _, err := runPiCommand(t, "install", "--config", configPath, "--proxy", piTestProxyURL)
	if err != nil || !strings.Contains(stdout, "already routes") {
		t.Fatalf("idempotent install = %q, %v", stdout, err)
	}
	if err := writePiState(piStatePath(settingsPath), piState{Version: piStateVersion, Phase: piStatePhaseRemoving, Proxy: piTestProxyURL}); err != nil {
		t.Fatalf("write removing state: %v", err)
	}
	_, _, err = runPiCommand(t, "install", "--config", configPath, "--proxy", piTestProxyURL)
	if err == nil || !strings.Contains(err.Error(), "refusing to overwrite") {
		t.Fatalf("install error = %v, want ambiguous-state refusal", err)
	}
}

func TestPiInstallRecoversPreparedState(t *testing.T) {
	tests := []struct {
		name        string
		settings    string
		state       piState
		wantOutput  string
		wantProxy   string
		wantActive  bool
		wantFailure string
	}{
		{
			name:       "settings rename completed",
			settings:   `{"httpProxy":"http://127.0.0.1:18889"}`,
			state:      piState{Version: piStateVersion, Phase: piStatePhasePrepared, Proxy: piTestProxyURL, SettingsExisted: true},
			wantOutput: "Recovered Pi integration",
			wantProxy:  piTestProxyURL,
			wantActive: true,
		},
		{
			name:       "settings rename did not happen",
			settings:   `{"httpProxy":"http://previous.example:8080"}`,
			state:      piState{Version: piStateVersion, Phase: piStatePhasePrepared, Proxy: piTestProxyURL, SettingsExisted: true, HadHTTPProxy: true, PriorHTTPProxy: json.RawMessage(`"http://previous.example:8080"`)},
			wantOutput: "Configured Pi",
			wantProxy:  piTestProxyURL,
			wantActive: true,
		},
		{
			name:        "operator drift",
			settings:    `{"httpProxy":"http://operator.example:8080"}`,
			state:       piState{Version: piStateVersion, Phase: piStatePhasePrepared, Proxy: piTestProxyURL, SettingsExisted: true, HadHTTPProxy: true, PriorHTTPProxy: json.RawMessage(`"http://previous.example:8080"`)},
			wantFailure: "changed during an interrupted install",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			t.Setenv(piConfigDirEnv, dir)
			settingsPath := filepath.Join(dir, piSettingsFilename)
			if err := os.WriteFile(settingsPath, []byte(test.settings), 0o600); err != nil {
				t.Fatalf("seed settings: %v", err)
			}
			if err := writePiState(piStatePath(settingsPath), test.state); err != nil {
				t.Fatalf("seed state: %v", err)
			}
			configPath := writePiPipelockConfig(t, piTestProxyURL)
			stdout, _, err := runPiCommand(t, "install", "--config", configPath, "--proxy", piTestProxyURL)
			if test.wantFailure != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantFailure) {
					t.Fatalf("install error = %v, want %q", err, test.wantFailure)
				}
				return
			}
			if err != nil || !strings.Contains(stdout, test.wantOutput) {
				t.Fatalf("install = %q, %v", stdout, err)
			}
			if got := stringValue(t, readPiSettingsForTest(t, settingsPath)[piHTTPProxyKey]); got != test.wantProxy {
				t.Fatalf("httpProxy = %q, want %q", got, test.wantProxy)
			}
			state, found, err := readPiState(piStatePath(settingsPath))
			if err != nil || !found || (state.Phase == piStatePhaseActive) != test.wantActive {
				t.Fatalf("state = %#v, found=%t, err=%v", state, found, err)
			}
		})
	}
}

func TestPiPreparedRecoveryDryRunPreservesFiles(t *testing.T) {
	for _, settings := range []string{`{}`, `{"httpProxy":"http://127.0.0.1:18889"}`, `{"httpProxy":"http://changed.example:8080"}`} {
		t.Run(settings, func(t *testing.T) {
			dir := t.TempDir()
			t.Setenv(piConfigDirEnv, dir)
			path := filepath.Join(dir, piSettingsFilename)
			if err := os.WriteFile(path, []byte(settings), 0o600); err != nil {
				t.Fatal(err)
			}
			statePath := piStatePath(path)
			if err := writePiState(statePath, piState{Version: piStateVersion, Phase: piStatePhasePrepared, Proxy: piTestProxyURL}); err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(filepath.Clean(statePath))
			if err != nil {
				t.Fatal(err)
			}
			_, _, err = runPiCommand(t, "install", "--config", writePiPipelockConfig(t, piTestProxyURL), "--proxy", piTestProxyURL, "--dry-run")
			if strings.Contains(settings, "changed.example") != (err != nil) {
				t.Fatalf("dry run error=%v", err)
			}
			after, readErr := os.ReadFile(filepath.Clean(statePath))
			if readErr != nil || string(before) != string(after) {
				t.Fatalf("dry run changed state: %v", readErr)
			}
			current, readErr := os.ReadFile(filepath.Clean(path))
			if readErr != nil || string(current) != settings {
				t.Fatalf("dry run changed settings: %v", readErr)
			}
		})
	}
}

func TestPiPreparedRecoveryRefusesDifferentProxy(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(piConfigDirEnv, dir)
	path := filepath.Join(dir, piSettingsFilename)
	statePath := piStatePath(path)
	state := piState{Version: piStateVersion, Phase: piStatePhasePrepared, Proxy: "http://127.0.0.1:18890"}
	if err := writePiState(statePath, state); err != nil {
		t.Fatal(err)
	}
	alternative := "http://127.0.0.1:18891"
	_, stderr, err := runPiCommand(t, "install", "--config", writePiPipelockConfig(t, alternative), "--proxy", alternative)
	if stderr != "" {
		t.Fatalf("command printed an error instead of returning it: %s", stderr)
	}
	if err == nil || !strings.Contains(err.Error(), "different proxy") {
		t.Fatalf("mismatched recovery error = %v", err)
	}
	got, found, err := readPiState(statePath)
	if err != nil || !found || got.Proxy != state.Proxy || got.Phase != piStatePhasePrepared {
		t.Fatalf("recovery changed state: %+v, %v", got, err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("recovery created settings: %v", err)
	}
}

func TestPiMissingHomeFailsBeforeWriting(t *testing.T) {
	t.Setenv(piConfigDirEnv, "")
	t.Setenv("HOME", "")
	t.Setenv("USERPROFILE", "")
	for _, args := range [][]string{
		{"install", "--config", writePiPipelockConfig(t, piTestProxyURL), "--proxy", piTestProxyURL},
		{"remove"},
	} {
		_, _, err := runPiCommand(t, args...)
		if err == nil || !strings.Contains(err.Error(), "home directory") {
			t.Fatalf("missing home error = %v", err)
		}
	}
}

func TestPiPreparedRecoveryReportsFilesystemFailures(t *testing.T) {
	t.Run("activation write fails", func(t *testing.T) {
		state := piState{Version: piStateVersion, Phase: piStatePhasePrepared, Proxy: piTestProxyURL}
		settings := map[string]json.RawMessage{piHTTPProxyKey: json.RawMessage(`"http://127.0.0.1:18889"`)}
		recovered, err := recoverPreparedPiInstall(t.TempDir(), state, settings)
		if recovered || err == nil || !strings.Contains(err.Error(), "recording recovered") {
			t.Fatalf("activation result = %v, %v", recovered, err)
		}
	})
	t.Run("stale state removal fails", func(t *testing.T) {
		state := piState{Version: piStateVersion, Phase: piStatePhasePrepared, Proxy: piTestProxyURL}
		recovered, err := recoverPreparedPiInstall(filepath.Join(t.TempDir(), "missing.json"), state, map[string]json.RawMessage{})
		if recovered || err == nil || !strings.Contains(err.Error(), "removing stale prepared") {
			t.Fatalf("stale state result = %v, %v", recovered, err)
		}
	})
}

func TestPiRemoveRefusesDriftAndInterruptedState(t *testing.T) {
	t.Run("drift", func(t *testing.T) {
		t.Setenv(piConfigDirEnv, t.TempDir())
		settingsPath, err := piSettingsPath()
		if err != nil {
			t.Fatalf("piSettingsPath: %v", err)
		}
		configPath := writePiPipelockConfig(t, piTestProxyURL)
		if _, _, err := runPiCommand(t, "install", "--config", configPath, "--proxy", piTestProxyURL); err != nil {
			t.Fatalf("install: %v", err)
		}
		if err := os.WriteFile(settingsPath, []byte(`{"httpProxy":"http://operator.example:8080"}`), 0o600); err != nil {
			t.Fatalf("seed drift: %v", err)
		}
		_, _, err = runPiCommand(t, "remove")
		if err == nil || !strings.Contains(err.Error(), "changed after installation") {
			t.Fatalf("remove error = %v, want drift refusal", err)
		}
	})
	t.Run("prepared", func(t *testing.T) {
		t.Setenv(piConfigDirEnv, t.TempDir())
		settingsPath, err := piSettingsPath()
		if err != nil {
			t.Fatalf("piSettingsPath: %v", err)
		}
		if err := os.MkdirAll(filepath.Dir(settingsPath), 0o750); err != nil {
			t.Fatalf("make config dir: %v", err)
		}
		if err := os.WriteFile(settingsPath, []byte(`{"httpProxy":"`+piTestProxyURL+`"}`), 0o600); err != nil {
			t.Fatalf("seed settings: %v", err)
		}
		if err := writePiState(piStatePath(settingsPath), piState{Version: piStateVersion, Phase: piStatePhasePrepared, Proxy: piTestProxyURL}); err != nil {
			t.Fatalf("write prepared state: %v", err)
		}
		_, _, err = runPiCommand(t, "remove")
		if err == nil || !strings.Contains(err.Error(), "interrupted operation") {
			t.Fatalf("remove error = %v, want interrupted-state refusal", err)
		}
	})
}

func TestPiProfileValidation(t *testing.T) {
	configPath := writePiPipelockConfig(t, piTestProxyURL)
	tests := []struct {
		name    string
		profile string
		proxy   string
		wantErr string
	}{
		{name: "matching named listener", profile: piDefaultProfile, proxy: piTestProxyURL},
		{name: "default profile rejected", profile: "_default", proxy: piTestProxyURL, wantErr: "named Pipelock profile"},
		{name: "listener mismatch", profile: piDefaultProfile, proxy: "http://127.0.0.1:18890", wantErr: "no listener matching"},
		{name: "proxy requires port", profile: piDefaultProfile, proxy: "http://127.0.0.1", wantErr: "host and port"},
		{name: "https rejected", profile: piDefaultProfile, proxy: "https://127.0.0.1:18889", wantErr: "http URL"},
		{name: "path rejected", profile: piDefaultProfile, proxy: piTestProxyURL + "/path", wantErr: "http URL"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validatePiProfile(configPath, test.profile, test.proxy)
			if test.wantErr == "" {
				if err != nil {
					t.Fatalf("validatePiProfile: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("validatePiProfile error = %v, want %q", err, test.wantErr)
			}
		})
	}
}

func TestPiListenerPortBounds(t *testing.T) {
	for _, port := range []string{"0", "65536", "999999999999999999999"} {
		t.Run(port, func(t *testing.T) {
			proxyURL := "http://127.0.0.1:" + port
			configPath := filepath.Join(t.TempDir(), "pipelock.yaml")
			body := "forward_proxy:\n  enabled: true\nagents:\n  pi:\n    listeners: [127.0.0.1:" + port + "]\n"
			if err := os.WriteFile(configPath, []byte(body), 0o600); err != nil {
				t.Fatalf("write invalid listener config: %v", err)
			}
			if err := validatePiProfile(configPath, piDefaultProfile, proxyURL); err == nil {
				t.Fatal("invalid matching listener accepted")
			}
		})
	}
	for _, port := range []string{"1", "65535"} {
		t.Run(port, func(t *testing.T) {
			proxyURL := "http://127.0.0.1:" + port
			configPath := writePiPipelockConfig(t, proxyURL)
			if err := validatePiProfile(configPath, piDefaultProfile, proxyURL); err != nil {
				t.Fatalf("valid matching listener rejected: %v", err)
			}
		})
	}
}

func TestPiProfileValidationConfigurationFailures(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{name: "forward proxy disabled", body: "agents:\n  pi:\n    listeners: [127.0.0.1:18889]\n", want: "forward_proxy.enabled"},
		{name: "profile missing", body: "forward_proxy:\n  enabled: true\n", want: "does not define"},
		{name: "malformed config", body: "agents: [\n", want: "loading Pipelock config"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "pipelock.yaml")
			if err := os.WriteFile(path, []byte(test.body), 0o600); err != nil {
				t.Fatalf("write config: %v", err)
			}
			err := validatePiProfile(path, piDefaultProfile, piTestProxyURL)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("validatePiProfile error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestPiSettingsAndStateFailurePaths(t *testing.T) {
	t.Run("settings", func(t *testing.T) {
		dir := t.TempDir()
		tests := []struct {
			name string
			path string
			body string
			want string
		}{
			{name: "malformed JSON", path: filepath.Join(dir, "bad.json"), body: "{", want: "parsing Pi settings"},
			{name: "JSON null", path: filepath.Join(dir, "null.json"), body: "null", want: "expected a JSON object"},
			{name: "directory", path: dir, want: "reading Pi settings"},
		}
		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				if test.body != "" {
					if err := os.WriteFile(test.path, []byte(test.body), 0o600); err != nil {
						t.Fatalf("seed settings: %v", err)
					}
				}
				_, _, err := readPiSettings(test.path)
				if err == nil || !strings.Contains(err.Error(), test.want) {
					t.Fatalf("readPiSettings error = %v, want %q", err, test.want)
				}
			})
		}
	})
	t.Run("state", func(t *testing.T) {
		dir := t.TempDir()
		tests := []struct {
			name string
			path string
			body string
			want string
		}{
			{name: "malformed JSON", path: filepath.Join(dir, "bad.json"), body: "{", want: "parsing Pi integration state"},
			{name: "invalid shape", path: filepath.Join(dir, "invalid.json"), body: `{"version":0,"phase":"other","proxy":""}`, want: "invalid"},
			{name: "missing prior value", path: filepath.Join(dir, "missing-prior.json"), body: `{"version":1,"phase":"active","proxy":"http://127.0.0.1:18889","had_http_proxy":true}`, want: "invalid prior"},
			{name: "unexpected prior value", path: filepath.Join(dir, "unexpected-prior.json"), body: `{"version":1,"phase":"active","proxy":"http://127.0.0.1:18889","prior_http_proxy":"http://previous.example:8080"}`, want: "unexpected prior"},
			{name: "directory", path: dir, want: "reading Pi integration state"},
		}
		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				if test.body != "" {
					if err := os.WriteFile(test.path, []byte(test.body), 0o600); err != nil {
						t.Fatalf("seed state: %v", err)
					}
				}
				_, _, err := readPiState(test.path)
				if err == nil || !strings.Contains(err.Error(), test.want) {
					t.Fatalf("readPiState error = %v, want %q", err, test.want)
				}
			})
		}
	})
	t.Run("state write failures", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "missing", "state.json")
		if err := writePiState(path, piState{Version: piStateVersion, Phase: piStatePhaseActive, Proxy: piTestProxyURL}); err == nil {
			t.Fatal("writePiState succeeded in missing directory")
		}
		if err := writePiState(filepath.Join(t.TempDir(), "invalid.json"), piState{PriorHTTPProxy: json.RawMessage("{")}); err == nil {
			t.Fatal("writePiState accepted invalid raw JSON")
		}
	})
	t.Run("invalid settings marshal", func(t *testing.T) {
		if _, err := marshalPiSettings(map[string]json.RawMessage{"bad": json.RawMessage("{")}); err == nil {
			t.Fatal("marshalPiSettings accepted invalid raw JSON")
		}
	})
}

func TestPiCommandFailurePaths(t *testing.T) {
	t.Run("install rejects invalid config", func(t *testing.T) {
		t.Setenv(piConfigDirEnv, t.TempDir())
		configPath := filepath.Join(t.TempDir(), "invalid.yaml")
		if err := os.WriteFile(configPath, []byte("agents: [\n"), 0o600); err != nil {
			t.Fatalf("seed config: %v", err)
		}
		_, _, err := runPiCommand(t, "install", "--config", configPath, "--proxy", piTestProxyURL)
		if err == nil || !strings.Contains(err.Error(), "loading Pipelock config") {
			t.Fatalf("install error = %v, want config refusal", err)
		}
	})
	t.Run("install rejects malformed settings and state", func(t *testing.T) {
		for _, test := range []struct {
			name      string
			settings  string
			state     string
			wantError string
		}{
			{name: "settings", settings: "{", wantError: "parsing Pi settings"},
			{name: "state", settings: "{}", state: "{", wantError: "parsing Pi integration state"},
		} {
			t.Run(test.name, func(t *testing.T) {
				dir := t.TempDir()
				t.Setenv(piConfigDirEnv, dir)
				settingsPath := filepath.Join(dir, piSettingsFilename)
				if err := os.WriteFile(settingsPath, []byte(test.settings), 0o600); err != nil {
					t.Fatalf("seed settings: %v", err)
				}
				if test.state != "" {
					if err := os.WriteFile(piStatePath(settingsPath), []byte(test.state), 0o600); err != nil {
						t.Fatalf("seed state: %v", err)
					}
				}
				configPath := writePiPipelockConfig(t, piTestProxyURL)
				_, _, err := runPiCommand(t, "install", "--config", configPath, "--proxy", piTestProxyURL)
				if err == nil || !strings.Contains(err.Error(), test.wantError) {
					t.Fatalf("install error = %v, want %q", err, test.wantError)
				}
			})
		}
	})
	t.Run("remove rejects malformed state and settings", func(t *testing.T) {
		for _, test := range []struct {
			name      string
			settings  string
			state     string
			wantError string
		}{
			{name: "state", settings: "{}", state: "{", wantError: "parsing Pi integration state"},
			{name: "settings", settings: "{", state: `{"version":1,"phase":"active","proxy":"http://127.0.0.1:18889","settings_existed":true}`, wantError: "parsing Pi settings"},
		} {
			t.Run(test.name, func(t *testing.T) {
				dir := t.TempDir()
				t.Setenv(piConfigDirEnv, dir)
				settingsPath := filepath.Join(dir, piSettingsFilename)
				if err := os.WriteFile(settingsPath, []byte(test.settings), 0o600); err != nil {
					t.Fatalf("seed settings: %v", err)
				}
				if err := os.WriteFile(piStatePath(settingsPath), []byte(test.state), 0o600); err != nil {
					t.Fatalf("seed state: %v", err)
				}
				_, _, err := runPiCommand(t, "remove")
				if err == nil || !strings.Contains(err.Error(), test.wantError) {
					t.Fatalf("remove error = %v, want %q", err, test.wantError)
				}
			})
		}
	})
}

func TestPiSettingsPathUsesEnvironmentOverride(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(piConfigDirEnv, dir)
	path, err := piSettingsPath()
	if err != nil {
		t.Fatalf("piSettingsPath: %v", err)
	}
	if want := filepath.Join(dir, piSettingsFilename); path != want {
		t.Fatalf("path = %q, want %q", path, want)
	}
}

func TestPiSettingsPathDefaultAndProxyMatchFailures(t *testing.T) {
	t.Setenv(piConfigDirEnv, "")
	path, err := piSettingsPath()
	if err != nil {
		t.Fatalf("piSettingsPath: %v", err)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("os.UserHomeDir: %v", err)
	}
	if want := filepath.Join(home, piConfigDirname, piSettingsFilename); path != want {
		t.Fatalf("path = %q, want %q", path, want)
	}
	if _, err := piListenerAddress("http://[::1"); err == nil {
		t.Fatal("piListenerAddress accepted malformed URL")
	}
	if piHTTPProxyMatches(map[string]json.RawMessage{}, piTestProxyURL) {
		t.Fatal("piHTTPProxyMatches accepted missing value")
	}
	if piHTTPProxyMatches(map[string]json.RawMessage{piHTTPProxyKey: json.RawMessage(`1`)}, piTestProxyURL) {
		t.Fatal("piHTTPProxyMatches accepted non-string value")
	}
}

func writePiPipelockConfig(t *testing.T, proxyURL string) string {
	t.Helper()
	listener, err := piListenerAddress(proxyURL)
	if err != nil {
		t.Fatalf("piListenerAddress: %v", err)
	}
	path := filepath.Join(t.TempDir(), "pipelock.yaml")
	body := "forward_proxy:\n  enabled: true\nagents:\n  pi:\n    listeners:\n      - " + listener + "\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write Pipelock config: %v", err)
	}
	return path
}

func runPiCommand(t *testing.T, args ...string) (string, string, error) {
	t.Helper()
	cmd := PiCmd()
	cmd.SetArgs(args)
	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	err := cmd.Execute()
	return stdout.String(), stderr.String(), err
}

func readPiSettingsForTest(t *testing.T, path string) map[string]json.RawMessage {
	t.Helper()
	settings, _, err := readPiSettings(path)
	if err != nil {
		t.Fatalf("readPiSettings: %v", err)
	}
	return settings
}

func stringValue(t *testing.T, raw json.RawMessage) string {
	t.Helper()
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		t.Fatalf("unmarshal string: %v", err)
	}
	return value
}
