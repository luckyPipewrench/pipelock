// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/spf13/cobra"
)

const (
	piConfigDirEnv       = "PI_CODING_AGENT_DIR"
	piConfigDirname      = ".pi/agent"
	piSettingsFilename   = "settings.json"
	piHTTPProxyKey       = "httpProxy"
	piDefaultProfile     = "pi"
	piStateSuffix        = ".pipelock-pi-state.json"
	piStateVersion       = 1
	piStatePhasePrepared = "prepared"
	piStatePhaseActive   = "active"
	piStatePhaseRemoving = "removing"
)

type piState struct {
	Version         int             `json:"version"`
	Phase           string          `json:"phase"`
	Proxy           string          `json:"proxy"`
	SettingsExisted bool            `json:"settings_existed"`
	HadHTTPProxy    bool            `json:"had_http_proxy"`
	PriorHTTPProxy  json.RawMessage `json:"prior_http_proxy,omitempty"`
}

// PiCmd returns the `pipelock pi` command tree.
func PiCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "pi",
		Short: "Pi coding-agent integration",
		Long: `Configure Pi's supported global HTTP proxy setting for a named Pipelock agent listener.

Pi sends HTTP_PROXY and HTTPS_PROXY from its global httpProxy setting. Install
requires a Pipelock config whose named agent listener matches the supplied
proxy URL, so Pi is never attributed through a shared default identity.`,
	}
	cmd.AddCommand(piInstallCmd(), piRemoveCmd())
	return cmd
}

func piInstallCmd() *cobra.Command {
	var configPath, profile, proxyURL string
	var dryRun bool
	cmd := &cobra.Command{
		Use:           "install",
		Short:         "Route Pi through a named Pipelock listener",
		SilenceUsage:  true,
		SilenceErrors: true,
		Args:          cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runPiInstall(cmd, configPath, profile, proxyURL, dryRun)
		},
	}
	cmd.Flags().StringVarP(&configPath, "config", "c", "", "path to Pipelock config with the named Pi listener")
	cmd.Flags().StringVar(&profile, "profile", piDefaultProfile, "named Pipelock agent profile for Pi")
	cmd.Flags().StringVar(&proxyURL, "proxy", "", "HTTP URL for the named Pipelock listener")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "show the change without modifying Pi settings")
	_ = cmd.MarkFlagRequired("config")
	_ = cmd.MarkFlagRequired("proxy")
	return cmd
}

func piRemoveCmd() *cobra.Command {
	var dryRun bool
	cmd := &cobra.Command{
		Use:           "remove",
		Short:         "Restore Pi's previous HTTP proxy setting",
		SilenceUsage:  true,
		SilenceErrors: true,
		Args:          cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runPiRemove(cmd, dryRun)
		},
	}
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "show the restoration without modifying Pi settings")
	return cmd
}

func piSettingsPath() (string, error) {
	if configDir := os.Getenv(piConfigDirEnv); configDir != "" {
		return filepath.Join(configDir, piSettingsFilename), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("finding home directory: %w", err)
	}
	return filepath.Join(home, piConfigDirname, piSettingsFilename), nil
}

func runPiInstall(cmd *cobra.Command, configPath, profile, proxyURL string, dryRun bool) error {
	if err := validatePiProfile(configPath, profile, proxyURL); err != nil {
		return err
	}
	settingsPath, err := piSettingsPath()
	if err != nil {
		return err
	}
	settings, existingData, err := readPiSettings(settingsPath)
	if err != nil {
		return err
	}
	statePath := piStatePath(settingsPath)
	state, found, err := readPiState(statePath)
	if err != nil {
		return err
	}
	if found {
		if state.Phase == piStatePhasePrepared {
			if state.Proxy != proxyURL {
				return errors.New("interrupted Pi install targets a different proxy; rerun with the recorded proxy before changing it")
			}
			if dryRun {
				if !piHTTPProxyMatches(settings, state.Proxy) && !piSettingsMatchPrior(settings, state) {
					return errors.New("the Pi settings changed during an interrupted install; refusing to overwrite the current setting")
				}
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Would recover interrupted Pi installation at %s through %s\n", settingsPath, proxyURL)
				return nil
			}
			recovered, err := recoverPreparedPiInstall(statePath, state, settings)
			if err != nil {
				return err
			}
			if recovered {
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Recovered Pi integration at %s through %s using profile %q\n", settingsPath, proxyURL, profile)
				return nil
			}
			found = false
		}
	}
	if found {
		if state.Phase == piStatePhaseActive && state.Proxy == proxyURL && piHTTPProxyMatches(settings, proxyURL) {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Pi already routes through %s using profile %q\n", proxyURL, profile)
			return nil
		}
		return fmt.Errorf("the Pi integration state at %s is %q or does not match settings; refusing to overwrite it", statePath, state.Phase)
	}

	prior, hadPrior := settings[piHTTPProxyKey]
	settings[piHTTPProxyKey], err = json.Marshal(proxyURL)
	if err != nil {
		return fmt.Errorf("marshaling Pi proxy URL: %w", err)
	}
	output, err := marshalPiSettings(settings)
	if err != nil {
		return err
	}
	if dryRun {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Would set %s in %s to %q for Pipelock profile %q:\n%s", piHTTPProxyKey, settingsPath, proxyURL, profile, output)
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(settingsPath), 0o750); err != nil {
		return fmt.Errorf("creating Pi config directory: %w", err)
	}
	state = piState{Version: piStateVersion, Phase: piStatePhasePrepared, Proxy: proxyURL, SettingsExisted: existingData != nil, HadHTTPProxy: hadPrior, PriorHTTPProxy: prior}
	if err := writePiState(statePath, state); err != nil {
		return err
	}
	if err := vscodeAtomicWrite(settingsPath, output, filepath.Dir(settingsPath)); err != nil {
		return fmt.Errorf("writing Pi settings after recording recovery state: %w", err)
	}
	state.Phase = piStatePhaseActive
	if err := writePiState(statePath, state); err != nil {
		return fmt.Errorf("recording active Pi integration state: %w", err)
	}
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Configured Pi in %s to use Pipelock profile %q at %s. Restart Pi after restarting Pipelock so the named listener is active.\n", settingsPath, profile, proxyURL)
	return nil
}

// recoverPreparedPiInstall handles the two unambiguous outcomes of an
// interrupted install. A target match means the settings rename completed and
// only activation state was interrupted. A match for the recorded prior value
// means the settings rename did not happen, so the prepared state can be
// removed before a fresh install. Other values may be operator changes.
func recoverPreparedPiInstall(statePath string, state piState, settings map[string]json.RawMessage) (bool, error) {
	if piHTTPProxyMatches(settings, state.Proxy) {
		state.Phase = piStatePhaseActive
		if err := writePiState(statePath, state); err != nil {
			return false, fmt.Errorf("recording recovered Pi integration state: %w", err)
		}
		return true, nil
	}
	if !piSettingsMatchPrior(settings, state) {
		return false, errors.New("the Pi settings changed during an interrupted install; refusing to overwrite the current setting")
	}
	if err := os.Remove(statePath); err != nil {
		return false, fmt.Errorf("removing stale prepared Pi integration state: %w", err)
	}
	return false, nil
}

func runPiRemove(cmd *cobra.Command, dryRun bool) error {
	settingsPath, err := piSettingsPath()
	if err != nil {
		return err
	}
	statePath := piStatePath(settingsPath)
	state, found, err := readPiState(statePath)
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("no Pi integration state found at %s; refusing to guess the previous proxy setting", statePath)
	}
	if state.Phase != piStatePhaseActive {
		return fmt.Errorf("the Pi integration state at %s is %q; refusing an interrupted operation", statePath, state.Phase)
	}
	settings, _, err := readPiSettings(settingsPath)
	if err != nil {
		return err
	}
	if !piHTTPProxyMatches(settings, state.Proxy) {
		return errors.New("the Pi httpProxy changed after installation; refusing to overwrite the current setting")
	}
	if state.HadHTTPProxy {
		settings[piHTTPProxyKey] = state.PriorHTTPProxy
	} else {
		delete(settings, piHTTPProxyKey)
	}
	output, err := marshalPiSettings(settings)
	if err != nil {
		return err
	}
	if dryRun {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Would restore %s in %s:\n%s", piHTTPProxyKey, settingsPath, output)
		return nil
	}
	state.Phase = piStatePhaseRemoving
	if err := writePiState(statePath, state); err != nil {
		return fmt.Errorf("recording Pi removal state: %w", err)
	}
	if !state.SettingsExisted && len(settings) == 0 {
		if err := os.Remove(settingsPath); err != nil {
			return fmt.Errorf("removing newly created Pi settings after recording recovery state: %w", err)
		}
	} else if err := vscodeAtomicWrite(settingsPath, output, filepath.Dir(settingsPath)); err != nil {
		return fmt.Errorf("restoring Pi settings after recording recovery state: %w", err)
	}
	if err := os.Remove(statePath); err != nil {
		return fmt.Errorf("removing Pi integration state after restoring settings: %w", err)
	}
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Restored Pi's previous HTTP proxy setting in %s. Restart Pi to apply it.\n", settingsPath)
	return nil
}

func validatePiProfile(configPath, profile, proxyURL string) error {
	if profile == "" || profile == "_default" {
		return fmt.Errorf("the Pi requires a named Pipelock profile, not %q", profile)
	}
	listener, err := piListenerAddress(proxyURL)
	if err != nil {
		return err
	}
	cfg, err := config.LoadForInspection(filepath.Clean(configPath))
	if err != nil {
		return fmt.Errorf("loading Pipelock config: %w", err)
	}
	if !cfg.ForwardProxy.Enabled {
		return errors.New("the Pipelock forward_proxy.enabled must be true for Pi's HTTP proxy setting")
	}
	agent, found := cfg.Agents[profile]
	if !found {
		return fmt.Errorf("the Pipelock config does not define named profile %q", profile)
	}
	for _, candidate := range agent.Listeners {
		if candidate == listener {
			return nil
		}
	}
	return fmt.Errorf("the Pipelock profile %q has no listener matching %q", profile, listener)
}

func piListenerAddress(proxyURL string) (string, error) {
	u, err := url.ParseRequestURI(proxyURL)
	if err != nil {
		return "", fmt.Errorf("parsing Pi proxy URL: %w", err)
	}
	if u.Scheme != "http" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return "", errors.New("the Pi proxy URL must be an http URL with only a host and port")
	}
	host, port, err := net.SplitHostPort(u.Host)
	if err != nil || host == "" || port == "" {
		return "", errors.New("the Pi proxy URL must include a host and port")
	}
	portNumber, err := strconv.ParseUint(port, 10, 16)
	if err != nil || portNumber == 0 {
		return "", errors.New("the Pi proxy URL must include a port from 1 to 65535")
	}
	return net.JoinHostPort(host, port), nil
}

func readPiSettings(path string) (map[string]json.RawMessage, []byte, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if errors.Is(err, os.ErrNotExist) {
		return make(map[string]json.RawMessage), nil, nil
	}
	if err != nil {
		return nil, nil, fmt.Errorf("reading Pi settings %s: %w", path, err)
	}
	settings := make(map[string]json.RawMessage)
	if len(bytes.TrimSpace(data)) == 0 {
		return settings, data, nil
	}
	if err := json.Unmarshal(data, &settings); err != nil {
		return nil, nil, fmt.Errorf("parsing Pi settings %s: %w", path, err)
	}
	if settings == nil {
		return nil, nil, fmt.Errorf("parsing Pi settings %s: expected a JSON object", path)
	}
	return settings, data, nil
}

func marshalPiSettings(settings map[string]json.RawMessage) ([]byte, error) {
	data, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshaling Pi settings: %w", err)
	}
	return append(data, '\n'), nil
}

func piStatePath(settingsPath string) string {
	return settingsPath + piStateSuffix
}

func readPiState(path string) (piState, bool, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if errors.Is(err, os.ErrNotExist) {
		return piState{}, false, nil
	}
	if err != nil {
		return piState{}, false, fmt.Errorf("reading Pi integration state %s: %w", path, err)
	}
	var state piState
	if err := json.Unmarshal(data, &state); err != nil {
		return piState{}, false, fmt.Errorf("parsing Pi integration state %s: %w", path, err)
	}
	if state.Version != piStateVersion || state.Proxy == "" || (state.Phase != piStatePhasePrepared && state.Phase != piStatePhaseActive && state.Phase != piStatePhaseRemoving) {
		return piState{}, false, fmt.Errorf("the Pi integration state %s is invalid; refusing to guess recovery", path)
	}
	if state.HadHTTPProxy && (len(state.PriorHTTPProxy) == 0 || !json.Valid(state.PriorHTTPProxy)) {
		return piState{}, false, fmt.Errorf("the Pi integration state %s has an invalid prior httpProxy; refusing to guess recovery", path)
	}
	if !state.HadHTTPProxy && len(state.PriorHTTPProxy) != 0 {
		return piState{}, false, fmt.Errorf("the Pi integration state %s has an unexpected prior httpProxy; refusing to guess recovery", path)
	}
	return state, true, nil
}

func writePiState(path string, state piState) error {
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling Pi integration state: %w", err)
	}
	if err := vscodeAtomicWrite(path, append(data, '\n'), filepath.Dir(path)); err != nil {
		return fmt.Errorf("writing Pi integration state %s: %w", path, err)
	}
	return nil
}

func piHTTPProxyMatches(settings map[string]json.RawMessage, proxyURL string) bool {
	value, found := settings[piHTTPProxyKey]
	if !found {
		return false
	}
	var configured string
	return json.Unmarshal(value, &configured) == nil && configured == proxyURL
}

func piSettingsMatchPrior(settings map[string]json.RawMessage, state piState) bool {
	value, found := settings[piHTTPProxyKey]
	if state.HadHTTPProxy != found {
		return false
	}
	if !found {
		return true
	}
	var current, prior bytes.Buffer
	return json.Compact(&current, value) == nil && json.Compact(&prior, state.PriorHTTPProxy) == nil && bytes.Equal(current.Bytes(), prior.Bytes())
}
