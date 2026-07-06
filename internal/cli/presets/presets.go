// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package presets

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/luckyPipewrench/pipelock/configs"
	"github.com/luckyPipewrench/pipelock/internal/config"
)

const (
	PresetClaudeCode   = "claude-code"
	PresetCursor       = "cursor"
	PresetGenericAgent = "generic-agent"
	PresetHostileModel = "hostile-model"
)

var All = []string{
	config.ModeStrict,
	config.ModeBalanced,
	config.ModeAudit,
	PresetClaudeCode,
	PresetCursor,
	PresetGenericAgent,
	PresetHostileModel,
}

var (
	ValidNames = strings.Join(All, ", ")
	FlagHelp   = "config preset: " + ValidNames
)

type Info struct {
	Name          string
	Mode          string
	DefaultAction string
	Reachability  string
	Description   string
}

// Cmd returns the top-level "presets" command.
func Cmd() *cobra.Command {
	return &cobra.Command{
		Use:   "presets",
		Short: "List built-in config presets",
		Long:  "List every built-in config preset accepted by `pipelock generate config --preset <name>`.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return PrintList(cmd.OutOrStdout())
		},
	}
}

// PrintList writes all built-in presets in a stable table.
func PrintList(w io.Writer) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	if _, err := fmt.Fprintln(tw, "NAME\tMODE\tDEFAULT ACTION\tREACHABILITY"); err != nil {
		return fmt.Errorf("writing presets header: %w", err)
	}
	for _, info := range List() {
		if _, err := fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", info.Name, info.Mode, info.DefaultAction, info.Reachability); err != nil {
			return fmt.Errorf("writing preset %q: %w", info.Name, err)
		}
	}
	if err := tw.Flush(); err != nil {
		return fmt.Errorf("flushing presets table: %w", err)
	}
	return nil
}

// List returns metadata for every built-in preset in CLI selection order.
func List() []Info {
	out := make([]Info, 0, len(All))
	for _, name := range All {
		cfg, err := Config(name)
		if err != nil {
			out = append(out, Info{Name: name, Mode: "invalid", DefaultAction: "invalid", Reachability: err.Error()})
			continue
		}
		out = append(out, Info{
			Name:          name,
			Mode:          cfg.Mode,
			DefaultAction: defaultAction(cfg),
			Reachability:  reachability(cfg),
			Description:   description(name),
		})
	}
	return out
}

func defaultAction(cfg *config.Config) string {
	if cfg.Enforce != nil && !*cfg.Enforce {
		return "warn (log-only)"
	}
	if cfg.Mode == config.ModeStrict {
		return config.ActionBlock
	}
	if cfg.ResponseScanning.Action != "" {
		return cfg.ResponseScanning.Action
	}
	return config.ActionWarn
}

func reachability(cfg *config.Config) string {
	if cfg.Mode == config.ModeStrict {
		return fmt.Sprintf("allowlist-only (%d allowlist, %d blocklist)", len(cfg.APIAllowlist), len(cfg.FetchProxy.Monitoring.Blocklist))
	}
	if cfg.Enforce != nil && !*cfg.Enforce {
		return fmt.Sprintf("audit/blocklist (%d blocklist, allowlist not enforced)", len(cfg.FetchProxy.Monitoring.Blocklist))
	}
	return fmt.Sprintf("blocklist posture (%d blocklist, %d allowlist available)", len(cfg.FetchProxy.Monitoring.Blocklist), len(cfg.APIAllowlist))
}

func description(name string) string {
	switch name {
	case config.ModeStrict:
		return "Agent can only reach allowlisted API domains."
	case config.ModeBalanced:
		return "General-purpose monitored browsing posture."
	case config.ModeAudit:
		return "Evaluation mode; detects and logs without enforcing."
	case PresetClaudeCode:
		return "Coding-agent preset with stricter response handling."
	case PresetCursor:
		return "IDE preset with coding and Cursor domains."
	case PresetGenericAgent:
		return "Broad tuning preset for new agents."
	case PresetHostileModel:
		return "Strict posture for agents that cannot be trusted to refuse."
	default:
		return ""
	}
}

// YAML returns the config YAML bytes for a built-in preset.
func YAML(name string) ([]byte, error) {
	if isFilePreset(name) {
		data, _, err := filePreset(name)
		return data, err
	}
	cfg, err := Config(name)
	if err != nil {
		return nil, err
	}
	return marshal(cfg)
}

// Config returns a parsed config for a built-in preset.
func Config(name string) (*config.Config, error) {
	switch name {
	case config.ModeStrict:
		return validatedConfig(name, strictPreset())
	case config.ModeBalanced:
		return validatedConfig(name, config.Defaults())
	case config.ModeAudit:
		return validatedConfig(name, auditPreset())
	case PresetClaudeCode, PresetCursor, PresetGenericAgent, PresetHostileModel:
		_, cfg, err := filePreset(name)
		return cfg, err
	default:
		return nil, UnknownError(name)
	}
}

func UnknownError(name string) error {
	return fmt.Errorf("unknown preset %q: choose %s", name, ValidNames)
}

func isFilePreset(name string) bool {
	switch name {
	case PresetClaudeCode, PresetCursor, PresetGenericAgent, PresetHostileModel:
		return true
	default:
		return false
	}
}

func filePreset(name string) ([]byte, *config.Config, error) {
	data, ok := configs.Preset(name)
	if !ok {
		return nil, nil, fmt.Errorf("preset %q is not embedded", name)
	}
	cfg, err := parseConfig(data)
	if err != nil {
		return nil, nil, fmt.Errorf("validating preset %q: %w", name, err)
	}
	return data, cfg, nil
}

func validatedConfig(name string, cfg *config.Config) (*config.Config, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("validating preset %q: %w", name, err)
	}
	return cfg, nil
}

func marshal(cfg *config.Config) ([]byte, error) {
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return nil, fmt.Errorf("marshaling config: %w", err)
	}
	return data, nil
}

func parseConfig(data []byte) (*config.Config, error) {
	cfg := &config.Config{}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(cfg); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("empty YAML document")
		}
		return nil, fmt.Errorf("decoding preset config: %w", err)
	}
	var extra yaml.Node
	if err := decoder.Decode(&extra); err == nil {
		return nil, fmt.Errorf("multiple YAML documents not supported")
	} else if !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("decoding preset config: %w", err)
	}
	if err := requireMappingDocument(data); err != nil {
		return nil, err
	}
	cfg.ApplyDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func requireMappingDocument(data []byte) error {
	var doc yaml.Node
	if err := yaml.NewDecoder(bytes.NewReader(data)).Decode(&doc); err != nil {
		if errors.Is(err, io.EOF) {
			return fmt.Errorf("empty YAML document")
		}
		return fmt.Errorf("decoding preset document: %w", err)
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return fmt.Errorf("preset YAML must be a non-empty mapping document")
	}
	return nil
}

func strictPreset() *config.Config {
	cfg := config.Defaults()
	cfg.Mode = config.ModeStrict
	// In strict mode, the fetch proxy enforces the API allowlist.
	cfg.FetchProxy.Monitoring.EntropyThreshold = 3.5
	cfg.FetchProxy.Monitoring.SubdomainEntropyThreshold = 3.5
	cfg.FetchProxy.Monitoring.MaxURLLength = 500
	cfg.FetchProxy.Monitoring.MaxReqPerMinute = 30
	return cfg
}

func auditPreset() *config.Config {
	cfg := config.Defaults()
	cfg.Mode = config.ModeAudit
	// Audit mode: detect and log everything but never block.
	// All DLP patterns, blocklists, and entropy checks stay active for
	// visibility - enforce=false makes them log-only.
	enforce := false
	cfg.Enforce = &enforce
	cfg.Logging.IncludeAllowed = true
	cfg.Logging.IncludeBlocked = true
	return cfg
}
