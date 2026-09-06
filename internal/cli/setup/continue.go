// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

const (
	continueDirname        = ".continue"
	continueConfigName     = "config.yaml"
	continueLegacyName     = "config.json"
	continueMCPDirname     = "mcpServers"
	continueServersKey     = "mcpServers"
	continueTypeSSE        = "sse"
	continueTypeStreamHTTP = "streamable-http"
)

// ContinueCmd returns the `pipelock continue` command tree.
func ContinueCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "continue", Short: "Continue.dev integration"}
	cmd.AddCommand(continueInstallCmd(), continueRemoveCmd())
	return cmd
}

func continueInstallCmd() *cobra.Command {
	var path, mcpDir, configFile string
	var dryRun bool
	cmd := &cobra.Command{Use: "install", Short: "Wrap Continue MCP servers through pipelock", SilenceUsage: true, SilenceErrors: true, Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runContinue(cmd, path, mcpDir, dryRun, configFile, false)
		}}
	cmd.Flags().StringVar(&path, "path", "", "path to config.yaml (default ~/.continue/config.yaml)")
	cmd.Flags().StringVar(&mcpDir, "mcp-dir", "", "path to standalone MCP block directory (default ~/.continue/mcpServers)")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "show changes without modifying files")
	cmd.Flags().StringVarP(&configFile, "config", "c", "", "path to pipelock config file for --config passthrough")
	return cmd
}

func continueRemoveCmd() *cobra.Command {
	var path, mcpDir string
	var dryRun bool
	cmd := &cobra.Command{Use: "remove", Short: "Remove pipelock wrapping from Continue MCP servers", SilenceUsage: true, SilenceErrors: true, Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error { return runContinue(cmd, path, mcpDir, dryRun, "", true) }}
	cmd.Flags().StringVar(&path, "path", "", "path to config.yaml (default ~/.continue/config.yaml)")
	cmd.Flags().StringVar(&mcpDir, "mcp-dir", "", "path to standalone MCP block directory (default ~/.continue/mcpServers)")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "show changes without modifying files")
	return cmd
}

func continuePaths(path, mcpDir string) (string, string, error) {
	if path != "" && filepath.Base(path) == continueLegacyName {
		return "", "", fmt.Errorf("%s is deprecated and unsupported; migrate it to %s first", continueLegacyName, continueConfigName)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", "", fmt.Errorf("finding home directory: %w", err)
	}
	if path == "" {
		path = filepath.Join(home, continueDirname, continueConfigName)
	}
	if mcpDir == "" {
		mcpDir = filepath.Join(home, continueDirname, continueMCPDirname)
	}
	return path, mcpDir, nil
}

// runContinue plans every target before writing any target. A malformed config
// therefore fails closed: no Continue file is partially rewritten.
func runContinue(cmd *cobra.Command, path, mcpDir string, dryRun bool, configFile string, remove bool) error {
	configPath, blocksDir, err := continuePaths(path, mcpDir)
	if err != nil {
		return err
	}
	if !remove {
		if _, err := os.Stat(filepath.Join(filepath.Dir(configPath), continueLegacyName)); err == nil {
			return fmt.Errorf("found deprecated %s; migrate it to %s before installing", continueLegacyName, continueConfigName)
		}
	}
	exe, err := resolvePipelockBinary()
	if err != nil {
		return err
	}
	configFile = discoverConfigForWrap(cmd, configFile)
	targets := []string{configPath}
	entries, err := os.ReadDir(filepath.Clean(blocksDir))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("reading standalone MCP directory: %w", err)
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		ext := strings.ToLower(filepath.Ext(entry.Name()))
		if ext == ".yaml" || ext == ".yml" {
			targets = append(targets, filepath.Join(blocksDir, entry.Name()))
		}
	}
	sort.Strings(targets[1:])
	plans := make([]continuePlan, 0, len(targets))
	for _, target := range targets {
		plan, err := planContinueFile(target, exe, configFile, remove)
		if err != nil {
			return err
		}
		if plan.exists && plan.changed {
			plans = append(plans, plan)
		}
	}
	if dryRun {
		for _, plan := range plans {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Would write to %s:\n%s", plan.path, plan.output)
		}
		return nil
	}
	for _, plan := range plans {
		if err := os.WriteFile(plan.path+".bak", plan.original, 0o600); err != nil {
			return fmt.Errorf("creating backup for %s: %w", plan.path, err)
		}
		if err := vscodeAtomicWrite(plan.path, plan.output, filepath.Dir(plan.path)); err != nil {
			return err
		}
	}
	verb := "Wrapped"
	if remove {
		verb = "Unwrapped"
	}
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s Continue MCP servers in %d file(s)\n", verb, len(plans))
	return nil
}

type continuePlan struct {
	path             string
	original, output []byte
	exists, changed  bool
}

func planContinueFile(path, exe, configFile string, remove bool) (continuePlan, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if errors.Is(err, os.ErrNotExist) {
		return continuePlan{path: path}, nil
	}
	if err != nil {
		return continuePlan{}, fmt.Errorf("reading %s: %w", path, err)
	}
	var document map[string]interface{}
	if err := yaml.Unmarshal(data, &document); err != nil {
		return continuePlan{}, fmt.Errorf("parsing %s: %w", path, err)
	}
	raw, ok := document[continueServersKey]
	if !ok || raw == nil {
		return continuePlan{path: path, original: data, exists: true}, nil
	}
	servers, ok := raw.([]interface{})
	if !ok {
		return continuePlan{}, fmt.Errorf("parsing %s: %s must be a list", path, continueServersKey)
	}
	changed := false
	for i, rawServer := range servers {
		server, ok := rawServer.(map[string]interface{})
		if !ok {
			return continuePlan{}, fmt.Errorf("parsing %s: mcpServers[%d] must be a mapping", path, i)
		}
		var result map[string]interface{}
		if remove {
			if !isRestorableWrapper(server) {
				continue
			}
			result, err = unwrapMCPServer(server)
		} else {
			if isWrappedBySelf(server) {
				continue
			}
			result, err = wrapContinueServer(server, exe, configFile)
		}
		if err != nil {
			return continuePlan{}, fmt.Errorf("%s mcpServers[%d]: %w", path, i, err)
		}
		servers[i] = result
		changed = true
	}
	if !changed {
		return continuePlan{path: path, original: data, exists: true}, nil
	}
	document[continueServersKey] = servers
	output, err := yaml.Marshal(document)
	if err != nil {
		return continuePlan{}, fmt.Errorf("marshaling %s: %w", path, err)
	}
	return continuePlan{path: path, original: data, output: output, exists: true, changed: true}, nil
}

func wrapContinueServer(server map[string]interface{}, exe, configFile string) (map[string]interface{}, error) {
	_, hasCommand := server[mcpFieldCommand]
	_, hasURL := server[mcpFieldURL]
	if hasCommand == hasURL {
		return nil, fmt.Errorf("server must contain exactly one of command or url")
	}
	typ, _ := server[mcpFieldType].(string)
	omitted := typ == ""
	if typ == "" {
		if hasCommand {
			typ = vsTypeStdio
		} else {
			typ = continueTypeStreamHTTP
		}
	}
	if typ != vsTypeStdio && typ != continueTypeSSE && typ != continueTypeStreamHTTP {
		return nil, fmt.Errorf("unsupported server type %q", typ)
	}
	result := make(map[string]interface{}, len(server)+1)
	for key, value := range server {
		if key != mcpFieldCommand && key != mcpFieldArgs && key != mcpFieldURL && key != mcpFieldType && key != mcpFieldPipelock {
			result[key] = value
		}
	}
	meta := &pipelockMeta{OriginalType: typ, TypeOmitted: omitted}
	args := []string{"mcp", "proxy"}
	if configFile != "" {
		args = append(args, "--config", configFile)
	}
	args = append(args, buildEnvFlags(server)...)
	if hasCommand {
		original, ok := server[mcpFieldCommand].(string)
		if !ok || original == "" {
			return nil, fmt.Errorf("stdio server missing command")
		}
		meta.OriginalCommand = original
		meta.OriginalArgs = interfaceSliceToStrings(server[mcpFieldArgs])
		args = append(args, "--", original)
		args = append(args, meta.OriginalArgs...)
	} else {
		url, ok := server[mcpFieldURL].(string)
		if !ok || url == "" {
			return nil, fmt.Errorf("remote server missing url")
		}
		meta.OriginalURL = url
		args = append(args, "--upstream", url)
	}
	result[mcpFieldType] = vsTypeStdio
	result[mcpFieldCommand] = exe
	result[mcpFieldArgs] = args
	metaRaw, err := json.Marshal(meta)
	if err != nil {
		return nil, err
	}
	var metaMap map[string]interface{}
	if err := json.Unmarshal(metaRaw, &metaMap); err != nil {
		return nil, err
	}
	result[mcpFieldPipelock] = metaMap
	return result, nil
}
