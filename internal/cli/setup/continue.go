// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/discover"
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
	cmd := &cobra.Command{
		Use: "install", Short: "Wrap Continue MCP servers through pipelock", SilenceUsage: true, SilenceErrors: true, Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runContinue(cmd, path, mcpDir, dryRun, configFile, false)
		},
	}
	cmd.Flags().StringVar(&path, "path", "", "path to config.yaml (default ~/.continue/config.yaml)")
	cmd.Flags().StringVar(&mcpDir, "mcp-dir", "", "path to standalone MCP block directory (default ~/.continue/mcpServers)")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "show changes without modifying files")
	cmd.Flags().StringVarP(&configFile, "config", "c", "", "path to pipelock config file for --config passthrough")
	return cmd
}

func continueRemoveCmd() *cobra.Command {
	var path, mcpDir string
	var dryRun bool
	cmd := &cobra.Command{
		Use: "remove", Short: "Remove pipelock wrapping from Continue MCP servers", SilenceUsage: true, SilenceErrors: true, Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error { return runContinue(cmd, path, mcpDir, dryRun, "", true) },
	}
	cmd.Flags().StringVar(&path, "path", "", "path to config.yaml (default ~/.continue/config.yaml)")
	cmd.Flags().StringVar(&mcpDir, "mcp-dir", "", "path to standalone MCP block directory (default ~/.continue/mcpServers)")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "show changes without modifying files")
	return cmd
}

func continuePaths(path, mcpDir string) (string, string, error) {
	if path != "" && filepath.Base(path) == continueLegacyName {
		return "", "", fmt.Errorf("%s is deprecated; rename or remove it and create %s instead, because wrapping JSON would be inert", continueLegacyName, continueConfigName)
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

// runContinue plans every target before writing any target. Parse and planning
// errors therefore fail closed without rewriting a Continue file. A later write
// error can leave earlier targets changed, but each changed target has a .bak.
func runContinue(cmd *cobra.Command, path, mcpDir string, dryRun bool, configFile string, remove bool) error {
	configPath, blocksDir, err := continuePaths(path, mcpDir)
	if err != nil {
		return err
	}
	if !remove {
		// Continue's migration guide says: "If a config.yaml file is present,
		// it will be loaded instead of config.json."
		// https://docs.continue.dev/reference/yaml-migration
		legacyPath := filepath.Join(filepath.Dir(configPath), continueLegacyName)
		if _, err := os.Stat(legacyPath); err == nil {
			if _, configErr := os.Stat(configPath); configErr == nil {
				_, _ = fmt.Fprintln(cmd.ErrOrStderr(), "note: deprecated config.json is present and ignored because config.yaml takes precedence")
			} else if errors.Is(configErr, os.ErrNotExist) {
				return fmt.Errorf("found deprecated %s but no %s; rename or remove the legacy file before creating %s, because wrapping it would be inert", continueLegacyName, continueConfigName, continueConfigName)
			} else {
				return fmt.Errorf("checking %s: %w", configPath, configErr)
			}
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
		if discover.IsContinueConfigExtension(filepath.Ext(entry.Name())) {
			targets = append(targets, filepath.Join(blocksDir, entry.Name()))
		}
	}
	sort.Strings(targets[1:])
	plans := make([]continuePlan, 0, len(targets))
	var warnings strings.Builder
	for _, target := range targets {
		plan, err := planContinueFile(target, exe, configFile, remove)
		if err != nil {
			return err
		}
		warnings.WriteString(plan.warnings)
		if plan.exists && plan.changed {
			plans = append(plans, plan)
		}
	}
	_, _ = fmt.Fprint(cmd.ErrOrStderr(), warnings.String())
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
	warnings         string
}

type continueEntryRewrite struct {
	index       int
	original    *yaml.Node
	replacement *yaml.Node
}

var encodeContinueDocument = marshalContinueDocument

func planContinueFile(path, exe, configFile string, remove bool) (continuePlan, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if errors.Is(err, os.ErrNotExist) {
		return continuePlan{path: path}, nil
	}
	if err != nil {
		return continuePlan{}, fmt.Errorf("reading %s: %w", path, err)
	}
	var document yaml.Node
	if err := yaml.Unmarshal(data, &document); err != nil {
		return continuePlan{}, fmt.Errorf("parsing %s: %w", path, err)
	}
	serversNode, found, err := continueServersNode(&document)
	if err != nil {
		return continuePlan{}, fmt.Errorf("parsing %s: %w", path, err)
	}
	if !found {
		return continuePlan{path: path, original: data, exists: true}, nil
	}
	if serversNode.Kind != yaml.SequenceNode {
		return continuePlan{}, fmt.Errorf("parsing %s: %s must be a list", path, continueServersKey)
	}
	changed := false
	var warnings bytes.Buffer
	rewrites := make([]continueEntryRewrite, 0, len(serversNode.Content))
	for i, serverNode := range serversNode.Content {
		if serverNode.Kind != yaml.MappingNode {
			return continuePlan{}, fmt.Errorf("parsing %s: mcpServers[%d] must be a mapping", path, i)
		}
		server := make(map[string]interface{})
		if err := serverNode.Decode(&server); err != nil {
			return continuePlan{}, fmt.Errorf("parsing %s: mcpServers[%d]: %w", path, i, err)
		}
		name := continueServerName(server, i)
		var result map[string]interface{}
		if remove {
			if !isRestorableWrapper(server) {
				warnUnrestorableWrapper(&warnings, name, server)
				continue
			}
			result, err = unwrapMCPServer(server)
		} else {
			if isWrappedBySelf(server) {
				continue
			}
			warnForeignWrapper(&warnings, name, server)
			result, err = wrapContinueServer(server, exe, configFile)
		}
		if err != nil {
			return continuePlan{}, fmt.Errorf("%s mcpServers[%d]: %w", path, i, err)
		}
		newNode, err := continueServerNode(result)
		if err != nil {
			return continuePlan{}, fmt.Errorf("marshaling %s mcpServers[%d]: %w", path, i, err)
		}
		rewrites = append(rewrites, continueEntryRewrite{index: i, original: serverNode, replacement: newNode})
		changed = true
	}
	if !changed {
		return continuePlan{path: path, original: data, exists: true, warnings: warnings.String()}, nil
	}
	for _, rewrite := range rewrites {
		if anchor := continueAliasToEntry(&document, rewrite.original); anchor != "" {
			return continuePlan{}, fmt.Errorf("parsing %s: mcpServers[%d] is referenced by anchor %q; inline it before wrapping", path, rewrite.index, anchor)
		}
		if anchor := continueAnchorWithin(rewrite.original); anchor != "" {
			return continuePlan{}, fmt.Errorf("parsing %s: mcpServers[%d] contains anchor %q; inline it before wrapping", path, rewrite.index, anchor)
		}
	}
	for _, rewrite := range rewrites {
		serversNode.Content[rewrite.index] = rewrite.replacement
	}
	output, err := encodeContinueDocument(&document)
	if err != nil {
		return continuePlan{}, fmt.Errorf("marshaling %s: %w", path, err)
	}
	if continueHasDocumentMarker(data) && !continueHasDocumentMarker(output) {
		output = append([]byte("---\n"), output...)
	}
	var verified yaml.Node
	if err := yaml.Unmarshal(output, &verified); err != nil {
		return continuePlan{}, fmt.Errorf("marshaling %s: rewritten YAML does not parse: %w", path, err)
	}
	return continuePlan{path: path, original: data, output: output, exists: true, changed: true, warnings: warnings.String()}, nil
}

func marshalContinueDocument(document *yaml.Node) ([]byte, error) {
	var output bytes.Buffer
	encoder := yaml.NewEncoder(&output)
	encoder.SetIndent(2)
	if err := encoder.Encode(document); err != nil {
		return nil, err
	}
	if err := encoder.Close(); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}

func continueHasDocumentMarker(data []byte) bool {
	return bytes.HasPrefix(data, []byte("---\n")) || bytes.HasPrefix(data, []byte("---\r\n"))
}

func continueAnchorWithin(node *yaml.Node) string {
	if node.Anchor != "" {
		return node.Anchor
	}
	for _, child := range node.Content {
		if anchor := continueAnchorWithin(child); anchor != "" {
			return anchor
		}
	}
	return ""
}

func continueAliasToEntry(document, entry *yaml.Node) string {
	if document.Kind == yaml.AliasNode && continueNodeContains(entry, document.Alias) {
		return document.Alias.Anchor
	}
	for _, child := range document.Content {
		if anchor := continueAliasToEntry(child, entry); anchor != "" {
			return anchor
		}
	}
	return ""
}

func continueNodeContains(root, candidate *yaml.Node) bool {
	if root == candidate {
		return true
	}
	for _, child := range root.Content {
		if continueNodeContains(child, candidate) {
			return true
		}
	}
	return false
}

func continueServersNode(document *yaml.Node) (*yaml.Node, bool, error) {
	if document.Kind != yaml.DocumentNode || len(document.Content) != 1 || document.Content[0].Kind != yaml.MappingNode {
		return nil, false, errors.New("document must contain a mapping")
	}
	mapping := document.Content[0]
	for i := 0; i < len(mapping.Content); i += 2 {
		if mapping.Content[i].Value == continueServersKey {
			return mapping.Content[i+1], true, nil
		}
	}
	return nil, false, nil
}

func continueServerNode(server map[string]interface{}) (*yaml.Node, error) {
	data, err := yaml.Marshal(server)
	if err != nil {
		return nil, err
	}
	var document yaml.Node
	if err := yaml.Unmarshal(data, &document); err != nil {
		return nil, err
	}
	if len(document.Content) != 1 || document.Content[0].Kind != yaml.MappingNode {
		return nil, errors.New("server must marshal to a mapping")
	}
	return document.Content[0], nil
}

func continueServerName(server map[string]interface{}, index int) string {
	if name, ok := server["name"].(string); ok && name != "" {
		return name
	}
	return fmt.Sprintf("mcpServers[%d]", index)
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
