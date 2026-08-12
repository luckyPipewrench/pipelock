// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package guard implements the Guard command plus read-only declaration and
// compiled-floor inspection.
package guard

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	cliruntime "github.com/luckyPipewrench/pipelock/internal/cli/runtime"
	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/sandbox"
)

const (
	reportSchemaVersion = "1"
	defaultConfigLabel  = "(built-in defaults)"
	enforcementNotice   = "This inspection command does not enforce Guard. These results describe declarations and the compiled validation floor only; no workload is constrained."
	guardBoundaryNotice = "Linux HTTP/HTTPS preview: non-proxy TCP, UDP, QUIC, and child DNS are denied. Host ownership maps to the caller UID while the namespace UID may be 0. Same-UID host brokers remain outside this boundary."
)

type commandOptions struct {
	configFile string
	profile    string
	workspace  string
	dryRun     bool
	jsonOutput bool
}

type reportHeader struct {
	SchemaVersion     string `json:"schema_version"`
	Command           string `json:"command"`
	Enforced          bool   `json:"enforced"`
	EnforcementNotice string `json:"enforcement_notice"`
	ConfigFile        string `json:"config_file"`
}

type grantMatch struct {
	Manifest  string   `json:"manifest"`
	GrantType string   `json:"grant_type"`
	Scope     string   `json:"scope"`
	Path      string   `json:"path"`
	Profiles  []string `json:"profiles"`
	Effective bool     `json:"effective"`
}

type accessDecision struct {
	Operation      string       `json:"operation"`
	WouldBeAllowed bool         `json:"would_be_allowed"`
	Source         string       `json:"source"`
	Rule           string       `json:"rule"`
	Matched        string       `json:"matched"`
	Reason         string       `json:"reason"`
	Configurable   bool         `json:"configurable"`
	Grants         []grantMatch `json:"grants"`
}

type explainReport struct {
	reportHeader
	Scope        string         `json:"scope"`
	Path         string         `json:"path"`
	ResolvedPath string         `json:"resolved_path"`
	Read         accessDecision `json:"read"`
	Write        accessDecision `json:"write"`
}

type floorRefusal struct {
	Operation string `json:"operation"`
	Rule      string `json:"rule"`
	Matched   string `json:"matched"`
	Reason    string `json:"reason"`
}

type grantReport struct {
	GrantType    string         `json:"grant_type"`
	Scope        string         `json:"scope"`
	Path         string         `json:"path"`
	ResolvedPath string         `json:"resolved_path"`
	Refusals     []floorRefusal `json:"floor_refusals"`
}

type manifestReport struct {
	Name   string        `json:"name"`
	Grants []grantReport `json:"grants"`
}

type showReport struct {
	reportHeader
	Profile   string           `json:"profile"`
	Manifests []manifestReport `json:"manifests"`
}

// Cmd returns the parent `pipelock guard` command.
func Cmd() *cobra.Command {
	opts := &commandOptions{}
	cmd := &cobra.Command{
		Use:          "guard [flags] -- COMMAND [ARGS...]",
		Short:        "Run a command in the Linux HTTP/HTTPS egress-guard preview",
		Long:         "Run a command in the Linux HTTP/HTTPS egress-guard preview.\n\n" + guardBoundaryNotice,
		SilenceUsage: true,
		Args:         cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return cmd.Help()
			}
			dashIdx := cmd.ArgsLenAtDash()
			if dashIdx != 0 || dashIdx >= len(args) {
				return errors.New("usage: pipelock guard [flags] -- COMMAND [ARGS...]")
			}
			if opts.jsonOutput && !opts.dryRun {
				return errors.New("--json requires --dry-run, guard show, or guard explain")
			}
			command := args[dashIdx:]
			cfg, err := loadRuntimeConfig(opts.configFile)
			if err != nil {
				return cliutil.ExitCodeError(cliutil.ExitConfig, err)
			}
			workspace, err := resolveWorkspace(opts.workspace, cfg.Sandbox.Workspace)
			if err != nil {
				return err
			}
			if opts.dryRun {
				result, preflightErr := cliruntime.GuardPreflight(cfg, opts.profile, workspace, command)
				if preflightErr != nil {
					return cliutil.ExitCodeError(cliutil.ExitConfig, preflightErr)
				}
				if opts.jsonOutput {
					if err := writeJSON(cmd.OutOrStdout(), "guard", result); err != nil {
						return err
					}
				} else {
					if err := renderGuardPreflight(cmd.OutOrStdout(), result); err != nil {
						return err
					}
				}
				if result.Status != sandbox.StatusReady {
					return cliutil.ExitCodeError(2, errors.New("guard preflight failed"))
				}
				return nil
			}
			_, _ = fmt.Fprintln(cmd.ErrOrStderr(), "pipelock guard: "+guardBoundaryNotice)
			launchErr := cliruntime.LaunchGuard(cliruntime.GuardLaunchOptions{
				Context: cmd.Context(), Config: cfg, Profile: opts.profile,
				Workspace: workspace, Command: command, Stderr: cmd.ErrOrStderr(),
			})
			return preserveCommandExitCode(launchErr)
		},
	}
	cmd.PersistentFlags().StringVarP(&opts.configFile, "config", "c", "", "config file path (default: built-in defaults)")
	cmd.PersistentFlags().StringVar(&opts.profile, "profile", "", "guard profile selecting state manifests")
	cmd.PersistentFlags().StringVar(&opts.workspace, "workspace", "", "workspace directory (default: sandbox.workspace or current directory)")
	cmd.PersistentFlags().BoolVar(&opts.dryRun, "dry-run", false, "validate and probe the Linux HTTP/HTTPS preview without launching")
	cmd.PersistentFlags().BoolVar(&opts.jsonOutput, "json", false, "output reports as JSON")
	cmd.AddCommand(explainCmd(opts), showCmd(opts))
	return cmd
}

func preserveCommandExitCode(err error) error {
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return cliutil.ExitCodeError(exitErr.ExitCode(), err)
	}
	return err
}

func explainCmd(opts *commandOptions) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "explain <absolute-path>",
		Short: "Explain read and write declarations and compiled-floor refusals",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, label, err := loadConfig(opts.configFile)
			if err != nil {
				return cliutil.ExitCodeError(cliutil.ExitConfig, err)
			}
			report, err := buildExplainReport(cfg, label, args[0])
			if err != nil {
				return cliutil.ExitCodeError(cliutil.ExitConfig, err)
			}
			if opts.jsonOutput {
				return writeJSON(cmd.OutOrStdout(), "guard explain", report)
			}
			return writeHuman(cmd.OutOrStdout(), renderExplain(report))
		},
	}
	return cmd
}

func showCmd(opts *commandOptions) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "show <profile>",
		Short: "Show a profile's resolved manifests, grants, and floor refusals",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, label, err := loadConfig(opts.configFile)
			if err != nil {
				return cliutil.ExitCodeError(cliutil.ExitConfig, err)
			}
			report, err := buildShowReport(cfg, label, args[0])
			if err != nil {
				return cliutil.ExitCodeError(cliutil.ExitConfig, err)
			}
			if opts.jsonOutput {
				return writeJSON(cmd.OutOrStdout(), "guard show", report)
			}
			return writeHuman(cmd.OutOrStdout(), renderShow(report))
		},
	}
	return cmd
}

func loadConfig(path string) (*config.Config, string, error) {
	if path == "" {
		cfg := config.Defaults()
		if err := cfg.ValidateGuardStructure(); err != nil {
			return nil, "", fmt.Errorf("validating built-in guard declaration: %w", err)
		}
		return cfg, defaultConfigLabel, nil
	}
	cfg, err := config.LoadForInspection(path)
	if err != nil {
		return nil, "", fmt.Errorf("loading config %q for guard inspection: %w", path, err)
	}
	if err := cfg.ValidateGuardStructure(); err != nil {
		return nil, "", fmt.Errorf("invalid guard declaration: %w", err)
	}
	return cfg, path, nil
}

func loadRuntimeConfig(path string) (*config.Config, error) {
	if path == "" {
		cfg := config.Defaults()
		if err := cfg.Validate(); err != nil {
			return nil, fmt.Errorf("validating built-in config: %w", err)
		}
		return cfg, nil
	}
	if path == "-" {
		return nil, errors.New("guard runtime config cannot be read from stdin because stdin belongs to the operator command")
	}
	configInfo, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("loading guard config %q: %w", path, err)
	}
	stdinInfo, err := os.Stdin.Stat()
	if err != nil {
		return nil, fmt.Errorf("inspecting operator-command stdin: %w", err)
	}
	if os.SameFile(configInfo, stdinInfo) {
		return nil, errors.New("guard runtime config cannot alias stdin because stdin belongs to the operator command")
	}
	if !configInfo.Mode().IsRegular() {
		return nil, fmt.Errorf("loading guard config %q: not a regular file", path)
	}
	cfg, err := config.Load(path)
	if err != nil {
		return nil, fmt.Errorf("loading guard config %q: %w", path, err)
	}
	return cfg, nil
}

func resolveWorkspace(flagValue, configured string) (string, error) {
	workspace := flagValue
	if workspace == "" {
		workspace = configured
	}
	if workspace == "" {
		var err error
		workspace, err = os.Getwd()
		if err != nil {
			return "", fmt.Errorf("resolving workspace: %w", err)
		}
	}
	resolved, err := filepath.Abs(workspace)
	if err != nil {
		return "", fmt.Errorf("resolving workspace: %w", err)
	}
	return resolved, nil
}

func renderGuardPreflight(w io.Writer, result sandbox.PreflightResult) error {
	if _, err := fmt.Fprintf(w, "Guard Preflight: %s\n", strings.ToUpper(result.Status)); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, "  Surface: Linux HTTP/HTTPS preview"); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "  Workspace: %s\n", result.Workspace); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, "  Boundary: "+guardBoundaryNotice); err != nil {
		return err
	}
	for _, layer := range result.Layers {
		state := "available"
		if !layer.Available {
			state = "unavailable"
		}
		if layer.Reason != "" {
			state += ": " + layer.Reason
		}
		if _, err := fmt.Fprintf(w, "  %s: %s (required=%t)\n", layer.Name, state, layer.Required); err != nil {
			return err
		}
	}
	for _, item := range result.Warnings {
		if _, err := fmt.Fprintf(w, "  WARNING: %s\n", item); err != nil {
			return err
		}
	}
	for _, item := range result.Errors {
		if _, err := fmt.Fprintf(w, "  ERROR: %s\n", item); err != nil {
			return err
		}
	}
	return nil
}

func newHeader(command, configFile string) reportHeader {
	return reportHeader{
		SchemaVersion:     reportSchemaVersion,
		Command:           command,
		Enforced:          false,
		EnforcementNotice: enforcementNotice,
		ConfigFile:        configFile,
	}
}

func buildExplainReport(cfg *config.Config, configFile, path string) (explainReport, error) {
	readFloor, err := config.ExplainGuardPathFloor(path, config.GuardAccessRead)
	if err != nil {
		return explainReport{}, fmt.Errorf("explaining read access: %w", err)
	}
	writeFloor, err := config.ExplainGuardPathFloor(path, config.GuardAccessWrite)
	if err != nil {
		return explainReport{}, fmt.Errorf("explaining write access: %w", err)
	}
	if readFloor.ResolvedPath != writeFloor.ResolvedPath {
		return explainReport{}, fmt.Errorf("path resolution changed while inspecting %q; retry", path)
	}

	profiles := manifestProfiles(cfg.Guard)
	return explainReport{
		reportHeader: newHeader("explain", configFile),
		Scope:        "all_declared_profiles",
		Path:         path,
		ResolvedPath: readFloor.ResolvedPath,
		Read:         decideAccess(cfg.Guard, profiles, path, config.GuardAccessRead, readFloor),
		Write:        decideAccess(cfg.Guard, profiles, path, config.GuardAccessWrite, writeFloor),
	}, nil
}

func manifestProfiles(guard config.Guard) map[string][]string {
	profiles := make(map[string][]string, len(guard.Manifests))
	for _, profile := range guard.Profiles {
		for _, manifest := range profile.Manifests {
			profiles[manifest] = append(profiles[manifest], profile.Name)
		}
	}
	return profiles
}

func decideAccess(guard config.Guard, profiles map[string][]string, path string, access config.GuardAccess, floor config.GuardFloorDecision) accessDecision {
	matches := matchingGrants(guard, profiles, path, access)
	decision := accessDecision{
		Operation:    string(access),
		Configurable: true,
		Grants:       matches,
	}
	if floor.Refused {
		decision.Source = "compiled_floor"
		decision.Rule = floor.Rule
		decision.Matched = floor.Matched
		decision.Reason = floor.Reason + "; this refusal cannot be configured away"
		decision.Configurable = false
		return decision
	}
	for _, match := range matches {
		if match.Effective {
			decision.WouldBeAllowed = true
			decision.Source = "operator_declared"
			if match.Scope == "directory" {
				decision.Rule = "directory_subtree_grant"
				decision.Reason = "one or more selected manifests declare a directory subtree grant"
			} else {
				decision.Rule = "exact_file_grant"
				decision.Reason = "one or more selected manifests declare an exact file grant"
			}
			decision.Matched = match.Path
			return decision
		}
	}
	decision.Source = "none"
	decision.Rule = "default_no_grant"
	if len(matches) > 0 {
		decision.Reason = "matching grants exist, but no declared profile selects their manifests"
	} else {
		decision.Reason = "no operator-declared file or directory grant covers this path"
	}
	return decision
}

func matchingGrants(guard config.Guard, profiles map[string][]string, path string, access config.GuardAccess) []grantMatch {
	matches := make([]grantMatch, 0)
	cleanPath := filepath.Clean(path)
	for _, manifest := range guard.Manifests {
		selectedBy := append([]string{}, profiles[manifest.Name]...)
		if access == config.GuardAccessRead {
			matches = appendGrantMatches(matches, manifest.Name, "read_only", "file", manifest.ReadOnly, selectedBy, cleanPath)
			matches = appendGrantMatches(matches, manifest.Name, "read_only_directories", "directory", manifest.ReadOnlyDirectories, selectedBy, cleanPath)
		}
		matches = appendGrantMatches(matches, manifest.Name, "read_write", "file", manifest.ReadWrite, selectedBy, cleanPath)
		matches = appendGrantMatches(matches, manifest.Name, "read_write_directories", "directory", manifest.ReadWriteDirectories, selectedBy, cleanPath)
	}
	return matches
}

func appendGrantMatches(matches []grantMatch, manifest, grantType, scope string, paths, profiles []string, cleanPath string) []grantMatch {
	for _, declaredPath := range paths {
		cleanDeclared := filepath.Clean(declaredPath)
		matchesPath := cleanDeclared == cleanPath
		if scope == "directory" {
			matchesPath = pathWithinDirectory(cleanPath, cleanDeclared)
		}
		if !matchesPath {
			continue
		}
		selectedBy := append([]string{}, profiles...)
		matches = append(matches, grantMatch{
			Manifest:  manifest,
			GrantType: grantType,
			Scope:     scope,
			Path:      declaredPath,
			Profiles:  selectedBy,
			Effective: len(selectedBy) > 0,
		})
	}
	return matches
}

func pathWithinDirectory(cleanPath, cleanDirectory string) bool {
	if cleanPath == cleanDirectory {
		return true
	}
	if cleanDirectory == string(filepath.Separator) {
		return filepath.IsAbs(cleanPath)
	}
	return strings.HasPrefix(cleanPath, cleanDirectory+string(filepath.Separator))
}

func buildShowReport(cfg *config.Config, configFile, profileName string) (showReport, error) {
	var selected *config.GuardProfile
	for i := range cfg.Guard.Profiles {
		if cfg.Guard.Profiles[i].Name == profileName {
			selected = &cfg.Guard.Profiles[i]
			break
		}
	}
	if selected == nil {
		return showReport{}, fmt.Errorf("guard profile %q not found", profileName)
	}

	manifests := make(map[string]config.GuardManifest, len(cfg.Guard.Manifests))
	for _, manifest := range cfg.Guard.Manifests {
		manifests[manifest.Name] = manifest
	}
	report := showReport{
		reportHeader: newHeader("show", configFile),
		Profile:      profileName,
		Manifests:    make([]manifestReport, 0, len(selected.Manifests)),
	}
	for _, name := range selected.Manifests {
		manifest := manifests[name]
		manifestView := manifestReport{Name: name, Grants: make([]grantReport, 0, len(manifest.ReadOnly)+len(manifest.ReadOnlyDirectories)+len(manifest.ReadWrite)+len(manifest.ReadWriteDirectories))}
		for _, path := range manifest.ReadOnly {
			grant, err := buildGrantReport("read_only", "file", path)
			if err != nil {
				return showReport{}, err
			}
			manifestView.Grants = append(manifestView.Grants, grant)
		}
		for _, path := range manifest.ReadOnlyDirectories {
			grant, err := buildGrantReport("read_only_directories", "directory", path)
			if err != nil {
				return showReport{}, err
			}
			manifestView.Grants = append(manifestView.Grants, grant)
		}
		for _, path := range manifest.ReadWrite {
			grant, err := buildGrantReport("read_write", "file", path)
			if err != nil {
				return showReport{}, err
			}
			manifestView.Grants = append(manifestView.Grants, grant)
		}
		for _, path := range manifest.ReadWriteDirectories {
			grant, err := buildGrantReport("read_write_directories", "directory", path)
			if err != nil {
				return showReport{}, err
			}
			manifestView.Grants = append(manifestView.Grants, grant)
		}
		report.Manifests = append(report.Manifests, manifestView)
	}
	return report, nil
}

func buildGrantReport(grantType, scope, path string) (grantReport, error) {
	accesses := []config.GuardAccess{config.GuardAccessRead}
	if strings.HasPrefix(grantType, "read_write") {
		accesses = append(accesses, config.GuardAccessWrite)
	}
	report := grantReport{
		GrantType: grantType,
		Scope:     scope,
		Path:      path,
		Refusals:  make([]floorRefusal, 0),
	}
	for _, access := range accesses {
		decision, err := config.ExplainGuardPathFloor(path, access)
		if err != nil {
			return grantReport{}, fmt.Errorf("explaining %s grant %q: %w", grantType, path, err)
		}
		if report.ResolvedPath == "" {
			report.ResolvedPath = decision.ResolvedPath
		} else if report.ResolvedPath != decision.ResolvedPath {
			return grantReport{}, fmt.Errorf("path resolution changed while inspecting %q; retry", path)
		}
		if decision.Refused {
			report.Refusals = append(report.Refusals, floorRefusal{
				Operation: string(access),
				Rule:      decision.Rule,
				Matched:   decision.Matched,
				Reason:    decision.Reason,
			})
		}
	}
	return report, nil
}

func writeJSON(w io.Writer, command string, report any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(report); err != nil {
		return fmt.Errorf("encode %s report JSON: %w", command, err)
	}
	return nil
}

func writeHuman(w io.Writer, body string) error {
	if _, err := io.WriteString(w, body); err != nil {
		return fmt.Errorf("write guard report: %w", err)
	}
	return nil
}

// display renders an untrusted value for HUMAN output.
//
// Paths, manifest names and profile names come from an operator's config or
// from a caller's argument, and this command's output is read as evidence. A
// value carrying a newline can forge an extra report line, and one carrying a
// terminal escape can move the cursor or recolour the screen, which is enough
// to hide the "not enforced" warning that every one of these reports is
// required to show. Quoting escapes both, and non-ASCII besides, so a
// look-alike path cannot be passed off as a different one.
//
// JSON output does not need this; encoding/json already escapes controls.
func display(value string) string {
	return strconv.QuoteToASCII(value)
}

// displayText renders untrusted PROSE for human output.
//
// A reason embeds the operator's raw path, so it can carry a newline that
// forges an extra report line or an escape sequence that repositions the
// cursor. Quoting a whole sentence would be unreadable, so control characters
// are replaced instead and the wording is left intact.
func displayText(value string) string {
	return strings.Map(func(r rune) rune {
		if r == '\t' {
			return ' '
		}
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, value)
}

func renderExplain(report explainReport) string {
	var out strings.Builder
	_, _ = fmt.Fprintf(&out, "WARNING: %s\n\n", report.EnforcementNotice)
	_, _ = fmt.Fprintf(&out, "Guard path explanation\nConfig: %s\nScope: all declared profiles\nPath: %s\n", display(report.ConfigFile), display(report.Path))
	if report.ResolvedPath != report.Path {
		_, _ = fmt.Fprintf(&out, "Resolved path: %s\n", display(report.ResolvedPath))
	}
	renderAccess(&out, report.Read)
	renderAccess(&out, report.Write)
	return out.String()
}

func renderAccess(out *strings.Builder, decision accessDecision) {
	_, _ = fmt.Fprintf(out, "\n%s: ", strings.ToUpper(decision.Operation))
	switch decision.Source {
	case "compiled_floor":
		_, _ = fmt.Fprintf(out, "WOULD BE REFUSED BY COMPILED FLOOR (not currently enforced)\n  Rule: %s\n  Matched: %s\n  Reason: %s\n  This compiled-floor refusal cannot be configured away.\n", decision.Rule, display(decision.Matched), displayText(decision.Reason))
	case "operator_declared":
		_, _ = fmt.Fprintln(out, "DECLARED ALLOW (not currently enforced)")
		for _, grant := range decision.Grants {
			if grant.Effective {
				_, _ = fmt.Fprintf(out, "  %s.%s %s %s (profiles: %s)\n", display(grant.Manifest), grant.GrantType, grantScopeLabel(grant.Scope), display(grant.Path), displayText(strings.Join(grant.Profiles, ", ")))
			}
		}
	default:
		_, _ = fmt.Fprintf(out, "NO DECLARED GRANT (not currently enforced)\n  Rule: %s\n  Reason: %s\n", decision.Rule, displayText(decision.Reason))
	}
	for _, grant := range decision.Grants {
		if !grant.Effective {
			_, _ = fmt.Fprintf(out, "  Unselected declaration: %s.%s %s %s (no profile selects this manifest)\n", display(grant.Manifest), grant.GrantType, grantScopeLabel(grant.Scope), display(grant.Path))
		}
	}
}

func grantScopeLabel(scope string) string {
	if scope == "directory" {
		return "directory subtree"
	}
	return "exact file"
}

func renderShow(report showReport) string {
	var out strings.Builder
	_, _ = fmt.Fprintf(&out, "WARNING: %s\n\n", report.EnforcementNotice)
	_, _ = fmt.Fprintf(&out, "Guard profile: %s\nConfig: %s\n", display(report.Profile), display(report.ConfigFile))
	if len(report.Manifests) == 0 {
		_, _ = fmt.Fprintln(&out, "Manifests: none")
		return out.String()
	}
	for _, manifest := range report.Manifests {
		_, _ = fmt.Fprintf(&out, "\nManifest: %s\n", display(manifest.Name))
		if len(manifest.Grants) == 0 {
			_, _ = fmt.Fprintln(&out, "  Grants: none")
			continue
		}
		for _, grant := range manifest.Grants {
			_, _ = fmt.Fprintf(&out, "  - %s %s: %s\n", grant.GrantType, grant.Scope, display(grant.Path))
			if grant.ResolvedPath != grant.Path {
				_, _ = fmt.Fprintf(&out, "    resolved: %s\n", display(grant.ResolvedPath))
			}
			if len(grant.Refusals) == 0 {
				_, _ = fmt.Fprintln(&out, "    compiled floor: no refusal")
				continue
			}
			for _, refusal := range grant.Refusals {
				_, _ = fmt.Fprintf(&out, "    %s COMPILED FLOOR REFUSAL: rule=%s matched=%s\n      %s\n      This refusal cannot be configured away.\n", strings.ToUpper(refusal.Operation), refusal.Rule, display(refusal.Matched), displayText(refusal.Reason))
			}
		}
	}
	return out.String()
}
