// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package mcpwrap rewrites MCP server declarations so that every tool call,
// response, and description routes through `pipelock mcp proxy` for
// bidirectional scanning.
//
// The wrap is config-format agnostic: it operates on a single decoded server
// entry (map[string]interface{}) using the conventional MCP fields
// (command/args/env for stdio, url/headers for HTTP). The same engine backs
// the VS Code and Hermes integrations. Other installers remain on their legacy
// helpers until their host-specific behavior has parity tests.
//
// Credential safety: HTTP servers carrying auth `headers` never have those
// values placed on the wrapped argv (which would expose them via
// /proc/<pid>/cmdline). Instead the header lines are written to an
// operator-private 0o600 sidecar file and referenced through `--header-file`.
//
// Purity: WrapServer and UnwrapServer do not touch the filesystem. They return
// a *SidecarOp describing the file write/delete that the caller must apply at
// the correct point in its own commit sequence (writes before the canonical
// config rename, deletes only after the restored config is committed, neither
// on dry-run). This keeps the credential carrier's lifecycle consistent with
// the config that references it even when a later step fails.
//
// Migration status: the Cline / OpenCode / Zed / JetBrains installers under
// internal/cli/setup predate this package and still carry copies of the wrap
// logic. Moving them onto this package - one installer family at a
// time, gated by golden parity tests that compare wrapped JSON, metadata, and
// sidecar output against the existing implementation - is tracked as a focused
// follow-up so a feature did not have to depend on a broad installer refactor.
// Two behaviors here are intentional, parity-affecting improvements over those
// installers: type-less configs infer transport from url presence (rather than
// requiring a pre-mutation hack), and the wrapped entry omits a `type` field
// when the source omitted one (rather than always emitting `type: stdio`).
package mcpwrap

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
)

// WrapperState describes whether an MCP server invocation actually runs this
// executable's proxy. Only WrapperSelf proves that this process mediates the
// server's traffic.
type WrapperState int

const (
	WrapperNone WrapperState = iota
	WrapperSelf
	WrapperForeign
)

// ClassifyInvocation classifies a command by proxy shape and file identity.
// Names and metadata are not proof: both can be supplied by the config being
// inspected.
func ClassifyInvocation(command string, args []string) WrapperState {
	if command == "" || len(args) < 2 || args[0] != subcmdMCP || args[1] != subcmdProxy {
		return WrapperNone
	}
	self, err := os.Executable()
	return classifyExecutable(command, self, err)
}

// ClassifyInvocationAgainst classifies a proxy invocation against an explicit
// executable selected by the caller. This is for generators that intentionally
// target a different installed Pipelock path than the binary generating the
// config.
func ClassifyInvocationAgainst(command string, args []string, expected string) WrapperState {
	if command == "" || expected == "" || len(args) < 2 || args[0] != subcmdMCP || args[1] != subcmdProxy {
		return WrapperNone
	}
	return classifyExecutable(command, expected, nil)
}

func classifyExecutable(command, self string, executableErr error) WrapperState {
	if executableErr != nil {
		return WrapperForeign
	}
	selfInfo, err := os.Stat(self)
	if err != nil {
		return WrapperForeign
	}
	commandInfo, err := os.Stat(command)
	if err != nil || !os.SameFile(selfInfo, commandInfo) {
		return WrapperForeign
	}
	return WrapperSelf
}

// ClassifyServer applies ClassifyInvocation to either the conventional
// command-plus-args shape or OpenCode's single command-array shape.
func ClassifyServer(server map[string]interface{}) WrapperState {
	if command, ok := server[FieldCommand].(string); ok {
		args, err := stringArgs(server[FieldArgs])
		if err != nil {
			return WrapperNone
		}
		return ClassifyInvocation(command, args)
	}
	command, err := stringArgs(server[FieldCommand])
	if err != nil || len(command) == 0 {
		return WrapperNone
	}
	return ClassifyInvocation(command[0], command[1:])
}

// IsWrappedBySelf reports whether the current executable mediates this entry.
func IsWrappedBySelf(server map[string]interface{}) bool {
	return ClassifyServer(server) == WrapperSelf
}

// MCP server entry field keys, shared across wrap/unwrap operations.
const (
	FieldCommand  = "command"
	FieldArgs     = "args"
	FieldURL      = "url"
	FieldHeaders  = "headers"
	FieldType     = "type"
	FieldEnv      = "env"
	FieldEnvFile  = "envFile"
	FieldPipelock = "_pipelock"
)

// TypeStdio is the MCP server type for subprocess-based (stdio) servers. The
// wrapped form is always stdio (pipelock spawns the proxy as a subprocess),
// regardless of the original transport.
const TypeStdio = "stdio"

const (
	flagHeaderFile     = "--header-file"
	flagUpstream       = "--upstream"
	flagConfig         = "--config"
	flagEnvCarrier     = "--env-carrier"
	flagEnvUnset       = "--env-unset"
	flagEnvFileCarrier = "--env-file-carrier"
	flagHeaderCarrier  = "--header-carrier"
)

// typeHTTPInferred is the transport label WrapServer assigns internally when a
// type-less config (Hermes, Cline) declares a url. It is never written to the
// output entry; it only routes the wrap and is recorded in Meta.OriginalType
// (with TypeOmitted=true) so unwrap restores a url-shaped, type-less entry.
const typeHTTPInferred = "http"

// Meta stores the original server config so UnwrapServer can restore it on
// remove.
//
// ArgsPresent distinguishes "source had an args field" from "source omitted
// args entirely" so unwrap can restore `"args": []` byte-exact for sources
// that declared it. Without it, unwrapping a server seeded with empty args
// would drop the field.
//
// HeaderSidecarPath, when set, points at the operator-private 0o600 file the
// install wrote with the server's headers. The wrapped argv references it via
// --header-file so credential values never appear in process argv (visible via
// /proc/<pid>/cmdline). Remove deletes the sidecar.
//
// omitempty preserves backward compatibility with rosters wrapped before these
// fields existed.
type Meta struct {
	SchemaVersion     int                    `json:"schema_version,omitempty"`
	OriginalType      string                 `json:"original_type"`
	TypeOmitted       bool                   `json:"type_omitted,omitempty"`
	OriginalCommand   string                 `json:"original_command,omitempty"`
	OriginalArgs      []string               `json:"original_args,omitempty"`
	ArgsPresent       bool                   `json:"args_present,omitempty"`
	OriginalURL       string                 `json:"original_url,omitempty"`
	OriginalHeaders   map[string]string      `json:"original_headers,omitempty"`
	HeaderSidecarPath string                 `json:"header_sidecar_path,omitempty"`
	OriginalEnv       map[string]interface{} `json:"original_env,omitempty"`
	EnvPresent        bool                   `json:"env_present,omitempty"`
	OriginalEnvFile   string                 `json:"original_env_file,omitempty"`
	EnvFilePresent    bool                   `json:"env_file_present,omitempty"`
}

// IsWrapped reports whether a server entry already carries pipelock metadata.
// Used to make install/remove idempotent.
func IsWrapped(server map[string]interface{}) bool {
	_, ok := server[FieldPipelock]
	return ok
}

// IsHTTPType reports whether a server type uses URL-based upstream transport
// (anything that is not stdio and not empty).
func IsHTTPType(t string) bool { return t != TypeStdio && t != "" }

// WrapServer wraps a single MCP server entry through `pipelock mcp proxy`.
//
// exe is the absolute pipelock binary path; configFile (optional) becomes
// `--config`; targetConfigPath + serverName derive the per-server 0o600 header
// sidecar file when the entry carries an HTTP `headers` block.
//
// The returned map is the rewritten server entry (the caller attaches the Meta
// under FieldPipelock). The returned *SidecarOp is nil unless a header sidecar
// must be written; the caller applies it via ApplySidecarOps at commit time.
//
// Transport handling:
//   - Explicit `type` (e.g. VS Code): honored. An HTTP type is converted to a
//     stdio subprocess and the wrapped entry is marked `type: stdio` so the
//     host launches it correctly; unwrap restores the original type.
//   - Omitted `type` (e.g. Hermes, Cline): the transport is inferred from the
//     presence of `url` (HTTP) vs `command` (stdio). The wrapped entry omits
//     `type` entirely - the wrapped form is always a stdio subprocess, which
//     these hosts infer from the `command` key - so no field foreign to the
//     host's schema is introduced.
func WrapServer(server map[string]interface{}, exe, configFile, targetConfigPath, serverName string) (map[string]interface{}, *Meta, *SidecarOp, error) {
	return wrapServer(server, exe, configFile, targetConfigPath, serverName, false)
}

// WrapServerForVSCode preserves VS Code's launch-time substitutions without
// exposing child environment values to the Pipelock process itself. The host
// resolves values into neutral carrier variables; the runtime maps them to the
// child or upstream only after its own startup checks have completed.
func WrapServerForVSCode(server map[string]interface{}, exe, configFile, targetConfigPath, serverName string) (map[string]interface{}, *Meta, *SidecarOp, error) {
	return wrapServer(server, exe, configFile, targetConfigPath, serverName, true)
}

func wrapServer(server map[string]interface{}, exe, configFile, targetConfigPath, serverName string, runtimeResolve bool) (map[string]interface{}, *Meta, *SidecarOp, error) {
	server, err := recoverForeignServer(server)
	if err != nil {
		return nil, nil, nil, err
	}
	serverType, _ := server[FieldType].(string)
	typeOmitted := serverType == ""
	if typeOmitted {
		// Type-less configs infer the transport from which key is present.
		_, hasCommand := server[FieldCommand]
		_, hasURL := server[FieldURL]
		if hasCommand && hasURL {
			return nil, nil, nil, fmt.Errorf("type-less server has both command and url")
		}
		if hasURL {
			serverType = typeHTTPInferred
		} else {
			serverType = TypeStdio
		}
	}

	// Copy every field except the ones we replace (command/args/url/headers/type).
	result := make(map[string]interface{})
	for k, v := range server {
		switch k {
		case FieldCommand, FieldArgs, FieldURL, FieldHeaders, FieldType:
			// Replaced below.
		case FieldEnv, FieldEnvFile:
			if !runtimeResolve {
				result[k] = v
			}
		default:
			result[k] = v
		}
	}

	meta := &Meta{OriginalType: serverType, TypeOmitted: typeOmitted}

	// --env flags pass environment variable names through to the child. The
	// proxy strips the parent env and forwards only its safe set plus these
	// explicit additions, so without them the child server loses the env vars
	// the host (IDE/agent) set for it.
	envFlags := BuildEnvFlags(server)
	if runtimeResolve {
		if rawEnv, present := server[FieldEnv]; present {
			env, ok := rawEnv.(map[string]interface{})
			if !ok {
				return nil, nil, nil, fmt.Errorf("env has non-object value of type %T", rawEnv)
			}
			meta.EnvPresent = true
			for key := range env {
				if key == "" || strings.ContainsAny(key, "=\x00") {
					return nil, nil, nil, fmt.Errorf("env key %q is not a valid child environment variable name", key)
				}
				switch env[key].(type) {
				case nil, string, float64:
				default:
					return nil, nil, nil, fmt.Errorf("env value for %q has unsupported type %T", key, env[key])
				}
			}
		}
		if raw, present := server[FieldEnvFile]; present {
			if _, ok := raw.(string); !ok {
				return nil, nil, nil, fmt.Errorf("envFile has non-string value of type %T", raw)
			}
		}
		meta.SchemaVersion = 2
		var carrierEnv map[string]interface{}
		envFlags, carrierEnv = buildVSCodeEnvCarriers(server, serverName, meta)
		if len(carrierEnv) > 0 {
			result[FieldEnv] = carrierEnv
		}
		if serverType != TypeStdio {
			// HTTP transports have no child environment. Keep only carriers
			// introduced below for dynamic headers; resolving env/envFile here
			// would make an irrelevant missing file block the upstream.
			envFlags = nil
			delete(result, FieldEnv)
		}
	}

	switch serverType {
	case TypeStdio:
		originalCmd, _ := server[FieldCommand].(string)
		if originalCmd == "" {
			return nil, nil, nil, fmt.Errorf("stdio server missing command")
		}
		_, meta.ArgsPresent = server[FieldArgs]
		// Reject (rather than silently drop) non-string args: dropping one would
		// change the command the wrapped child actually runs.
		originalArgs, err := stringArgs(server[FieldArgs])
		if err != nil {
			return nil, nil, nil, fmt.Errorf("stdio server %w", err)
		}
		meta.OriginalCommand = originalCmd
		meta.OriginalArgs = originalArgs

		args := []string{"mcp", "proxy"}
		if configFile != "" {
			args = append(args, flagConfig, configFile)
		}
		args = append(args, envFlags...)
		args = append(args, "--")
		args = append(args, originalCmd)
		args = append(args, originalArgs...)

		if !typeOmitted {
			result[FieldType] = TypeStdio
		}
		result[FieldCommand] = exe
		result[FieldArgs] = args
		return result, meta, nil, nil

	default:
		// HTTP-like: an explicit http/sse type, or a type inferred from a url
		// on a type-less config. serverType is guaranteed non-empty after the
		// type resolution above, so there is no separate unsupported-type case.
		originalURL, _ := server[FieldURL].(string)
		if originalURL == "" {
			return nil, nil, nil, fmt.Errorf("%s server missing url", serverType)
		}
		meta.OriginalURL = originalURL

		headerLines, err := extractHeaderLines(server)
		if err != nil {
			return nil, nil, nil, err
		}
		// OriginalHeaders is retained in metadata so unwrap restores the source
		// headers block faithfully and self-containedly (no dependency on the
		// sidecar still existing). This is the SAME file-level exposure as the
		// operator's original `headers:` block - the sidecar's purpose is to
		// prevent the NEW exposure that wrapping would otherwise add: credential
		// values on the child argv, visible to all local users via
		// /proc/<pid>/cmdline. Scrubbing the token from the config entirely
		// (reconstruct-from-sidecar on unwrap) is a further hardening tracked
		// for a cross-installer follow-up, not done here, to stay behaviorally
		// aligned with the existing setup installers.
		if headers, ok := server[FieldHeaders].(map[string]interface{}); ok {
			meta.OriginalHeaders = make(map[string]string, len(headers))
			for k, v := range headers {
				value, ok := v.(string)
				if !ok {
					return nil, nil, nil, fmt.Errorf("header %q has non-string value of type %T; only string header values are supported", k, v)
				}
				meta.OriginalHeaders[k] = value
			}
		}

		var (
			sidecarFlags []string
			plan         *SidecarOp
		)
		var headerCarrierFlags []string
		if runtimeResolve {
			headerLines, headerCarrierFlags = splitVSCodeHeaders(headerLines, serverName, result)
		}
		if len(headerLines) > 0 {
			path, err := headerSidecarPath(targetConfigPath, serverName)
			if err != nil {
				return nil, nil, nil, err
			}
			body := []byte(strings.Join(headerLines, "\n") + "\n")
			op := SidecarWrite(path, body)
			plan = &op
			meta.HeaderSidecarPath = path
			sidecarFlags = []string{flagHeaderFile, path}
		}

		args := []string{"mcp", "proxy"}
		if configFile != "" {
			args = append(args, flagConfig, configFile)
		}
		args = append(args, envFlags...)
		args = append(args, sidecarFlags...)
		args = append(args, headerCarrierFlags...)
		args = append(args, flagUpstream, originalURL)

		if !typeOmitted {
			result[FieldType] = TypeStdio
		}
		result[FieldCommand] = exe
		result[FieldArgs] = args
		return result, meta, plan, nil
	}
}

func carrierName(serverName, kind, target string) string {
	sum := sha256.Sum256([]byte(serverName + "\x00" + kind + "\x00" + target))
	return fmt.Sprintf("PIPELOCK_VSCODE_%s_%X", strings.ToUpper(kind), sum[:10])
}

func buildVSCodeEnvCarriers(server map[string]interface{}, serverName string, meta *Meta) ([]string, map[string]interface{}) {
	var flags []string
	carriers := make(map[string]interface{})
	if env, ok := server[FieldEnv].(map[string]interface{}); ok {
		meta.OriginalEnv = env
		keys := make([]string, 0, len(env))
		for key := range env {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			if env[key] == nil {
				flags = append(flags, flagEnvUnset, key)
				continue
			}
			carrier := carrierName(serverName, "env", key)
			carriers[carrier] = env[key]
			flags = append(flags, flagEnvCarrier, key+"="+carrier)
		}
	}
	if raw, present := server[FieldEnvFile]; present {
		meta.EnvFilePresent = true
		path := raw.(string)
		meta.OriginalEnvFile = path
		carrier := carrierName(serverName, "envfile", "path")
		carriers[carrier] = path
		flags = append(flags, flagEnvFileCarrier, carrier)
	}
	if len(carriers) == 0 {
		return flags, nil
	}
	return flags, carriers
}

func splitVSCodeHeaders(lines []string, serverName string, result map[string]interface{}) ([]string, []string) {
	literal := make([]string, 0, len(lines))
	carrierEnv, _ := result[FieldEnv].(map[string]interface{})
	if carrierEnv == nil {
		carrierEnv = make(map[string]interface{})
	}
	var flags []string
	for _, line := range lines {
		key, value, _ := strings.Cut(line, ":")
		value = strings.TrimLeft(value, " \t")
		if !strings.Contains(value, "${") {
			literal = append(literal, line)
			continue
		}
		carrier := carrierName(serverName, "header", key)
		carrierEnv[carrier] = value
		flags = append(flags, flagHeaderCarrier, key+"="+carrier)
	}
	if len(carrierEnv) > 0 {
		result[FieldEnv] = carrierEnv
	}
	return literal, flags
}

// UnwrapServer restores a server from its pipelock metadata. The returned
// *SidecarOp (when non-nil) describes a sidecar delete the caller MUST execute
// only after successfully writing the restored config to disk; otherwise a
// marshal / write failure later in the remove path would leave the still-
// wrapped config on disk while the credential carrier it references is gone.
//
// A server with no pipelock metadata is returned unchanged with a nil op.
//
// The delete target is DERIVED from targetConfigPath and serverName, matching
// what WrapServer would have written, and is never taken from the metadata.
// The marker lives in an operator-editable config and every server's sidecar
// shares one directory, so honouring a metadata-supplied path would let one
// server's entry nominate another server's credential file for deletion. The
// metadata path is still shape-checked so a tampered marker fails closed.
func UnwrapServer(server map[string]interface{}, targetConfigPath, serverName string) (map[string]interface{}, *SidecarOp, error) {
	meta, ok, err := ParseMeta(server)
	if err != nil {
		return nil, nil, err
	}
	if !ok {
		return server, nil, nil
	}

	var plan *SidecarOp
	if meta.HeaderSidecarPath != "" {
		if _, err := validatedHeaderSidecarDeletePath(meta.HeaderSidecarPath); err != nil {
			return nil, nil, err
		}
		path, err := headerSidecarPath(targetConfigPath, serverName)
		if err != nil {
			return nil, nil, err
		}
		op := SidecarDelete(path)
		plan = &op
	}

	result := make(map[string]interface{})
	for k, v := range server {
		switch k {
		case FieldCommand, FieldArgs, FieldURL, FieldHeaders, FieldType, FieldPipelock:
			// Replaced/removed below.
		case FieldEnv, FieldEnvFile:
			if meta.SchemaVersion < 2 {
				result[k] = v
			}
		default:
			result[k] = v
		}
	}

	// Validate required metadata before restoring.
	switch meta.OriginalType {
	case TypeStdio:
		if meta.OriginalCommand == "" {
			return nil, nil, fmt.Errorf("invalid _pipelock metadata: missing original_command")
		}
	case "":
		return nil, nil, fmt.Errorf("invalid _pipelock metadata: missing original_type")
	default:
		if meta.OriginalURL == "" {
			return nil, nil, fmt.Errorf("invalid _pipelock metadata: missing original_url for %s server", meta.OriginalType)
		}
	}

	// Only set type if the original config declared it explicitly.
	if !meta.TypeOmitted {
		result[FieldType] = meta.OriginalType
	}

	switch meta.OriginalType {
	case TypeStdio:
		result[FieldCommand] = meta.OriginalCommand
		// Restore args if the source had the field (new metadata) or if the
		// stored args are non-empty (legacy metadata that lacked ArgsPresent).
		// A source that had `"args": []` round-trips byte-exact via ArgsPresent.
		switch {
		case meta.ArgsPresent:
			if meta.OriginalArgs != nil {
				result[FieldArgs] = meta.OriginalArgs
			} else {
				result[FieldArgs] = []string{}
			}
		case len(meta.OriginalArgs) > 0:
			result[FieldArgs] = meta.OriginalArgs
		}
	default:
		result[FieldURL] = meta.OriginalURL
		if len(meta.OriginalHeaders) > 0 {
			headers := make(map[string]interface{}, len(meta.OriginalHeaders))
			for k, v := range meta.OriginalHeaders {
				headers[k] = v
			}
			result[FieldHeaders] = headers
		}
	}
	if meta.EnvPresent || meta.OriginalEnv != nil {
		if meta.OriginalEnv == nil {
			result[FieldEnv] = map[string]interface{}{}
		} else {
			result[FieldEnv] = meta.OriginalEnv
		}
	}
	if meta.EnvFilePresent {
		result[FieldEnvFile] = meta.OriginalEnvFile
	}

	return result, plan, nil
}

// ParseMeta extracts the pipelock metadata from a server entry. The second
// return is false (with a nil Meta and nil error) when the entry is not
// wrapped. The metadata is round-tripped through JSON so it works whether the
// source config was decoded from JSON (IDE configs) or YAML (Hermes).
func ParseMeta(server map[string]interface{}) (*Meta, bool, error) {
	raw, ok := server[FieldPipelock]
	if !ok {
		return nil, false, nil
	}
	metaJSON, err := json.Marshal(raw)
	if err != nil {
		return nil, false, fmt.Errorf("reading _pipelock metadata: %w", err)
	}
	var meta Meta
	if err := json.Unmarshal(metaJSON, &meta); err != nil {
		return nil, false, fmt.Errorf("parsing _pipelock metadata: %w", err)
	}
	return &meta, true, nil
}

// BuildEnvFlags extracts env var keys from a server's "env" block and returns
// `--env KEY` flags for each. Hosts resolve env values before spawning the
// child, so only the key names are needed; the proxy reads the values from its
// own (host-set) environment.
func BuildEnvFlags(server map[string]interface{}) []string {
	envMap, ok := server["env"].(map[string]interface{})
	if !ok || len(envMap) == 0 {
		return nil
	}
	keys := make([]string, 0, len(envMap))
	for key := range envMap {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	// Cap hint is len(keys) (not len*2) to avoid a multiplication CodeQL flags
	// as a potential allocation-size overflow; append grows it as needed.
	flags := make([]string, 0, len(keys))
	for _, key := range keys {
		flags = append(flags, "--env", key)
	}
	return flags
}

// stringArgs converts a decoded args value to []string, returning an error on
// any non-string element instead of dropping it. Used on the wrap path, where
// silently dropping a numeric or boolean arg would change the command the
// wrapped child runs. A nil/absent value yields nil with no error.
func stringArgs(v interface{}) ([]string, error) {
	switch slice := v.(type) {
	case nil:
		return nil, nil
	case []string:
		return append([]string(nil), slice...), nil
	case []interface{}:
		out := make([]string, 0, len(slice))
		for i, item := range slice {
			s, ok := item.(string)
			if !ok {
				return nil, fmt.Errorf("args[%d] is %T, want string (quote it in the config)", i, item)
			}
			out = append(out, s)
		}
		return out, nil
	default:
		return nil, fmt.Errorf("args must be a list, got %T", v)
	}
}

// InterfaceSliceToStrings converts a []interface{} (from JSON/YAML unmarshal)
// to []string, dropping non-string elements. Used on read paths where lenient
// coercion is acceptable; the wrap path uses stringArgs, which rejects
// non-string elements.
func InterfaceSliceToStrings(v interface{}) []string {
	switch slice := v.(type) {
	case []interface{}:
		result := make([]string, 0, len(slice))
		for _, item := range slice {
			if s, ok := item.(string); ok {
				result = append(result, s)
			}
		}
		return result
	case []string:
		return append([]string(nil), slice...)
	default:
		return nil
	}
}
