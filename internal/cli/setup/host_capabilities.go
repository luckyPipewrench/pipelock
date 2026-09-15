// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package setup

// headerCapability names how a host's installer treats an HTTP `headers`
// block on a remote MCP server entry.
type headerCapability string

const (
	// headerCapabilitySidecar means header values are moved into a 0o600
	// sidecar file and the wrapped command references it with
	// --header-file; the literal values never appear in argv or in the
	// rewritten config's headers field.
	headerCapabilitySidecar headerCapability = "sidecar"
	// headerCapabilityRejected means the installer refuses to wrap the
	// server at all when it carries headers (the operator sees a warning
	// or error and the server is left unwrapped).
	headerCapabilityRejected headerCapability = "rejected"
	// headerCapabilityUnconsumedPassthrough means the installer copies the
	// headers field verbatim into the rewritten config (so it looks
	// preserved) but the generated wrapped command never reads it, so the
	// header is silently inert once pipelock's proxy is in the loop.
	headerCapabilityUnconsumedPassthrough headerCapability = "unconsumed-passthrough"
)

// envCapability names how a host's installer carries a child MCP server's
// declared environment variables through to `pipelock mcp proxy`.
type envCapability string

const (
	// envCapabilityKeyOnly means only the variable NAME crosses into the
	// wrapped command (`--env KEY`); pipelock's mcp proxy inherits the
	// value from its own process environment, which the host is relied on
	// to have already set before starting the wrapped command.
	envCapabilityKeyOnly envCapability = "key-only"
	// envCapabilityKeyValue means the literal value is written into the
	// wrapped command/config (`--env KEY=VALUE`), because the host's own
	// install mechanism (codex mcp add) does not run as a child of a
	// process that already has the value set.
	envCapabilityKeyValue envCapability = "key-value"
)

// hostCapability is the per-host declaration of what an MCP installer under
// internal/cli/setup actually honors. It exists so a future migration (for
// example, moving another host onto internal/mcpwrap the way vscode.go and
// codex.go were) has an executable record of current behavior to preserve or
// deliberately change, instead of inferring one host's semantics from
// another's. See host_capabilities_test.go for the derivation that keeps
// this table honest: it runs each host's real wrap function against a
// synthetic server carrying headers and env vars, and fails if what comes
// out disagrees with what is declared here.
type hostCapability struct {
	// Host is the command name (`pipelock <Host> install`).
	Host string
	// Engine names the wrapper implementation. "mcpwrap-runtime" hosts
	// resolve their environment carriers through internal/mcpwrap at
	// runtime; "legacy-shared" hosts use the command/args helpers in this
	// package (wrapVscodeServer, wrapMCPServer, wrapContinueServer,
	// wrapOpenCodeServer) that predate that engine.
	Engine string
	// Headers is how a remote (`url`) server's headers block is handled.
	Headers headerCapability
	// Env is how a stdio server's env block is carried to the child.
	Env envCapability
	// SelfWrapSkip is true when re-running install over a server this
	// same install already wrapped is a no-op (idempotent skip) rather
	// than nesting a second proxy invocation.
	SelfWrapSkip bool
	// ForeignRefusal is true when install refuses (rather than silently
	// re-wrapping) a server that was already wrapped by a pipelock binary
	// this installer cannot prove is itself, per normalizeForeignWrapper /
	// mcpwrap.ErrCannotNormalize.
	ForeignRefusal bool
}

const (
	engineLegacyShared = "legacy-shared"
	engineWrapRuntime  = "mcpwrap runtime"
)

// hostCapabilities is the declaration table for every MCP-wrapping
// installer in this package. Hosts that do NOT wrap an MCP server config
// (claude, cursor, pi — they patch a hook command or an HTTP proxy setting,
// not an MCP server map) are deliberately absent; see
// TestHostCapabilities_EnumeratedFromRegistry for the enumeration that
// enforces this list stays in sync with mcpWrappingHostRegistry.
var hostCapabilities = map[string]hostCapability{
	"vscode": {
		Host: "vscode", Engine: engineWrapRuntime,
		Headers: headerCapabilitySidecar, Env: envCapabilityKeyOnly,
		SelfWrapSkip: true, ForeignRefusal: true,
	},
	"cline": {
		// Shares wrapVscodeServer via wrapClineServer.
		Host: "cline", Engine: engineLegacyShared,
		Headers: headerCapabilitySidecar, Env: envCapabilityKeyOnly,
		SelfWrapSkip: true, ForeignRefusal: true,
	},
	"zed": {
		// Shares wrapVscodeServer via wrapClineServer.
		Host: "zed", Engine: engineLegacyShared,
		Headers: headerCapabilitySidecar, Env: envCapabilityKeyOnly,
		SelfWrapSkip: true, ForeignRefusal: true,
	},
	"jetbrains": {
		// Uses the generic wrapMCPServer (internal/cli/setup/mcpwrap.go),
		// which has no sidecar mechanism and rejects headers outright.
		Host: "jetbrains", Engine: engineLegacyShared,
		Headers: headerCapabilityRejected, Env: envCapabilityKeyOnly,
		SelfWrapSkip: true, ForeignRefusal: true,
	},
	"opencode": {
		Host: "opencode", Engine: engineLegacyShared,
		Headers: headerCapabilitySidecar, Env: envCapabilityKeyOnly,
		SelfWrapSkip: true, ForeignRefusal: true,
	},
	"continue": {
		// wrapContinueServer copies every field it does not itself
		// consume (command/args/url/type/_pipelock) straight into the
		// rewritten entry, including a "headers" block. Nothing in this
		// path builds a --header-file or reads headers out of the
		// server map, so the field rides through unconsumed. This is a
		// deliberately recorded contract, not a fix target here.
		Host: "continue", Engine: engineLegacyShared,
		Headers: headerCapabilityUnconsumedPassthrough, Env: envCapabilityKeyOnly,
		SelfWrapSkip: true, ForeignRefusal: true,
	},
	"codex": {
		// Codex has no config-file rewrite path; install shells out to
		// `codex mcp add/remove`, so env values must be literal
		// (--env KEY=VALUE) and any HTTP auth/header settings on the
		// upstream transport make the whole server unsupported.
		Host: "codex", Engine: engineWrapRuntime,
		Headers: headerCapabilityRejected, Env: envCapabilityKeyValue,
		SelfWrapSkip: true, ForeignRefusal: true,
	},
}
