# Using Pipelock with Grok Build

[Grok Build](https://docs.x.ai/build/overview) (the `grok` CLI from xAI) is a coding agent with an interactive TUI, headless scripting mode, Agent Client Protocol (ACP) support, and MCP servers configured via `grok mcp` / `~/.grok/config.toml`. Its model API egress is ordinary HTTPS. Pipelock covers that path as a **forward proxy** (standard proxy environment variables) and covers MCP tool traffic when you **manually wrap** stdio servers with `pipelock mcp proxy` — the same class as Codex manual wrapping.

This guide does **not** add a `pipelock grok install` command. There is no automatic config rewriter for Grok. Forward-proxy env vars and manual MCP wrapping are both in scope; do not treat this page as env-only or as “MCP unsupported.”

## Why Grok Needs an Agent Firewall

| Workflow | What Grok accesses | What could go wrong |
|---|---|---|
| Interactive / headless prompts | Repo files, diffs, tool results sent to the model | Secrets or private paths leaving in prompt context |
| Model inference / auth (OAuth or API key) | `cli-chat-proxy.grok.com`, `auth.x.ai`, and (API-key path) `api.x.ai` over HTTPS | Uninspected hostname egress; opaque CONNECT bodies without interception |
| MCP tool use (`grok mcp`) | Local stdio servers and remote HTTP MCP endpoints | Tool poisoning, rug-pull, secrets in tool arguments / results |
| Shell / local tools | Commands and network from the agent session | Exfiltration that never hits the model API or wrapped MCP path |

## What Is Covered

Coverage depends on which surface you wire and whether TLS interception is enabled. Ordinary CONNECT without interception is hostname-visible only — bodies, headers, and prompts stay encrypted end-to-end. That is the same [CONNECT tunnel body blindness](../bypass-resistance.md#known-limitations) honesty as other forward-proxy guides.

| Surface | Covered? | How / condition |
|---|---|---|
| Hostname / destination policy, SSRF-class host checks on CONNECT | Yes (without interception) | Forward proxy (`pipelock run`); proxy sees CONNECT target host, not tunnel plaintext |
| Full outbound DLP + response injection on model HTTPS | Yes **only with** TLS interception + trusted OS CA | Same listener; see [TLS interception](tls-interception.md) |
| Streaming inference responses (bodies) | Yes **only when** TLS interception makes HTTPS bodies visible | Same as above |
| MCP stdio servers wrapped with `pipelock mcp proxy` | Yes (manual wrap) | `grok mcp add … -- pipelock mcp proxy --config … -- <upstream>` |
| Remote HTTP MCP with static auth headers | Manual only | Prefer `--header-file` + `--upstream` (Continue/Codex honesty); do not put secrets on argv |
| Automatic `pipelock grok install`, Pro-only named listeners, unpublished controls | No | Not claimed here |

Grok's enterprise docs load root certificates from the **OS trust store** (rustls). Install Pipelock's CA there when intercepting. Do not invent Node-only `NODE_EXTRA_CA_CERTS` wiring for the Rust CLI.

## Quick Start (forward proxy)

Install Grok **before** exporting proxy env vars. With `pipelock run` already up, `curl`/`npm` install traffic would otherwise be forced through the proxy and can fail (or add install hosts to `NO_PROXY` / allow them in policy).

```bash
# 1. Install pipelock (requires Go 1.25+)
git clone --branch v3.5.0 --depth 1 https://github.com/luckyPipewrench/pipelock.git
make -C pipelock install
# or (macOS): brew install luckyPipewrench/tap/pipelock

# 2. Install Grok (public install paths — do this before exporting proxy)
curl -fsSL https://x.ai/cli/install.sh | bash
# or: npm install -g @xai-official/grok

# 3. Generate a config and start the forward proxy
pipelock generate config --preset balanced -o pipelock.yaml
pipelock run --config pipelock.yaml &

# 4. Point Grok Build at Pipelock (CLI honors these env vars)
export HTTPS_PROXY=http://127.0.0.1:8888
export HTTP_PROXY=http://127.0.0.1:8888
export NO_PROXY=127.0.0.1,localhost

# 5. Run Grok
grok
# headless: grok -p "Explain this repo"
# controlled headless / CI: grok --no-auto-update -p "Explain this repo"
```

The CLI honors standard proxy environment variables (`HTTPS_PROXY`, `HTTP_PROXY`, `NO_PROXY`). Set proxy idle timeouts to **at least 10 minutes** so long SSE model streams are not cut off mid-response (see [xAI enterprise network docs](https://docs.x.ai/build/enterprise)).

Authenticate with the usual Grok paths (`grok login`, device auth, or `XAI_API_KEY`). Pipelock does not replace Grok authentication.

For scripts, CI, or ACP (`grok agent stdio`), pass `--no-auto-update` so background update checks do not hit install/CDN hosts unexpectedly. Persistently disable updates with `auto_update = false` under `[cli]` in `~/.grok/config.toml` (see [Headless & Scripting](https://docs.x.ai/build/cli/headless-scripting)).

## MCP Proxy Mode (manual wrap)

Grok supports MCP servers via [`grok mcp`](https://docs.x.ai/build/features/mcp-servers). There is **no** `pipelock grok install`. Join the Codex manual class: wrap each stdio server so tool calls and results pass through `pipelock mcp proxy`.

```text
Grok  <-->  pipelock mcp proxy  <-->  MCP Server
(agent)     (scan both ways)         (subprocess)
```

### Adding a wrapped stdio server

Everything after `--` is the upstream MCP command (same shape as Codex):

```bash
# Wrap a filesystem server
grok mcp add filesystem \
  -- pipelock mcp proxy --config pipelock.yaml \
  -- npx -y @modelcontextprotocol/server-filesystem ~/projects

# Wrap a database server
grok mcp add postgres \
  -- pipelock mcp proxy --config pipelock.yaml \
  -- npx -y @modelcontextprotocol/server-postgres postgresql://localhost/mydb
```

Prefer an **absolute** path to both `pipelock` and `--config` so the wrap does not depend on Grok's later working directory.

### Or edit `~/.grok/config.toml` directly

```toml
[mcp_servers.filesystem]
command = "pipelock"
args = [
  "mcp", "proxy",
  "--config", "/home/you/pipelock.yaml",
  "--",
  "npx", "-y", "@modelcontextprotocol/server-filesystem", "/home/you/projects"
]
```

Grok also accepts project-scoped servers (`grok mcp add --scope project` → `.grok/config.toml`) and merges compat configs from Claude/Cursor MCP files; wrap those entries the same way if you rely on them.

### Verification

```bash
grok mcp list
grok mcp doctor
# machine-readable:
grok mcp list --json
grok mcp doctor --json
```

A listed server is not proof the client connected successfully. After wrapping, run a harmless tool action and use `grok mcp doctor` (and stderr under `~/.grok/logs/mcp/` if a stdio server fails to start).

### Remote HTTP MCP and auth headers

Grok can register remotes with HTTP transport:

```bash
# Native Grok remote (OAuth handled by Grok — not auto-wrapped by Pipelock)
grok mcp add --transport http linear https://mcp.linear.app/mcp

# Native Grok remote with static headers (header values land in config / argv surface)
grok mcp add --transport http api https://mcp.example.com/mcp \
  --header "Authorization: Bearer ${API_TOKEN}"
```

**What is and is not auto-wrapped:** Pipelock does not rewrite Grok's `[mcp_servers.*]` `url` / `headers` entries. A native `url=` remote stays a direct Grok→server HTTP path unless you replace it with a stdio wrap.

For remotes that need static auth headers, follow Continue/Codex honesty: do **not** put secrets on the process command line (`/proc/<pid>/cmdline` is world-readable). Store one `Header-Name: value` per line in a private `0600` file and wrap via `--header-file` + `--upstream`:

```bash
# Private header file (0600); one Header-Name: value per line
umask 077
printf 'Authorization: Bearer %s\n' "$API_TOKEN" > ~/.config/pipelock/wrap-headers/grok-api.headers
chmod 600 ~/.config/pipelock/wrap-headers/grok-api.headers

grok mcp add api-wrapped \
  -- pipelock mcp proxy --config pipelock.yaml \
  --header-file "$HOME/.config/pipelock/wrap-headers/grok-api.headers" \
  --upstream https://mcp.example.com/mcp
```

Equivalent TOML:

```toml
[mcp_servers.api-wrapped]
command = "pipelock"
args = [
  "mcp", "proxy",
  "--config", "/home/you/pipelock.yaml",
  "--header-file", "/home/you/.config/pipelock/wrap-headers/grok-api.headers",
  "--upstream", "https://mcp.example.com/mcp"
]
```

OAuth-only remotes that Grok authenticates itself (browser flow, tokens under `~/.grok/mcp_credentials.json`) are outside automatic Pipelock wrapping. Route tool traffic through a stdio/`--upstream` wrap when you need MCP JSON-RPC scanning on that path.

### What gets scanned (MCP wrap)

| Direction | What | Scanning |
|---|---|---|
| Grok → MCP server | Tool call arguments | DLP, injection patterns, tool-policy rules |
| MCP server → Grok | Tool results, descriptions | Prompt injection (response pipeline) |
| Tool definitions | `tools/list` responses | Poisoned descriptions, schema injection, rug-pull detection |
| Tool sequences | Multi-call patterns | Chain detection |

MCP stdio wrapping scans JSON-RPC directly and does **not** require TLS interception. Forward-proxy model HTTPS still needs interception for body DLP (next section).

## Optional: TLS interception CA

When Pipelock terminates TLS so it can scan HTTPS bodies on the forward-proxy path:

1. Enable interception and distribute the CA per [TLS interception](tls-interception.md).
2. Trust `~/.pipelock/ca.pem` in the **OS trust store** (Grok loads system roots). On Linux that is typically `update-ca-certificates` / `update-ca-trust`; on macOS, the system keychain — same instructions as the TLS guide.

Without a trusted CA, intercepted HTTPS handshakes fail. Without interception, CONNECT tunnels stay body-opaque (hostname-level controls only) — join [bypass-resistance CONNECT tunnel body blindness](../bypass-resistance.md#known-limitations).

## Destination matrix (enterprise hosts)

Authoritative public tables: [xAI enterprise network requirements](https://docs.x.ai/build/enterprise). All connections use HTTPS (port 443). Allow destinations in Pipelock policy the same way you allow other model endpoints.

### Required (core auth + inference)

| Host | Purpose |
|---|---|
| `cli-chat-proxy.grok.com` | Inference proxy, settings |
| `auth.x.ai` | OAuth2/OIDC authentication |

If using enterprise OIDC, also allow your IdP domain (for example `login.microsoftonline.com`).

### Additional (API-key path)

| Host | Purpose | Impact if blocked |
|---|---|---|
| `api.x.ai` | xAI API (direct API-key path) | Needed only when using `api_key` / `XAI_API_KEY` instead of the inference proxy |

### Optional features

| Host | Purpose | Impact if blocked |
|---|---|---|
| `code.grok.com` | Remote session sync, sharing, WebSocket relay | Sessions stay local-only; share links unavailable |
| `assets.grok.com` | Profile images, UI assets | Avatars won't load; no functional impact on inference |

### Install / update (shell installer and `grok update`)

| Host | Purpose | Impact if blocked |
|---|---|---|
| `x.ai` | CLI binary downloads via `curl \| bash` install script | Use `npm install -g @xai-official/grok` as an alternative that does not require this host |
| `storage.googleapis.com` | Fallback CDN for CLI binaries | Only needed if `x.ai` is unreachable during `curl \| bash` install / in-app update |

`x.ai` and `storage.googleapis.com` are only required for the shell-script installer and in-app `grok update`. npm distribution does not need them. For controlled headless runs, prefer `--no-auto-update` or `auto_update = false` under `[cli]` so CI does not depend on those hosts.

### Config file note

`~/.grok/config.toml` can bind an `api_key` (or custom `base_url`) per model and declare `[mcp_servers.*]`. Model `api_key` / `base_url` entries are **not** a Pipelock proxy rewrite surface: they do not replace `HTTPS_PROXY` / `HTTP_PROXY`. Prefer env vars for forward-proxy wiring. MCP entries **are** the manual wrap surface described above.

## What Gets Scanned (forward proxy)

Join [bypass-resistance](../bypass-resistance.md): unintercepted CONNECT carries TLS-encrypted traffic where bodies and headers are not visible. Do not claim unqualified outbound DLP on Grok→model plaintext.

| Direction / control | Without TLS interception | With TLS interception + trusted OS CA |
|---|---|---|
| CONNECT target hostname / destination policy / SSRF-class host checks | Visible and enforceable | Same, plus decrypted path |
| Grok → model API request bodies, headers, prompts (DLP) | **Not visible** (opaque tunnel) | Scanned (DLP, URL/policy on decrypted traffic) |
| Model API → Grok response bodies (injection checks) | **Not visible** | Scanned when bodies are visible |
| MCP JSON-RPC via `pipelock mcp proxy` | N/A on this table — scanned on the wrap path (no CONNECT MITM required) | Same |

Tools and subprocesses that ignore proxy environment variables need `pipelock contain`, a sandbox, or another network boundary — cooperative proxying is not binary-enforced isolation.

## Choosing a Config

| Preset | Action | Best for |
|---|---|---|
| `balanced` | warn | Getting started, tuning phase |
| `strict` | block | High-security workflows |
| `hostile-model` | block | Uncensored or jailbroken models |

Start with `balanced` to see what gets flagged, then move to a blocking preset once you have verified no false positives. A preset is selected at generate time (`pipelock generate config --preset <name> -o pipelock.yaml`); that file is what `run` and `mcp proxy` take through `--config`.

## Troubleshooting

### MCP server listed but not connecting

```bash
# Upstream alone
npx -y @modelcontextprotocol/server-filesystem /tmp

# Then wrap
pipelock mcp proxy --config pipelock.yaml -- npx -y @modelcontextprotocol/server-filesystem /tmp

grok mcp doctor filesystem
```

Cold-start `npx` downloads may need a higher `startup_timeout_sec` on the `[mcp_servers.*]` entry. Stdio stderr is under `~/.grok/logs/mcp/<name>.stderr.log`.

### Install or update fails with proxy already set

Install Grok before exporting `HTTPS_PROXY` / `HTTP_PROXY`, or allow `x.ai` / `storage.googleapis.com` (or use npm) and/or add them to policy. Prefer `--no-auto-update` in headless environments.

### TLS handshake failures after enabling interception

Trust the Pipelock CA in the **OS** trust store. Grok uses rustls with system roots — `NODE_EXTRA_CA_CERTS` alone does not fix the Rust CLI.

## See also

- [TLS interception](tls-interception.md) — CA trust and HTTPS body visibility
- [Bypass resistance](../bypass-resistance.md) — CONNECT tunnel body blindness and scanning scope
- [OpenAI Codex guide](codex.md) — MCP wrap + forward-proxy pattern (Codex has an installer; Grok does not)
- [Continue.dev guide](continue.md) — remote MCP header-file honesty
- [Receipt verification](receipt-verification.md) — independent audit of proxy decisions
- [xAI MCP servers](https://docs.x.ai/build/features/mcp-servers) — `grok mcp add/list/remove/doctor`
- [xAI enterprise network](https://docs.x.ai/build/enterprise) — destination hosts and proxy idle timeouts
- [xAI headless scripting](https://docs.x.ai/build/cli/headless-scripting) — `--no-auto-update`, `auto_update`
