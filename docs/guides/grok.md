# Using Pipelock with Grok Build

[Grok Build](https://docs.x.ai/build/overview) (the `grok` CLI from xAI) is a coding agent with an interactive TUI, headless scripting mode, and Agent Client Protocol (ACP) support. Its model API egress is ordinary HTTPS. Pipelock covers that path as a **forward proxy**: point the CLI at Pipelock with standard proxy environment variables so request and response traffic that honors those variables is scanned.

This guide does **not** add a `pipelock grok install` command. Coverage is env-only — the same class as Codex/OpenCode forward-proxy sections — not a config rewrite like Continue's MCP YAML or Cursor's hooks.

## Why Grok Needs an Agent Firewall

| Workflow | What Grok accesses | What could go wrong |
|---|---|---|
| Interactive / headless prompts | Repo files, diffs, tool results sent to the model | Secrets or private paths leaving in prompt context |
| Model inference / auth (OAuth or API key) | `cli-chat-proxy.grok.com`, `auth.x.ai`, or `api.x.ai` over HTTPS | Uninspected egress and inbound streaming responses |
| Shell / local tools | Commands and network from the agent session | Exfiltration that never hits the model API path |

## What Is Covered

| Surface | Covered? | How |
|---|---|---|
| Model API HTTP(S) egress that honors `HTTPS_PROXY` / `HTTP_PROXY` | Yes | Forward proxy (`pipelock run`) |
| Streaming inference responses on that path | Yes (when TLS interception is enabled for HTTPS bodies) | Same listener; see [TLS interception](tls-interception.md) |
| MCP wrapping, Pro-only named listeners, unpublished controls | No | Not claimed here |

Outbound HTTPS through CONNECT is hostname-visible by default. Full request/response body scanning on HTTPS needs TLS interception and a trusted CA — join the existing [TLS interception guide](tls-interception.md). Grok's enterprise docs load root certificates from the **OS trust store** (rustls); install Pipelock's CA there when intercepting. Do not invent Node-only `NODE_EXTRA_CA_CERTS` wiring for the Rust CLI.

## Quick Start

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
```

The CLI honors standard proxy environment variables (`HTTPS_PROXY`, `HTTP_PROXY`, `NO_PROXY`). Set proxy idle timeouts to **at least 10 minutes** so long SSE model streams are not cut off mid-response (see [xAI enterprise network docs](https://docs.x.ai/build/enterprise)).

Authenticate with the usual Grok paths (`grok login`, device auth, or `XAI_API_KEY`). Pipelock does not replace Grok authentication.

## Optional: TLS interception CA

When Pipelock terminates TLS so it can scan HTTPS bodies:

1. Enable interception and distribute the CA per [TLS interception](tls-interception.md).
2. Trust `~/.pipelock/ca.pem` in the **OS trust store** (Grok loads system roots). On Linux that is typically `update-ca-certificates` / `update-ca-trust`; on macOS, the system keychain — same instructions as the TLS guide.

Without a trusted CA, intercepted HTTPS handshakes fail. Without interception, CONNECT tunnels stay body-opaque (hostname-level controls only).

## Config file note

`~/.grok/config.toml` can bind an `api_key` (or custom `base_url`) per model. That file is **not** a Pipelock proxy rewrite surface: it does not replace `HTTPS_PROXY` / `HTTP_PROXY`, and Pipelock does not rewrite it. Prefer env vars for this integration.

Required / common hosts include `cli-chat-proxy.grok.com` (inference proxy), `auth.x.ai` (OAuth/device auth), and `api.x.ai` (API key path). Allow those destinations in your Pipelock policy the same way you allow other model endpoints (see [xAI enterprise network docs](https://docs.x.ai/build/enterprise)).

## What Gets Scanned

| Direction | Content |
|---|---|
| Grok → model API (via proxy) | DLP, SSRF, URL/policy checks on traffic the proxy sees |
| Model API → Grok (via proxy) | Response injection checks when bodies are visible (TLS interception) |

Tools and subprocesses that ignore proxy environment variables need `pipelock contain`, a sandbox, or another network boundary — cooperative proxying is not binary-enforced isolation.

## Choosing a Config

| Preset | Action | Best for |
|---|---|---|
| `balanced` | warn | Getting started, tuning phase |
| `strict` | block | High-security workflows |
| `hostile-model` | block | Uncensored or jailbroken models |

Start with `balanced` to see what gets flagged, then move to a blocking preset once you have verified no false positives.

## See also

- [TLS interception](tls-interception.md) — CA trust and HTTPS body visibility
- [OpenAI Codex guide](codex.md) — forward-proxy pattern for another CLI agent
- [Continue.dev guide](continue.md) — MCP YAML wrapping (different integration class)
- [Receipt verification](receipt-verification.md) — independent audit of proxy decisions
