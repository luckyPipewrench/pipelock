# Pipelock examples

Start with [quickstart](quickstart/README.md) for a Docker deployment with an isolated agent network, or [fetch proxy and SSRF](fetch-proxy-ssrf/README.md) for a local proxy walkthrough. Each linked README gives setup, commands, and the limits of its demonstration. Scanning applies to traffic routed through Pipelock; network isolation depends on the deployment.

## Examples with verification scripts

The directories below contain `verify.sh`. A script's presence means a check is available, not that it has passed in your environment. Local binary examples use `pipelock` at the repository root (`make build`), or `PIPELOCK_BIN` set to an executable path, plus Bash and Python 3. HTTP examples also use `curl`; additional requirements appear below. Local fixtures avoid external API calls, but building binaries or pulling container images can require network access.

| Example | Task | Runtime and prerequisites |
|---|---|---|
| [Quickstart](quickstart/README.md) | Isolate an agent network and exercise fetch, secret detection, response scanning, and MCP manifest scanning | Docker Engine and Compose v2; run the verification profile through Compose |
| [Docker forward proxy](docker-compose-proxy/README.md) | Route HTTP through a proxy to a Compose-local upstream | Docker Engine, Compose v2, `curl`, Python 3; builds a local image |
| [Fetch proxy and SSRF](fetch-proxy-ssrf/README.md) | Check clean fetches, private/metadata destination blocks, and response scanning | Local binary, Python HTTP fixture, `curl` |
| [WebSocket proxy](websocket-proxy/README.md) | Check clean text, secret detection, and binary-frame rejection | Local binary, Go helper programs, Python 3, `curl` |
| [SSE streaming scan](sse-streaming-scan/README.md) | Forward clean server-sent events and terminate an injection-bearing stream | Local binary, Python upstream, `curl`; reverse-proxy transport |
| [GraphQL request policy](request-policy-graphql/README.md) | Allow queries and deny protected mutations or malformed operations | Local binary, Python stub, `curl`; HTTP forward proxy |
| [Canary tokens](canary-tokens/README.md) | Detect synthetic canaries in URL forms | Offline `pipelock check`; no running proxy |
| [Kill switch](kill-switch/README.md) | Activate and clear a sentinel-file traffic stop while health stays available | Local binary, Python HTTP fixture, `curl` |
| [Hot reload](hot-reload/README.md) | Tighten policy without restarting the proxy | Local binary, Python HTTP fixture, `curl` |
| [MCP tool policy](mcp-tool-policy/README.md) | Apply tool-name and argument rules before forwarding a call | Local binary and Python stdio MCP decoy |
| [Tool poisoning honeypot](tool-poisoning-honeypot/README.md) | Block poisoned tool descriptions and a policy-denied call | Local binary and Python stdio MCP decoy |
| [MCP media policy](mcp-media-policy/README.md) | Strip JPEG metadata and block audio/video results | Local binary and Python stdio MCP decoy |
| [Learn and lock](learn-and-lock/README.md) | Learn a behavioral baseline, lock it, and deny a novel call | Local binary and Python stdio MCP decoy; baseline workflow |
| [Receipt verification](receipt-verify/README.md) | Capture a signed block receipt and reject tampered evidence | Local binary, Python 3, `curl`; generates a signing key |
| [SIEM events](siem-events/README.md) | Deliver block events to a webhook collector | Local binary, Python collector and HTTP fixture, `curl` |
| [Cursor integration](cursor-integration/README.md) | Install/remove hooks and simulate their input payloads | Temporary hook configuration; Cursor needn't be running |
| [OpenCode integration](opencode-integration/README.md) | Install/remove MCP wrappers and check configuration preservation | Temporary configuration; OpenCode needn't be installed |
| [Pi integration](pi-integration/README.md) | Install/remove the global HTTP proxy setting | Temporary settings directory; no Gemini API key required |

With the Go toolchain required by [go.mod](../go.mod) and Make installed, build a binary from the repository root and run one local example:

```bash
make build
export PIPELOCK_BIN="$PWD/pipelock"
bash examples/fetch-proxy-ssrf/verify.sh
```

To run the aggregate checks:

```bash
bash scripts/verify-examples.sh
```

The [aggregate runner](../scripts/verify-examples.sh) first checks guide links, requires an executable binary, discovers directory-level `verify.sh` files, and also runs Cline/OpenCode installation and MCP runtime checks. Quickstart also requires Go: the runner builds a binary from the current checkout and runs it through Compose. It reports `PASS`, `FAIL`, and `SKIP` separately and exits nonzero on failure. A zero exit status can include skips; inspect the summary for checks that weren't covered. Installation-only examples don't establish a live IDE session or provider request.

## Other walkthroughs and fixtures

These directories have no `verify.sh` and aren't discovered by the aggregate runner.

| Example | Contents and use |
|---|---|
| [Tool response injection](tool-response-injection/README.md) | Python demo for response scanning and signed receipts across MCP stdio, MCP HTTP, and fetch; requires a Pipelock binary and Python `cryptography`. The demo regenerates keys and evidence in its directory. |
| [Verifiable shadow rollout](verifiable-shadow-rollout/README.md) | Captured traffic, candidate contract, shadow report, and signed delta receipts; Go generator and standalone verifier commands are documented. |
| [Playground replay](playground-replay/README.md) | Saved evidence, manifest, packet, summary, verifier output, and public key for a replay fixture. |
| [Agent threat detection](agent-threat-detection/README.md) | Correlated telemetry and a synthetic receipt illustrating the proposed OpenTelemetry convention; the receipt is a schema sample, not a cryptographic verification fixture. |
| [Conductor](conductor/README.md) | Receipt-producer inventory for the production runbook. |
| [Prometheus](prometheus/README.md) | Alert-rule YAML to adapt to your monitoring setup. |

## Top-level samples and utilities

- [Basic CI workflow](ci-workflow.yaml) and [advanced CI workflow](ci-workflow-advanced.yaml) are GitHub Actions templates to copy and adapt. The advanced template expects a committed `pipelock.yaml`.
- [Sample events](sample-events.jsonl), [HTML report](sample-report.html), and [report image](sample-report.png) are saved output samples.
- [Interactive demo](demo.sh) and [recording demo](demo-readme.sh) are presentation scripts using `pipelock` on `PATH`. They aren't aggregate verification cases.
- [Guide-link checker](check_guide_links.py) and [its tests](test_guide_links.py) maintain navigation between examples and guides.

See the [configuration reference](../docs/configuration.md) for policy fields and [deployment recipes](../docs/guides/deployment-recipes.md) for adapting a walkthrough to a deployment.
