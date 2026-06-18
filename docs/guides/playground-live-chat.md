# Playground live chat: operator controls

The live-chat playground (`pipelock-playground-live serve`) lets a visitor talk to
a real model-backed agent and watch Pipelock mediate the agent's actual requests
in real time, streaming a signed decision for every action. Unlike the recorded
replay demo, every visitor message drives a real model API call, so it costs money
and is an attack surface. This page covers the controls an operator uses to run it
safely.

> The agent is provider-neutral: any OpenAI-compatible `/chat/completions` endpoint
> (base URL, model name, bearer key). The agent only ever holds a synthetic,
> per-run canary, never real credentials.

## Running it

```bash
pipelock-playground-live serve \
  --listen 0.0.0.0:8099 \
  --code <invite-code> \
  --llm-agent-bin /usr/local/bin/pipelock-playground-llm-agent \
  --model-base-url https://api.provider.example/v1 \
  --model <model-name> \
  --model-secret-file /run/secrets/model.key \
  --daily-turn-budget 2000 \
  --max-messages-per-session 40
```

Omitting the `--llm-agent-bin`/`--model-*` flags runs the deterministic
(non-model) agent instead. The model API key is read from `--model-secret-file`
(a path), never passed on the command line. `--model-base-url` must be a plain
HTTP(S) API root such as `https://api.provider.example/v1`; query strings,
fragments, and URL credentials are rejected so provider secrets cannot end up in
request URLs, logs, or receipts.

## Safety and abuse controls

These are layered: the rate limiters bound how *fast* the demo can be driven, and
the budgets bound the *total*. Public exposure should set all of them.

| Control | Flag | What it bounds |
|---|---|---|
| Invite-code gate | `--code` (repeatable), `--max-per-code` | Who can start a session; lifetime sessions per code |
| Global concurrency | `--concurrency` | Simultaneous live sessions |
| Per-IP / per-code rate | `--ip-rate`/`--ip-burst`, `--code-rate`/`--code-burst` | Request rate per client / per code |
| Session wall-clock | `--session-ttl` | How long one session lasts |
| Input size | `--max-input-bytes` | Size of one message |
| **Per-session message cap** | `--max-messages-per-session` | Messages (model calls) per session. Default 40. |
| **Daily spend kill switch** | `--daily-turn-budget` | **Hard ceiling on total turns (model calls) per UTC day.** When spent, messages are refused until the next UTC day. |

### Why the daily budget matters

Rate limits alone are not a spend ceiling: a flood of distinct codes or IPs, each
under its own per-client limit, still adds up to an unbounded model bill. The
daily turn budget is the hard backstop. Once the day's budget is spent, the demo
refuses further messages (HTTP 503, "paused until tomorrow") and resets at the UTC
day boundary. A value of `0` means unlimited and must only be used for local/dev
runs. The server refuses to enable the model-backed agent outside `--dev` unless
`--daily-turn-budget` is positive. `/api/live/health` reports
`budget_remaining`.

The in-process budget protects one live server process. Public deployments should
also set an account/provider spend cap, because a process restart or a multi-node
deployment is outside that local counter.

## Containment posture

- `--require-containment` (default) refuses to start a session unless host kernel
  containment is established and verified. Use this for any exposed deployment.
- `--dev` runs **uncontained** and says so loudly. The detection and enforcement
  controls (egress allowlist, DLP, signed receipts) still apply, but the host
  kernel does not block an out-of-band egress path. Never use `--dev` for public
  exposure.

The model-backed agent runs as a separate, proxy-only subprocess: its transport
may dial only the Pipelock proxy, so its model calls and tool calls are all
mediated. This is a transport-level guarantee; where the host provides kernel
containment, that no-bypass property is attested separately. Egress for a
model-agent run is restricted to the lab targets and the model API host; any other
destination is refused. The model provider authorization header is allowed only to
the configured `/chat/completions` endpoint; lab target requests remain scanned
and blocked on credential-shaped payloads.

## Deployment guidance

Run the public instance on isolated cloud infrastructure (a separate account/org),
not on shared or homelab hardware: the demo is a deliberately jailbreakable agent
behind a public endpoint, so its blast radius should be disposable and account-
isolated. The frontend is static and can be served separately. See the playground
cost/hosting plan for the recommended topology.

For the reverse proxy/CDN in front of the server:

- Do not log query strings for `/api/live/stream`; the SSE token is a short-lived
  bearer token in the URL query.
- Set `--trust-forwarded-for` only when the server is reachable exclusively
  through that trusted proxy/CDN.
- If the browser is served from a different origin, set `--allow-origin` to that
  exact origin, such as `https://pipelab.org`. Wildcard CORS is rejected outside
  `--dev`.
