# Playground broker operations

> **Demonstration tooling, not a shipped product feature.** The playground
> binaries live under `cmd/` and are built from source; they are **not packaged in
> Pipelock releases**, and the production firewall does not depend on them. This
> guide documents evaluation/demonstration tooling.

`pipelock-playground-broker` is the public front door for the live playground. It
serves the static viewer, validates the visitor gate, leases one isolated
per-visitor VM, and reverse-proxies `/api/live/*` to that VM. Treat it as an
internet-facing cost and abuse boundary: every accepted session can boot compute
and every VM can spend model tokens.

## Public exposure checklist

Before removing an external identity gate, the broker must have all of these
controls enabled:

| Control | Required setting |
|---|---|
| Human/bot gate | `--turnstile-secret-file` or `--turnstile-secret-env` |
| Global broker spend cap | `--global-daily-budget` greater than `0` |
| Per-VM model spend cap | `--vm-daily-turn-budget` greater than `0` |
| Abuse buckets | `--per-ip-daily-budget`, `--per-code-daily-budget`, IP/code rates |
| Short sessions | `--session-ttl`, `--deadline-grace`, `--vm-session-ttl` |
| Host protection | `--public-host`, `--allow-origin`, and origin-side Access JWT while private |
| Provider backstop | Model-provider billing cap or prepaid balance outside Pipelock |

The broker refuses to start with unlimited global/model budgets unless
`--unsafe-unlimited-budgets` is set. That escape hatch is for local development,
not public deployments. Think of this like a shutoff valve: rate limits slow the
flow, but a positive daily budget is the valve that stops the bill.

The broker also refuses to start without either Turnstile or Cloudflare Access
unless `--unsafe-no-human-gate` is set. Use that only for local development or a
separately protected private environment; anonymous public traffic needs a bot
gate before session creation.

## Example command

```bash
pipelock-playground-broker serve \
  --listen 0.0.0.0:8100 \
  --provider fly \
  --fly-app playground-example \
  --fly-token-env FLY_API_TOKEN \
  --image registry.example.com/pipelock/playground-vm:review \
  --region iad \
  --memory-mb 256 \
  --cpus 1 \
  --internal-port 8080 \
  --concurrency 20 \
  --code press-review-code \
  --max-per-code 25 \
  --global-daily-budget 60 \
  --per-ip-daily-budget 20 \
  --per-code-daily-budget 60 \
  --admin-listen 127.0.0.1:8101 \
  --admin-token-env PLAYGROUND_ADMIN_TOKEN \
  --turnstile-secret-env PLAYGROUND_TURNSTILE_SECRET \
  --vm-model-base-url https://api.provider.example/v1 \
  --vm-model demo-model \
  --vm-model-max-steps 20 \
  --vm-daily-turn-budget 400 \
  --vm-max-messages-per-session 20 \
  --vm-session-ttl 30m \
  --static-dir ./dist/playground \
  --allow-origin https://playground.example.com \
  --public-host playground.example.com
```

Secrets are loaded from files or environment variables and are never printed by
the broker. Do not pass model keys, provider tokens, Turnstile secrets, or invite
codes through public logs or shell history in real deployments.

## Human verification

When `--turnstile-secret-file` or `--turnstile-secret-env` is set, session
creation requires a JSON `turnstile_token` field. The broker sends that token,
plus the resolved client IP, to Cloudflare Turnstile Siteverify before redeeming
the invite code or leasing a VM. Missing, expired, duplicated, oversized,
unparseable, or rejected tokens fail closed with HTTP 403.

The static UI must obtain the token in the visitor's browser and include it with
the `/api/live/session` request. The server-side verification is mandatory; a
client-side widget without Siteverify does not protect the broker.

## Client IPs behind Cloudflare

The broker always accepts `CF-Connecting-IP` only when the direct TCP peer is in
Cloudflare's published proxy ranges. Direct clients cannot mint a fresh abuse
bucket by forging Cloudflare headers. `--trust-forwarded-for` remains available
for other trusted reverse proxies, but only enable it when the broker is not
reachable directly.

IPv6 clients are bucketed by their `/64` network for rate limits and per-IP
budgets, so an attacker cannot evade per-IP caps by rotating addresses inside a
single allocation. IPv4 clients are bucketed by their exact address.

The Cloudflare proxy ranges are compiled into the binary from
<https://www.cloudflare.com/ips-v4/> and <https://www.cloudflare.com/ips-v6/>.
If Cloudflare adds a range, clients arriving from it collapse to the shared edge
IP as one abuse bucket (over-restrictive, never a bypass) until the list is
refreshed in a new build.

Validation command:

```bash
curl -i https://playground.example.com/api/live/session \
  -H 'Content-Type: application/json' \
  -H 'X-Forwarded-For: 198.51.100.200' \
  --data '{"code":"press-review-code","turnstile_token":"invalid"}'
```

Expected result for the invalid token is HTTP 403. The request must not lease a
VM and must not create a separate per-IP budget bucket from the forged
`X-Forwarded-For` value.

## Pause and resume

The broker has an emergency kill switch. `SIGUSR1` pauses the broker and releases
all active leases; `SIGUSR2` resumes new sessions. `SIGTERM` and `SIGINT` trigger
graceful HTTP shutdown. For remote operation, run the authenticated admin API on
a separate listener with `--admin-listen` plus `--admin-token-file` or
`--admin-token-env`.

Bind `--admin-listen` to loopback or a private interface, never the public
internet, and use a long random token (e.g. `openssl rand -hex 32`). The token is
compared in constant time, but the endpoint has no rate limiting or lockout by
design, so a weak token on a reachable interface is brute-forceable.

On a single host:

```bash
kill -USR1 "$(pidof pipelock-playground-broker)"
```

What this does: engages the broker pause switch and tears down current leased VMs.

```bash
kill -USR2 "$(pidof pipelock-playground-broker)"
```

What this does: clears the pause switch so new sessions can start again.

Through the admin listener:

```bash
curl -sS -X POST http://127.0.0.1:8101/admin/pause \
  -H "Authorization: Bearer $PLAYGROUND_ADMIN_TOKEN"
```

What this does: authenticates with the admin bearer token, engages the pause
switch, and releases active leases.

```bash
curl -sS -X POST http://127.0.0.1:8101/admin/resume \
  -H "Authorization: Bearer $PLAYGROUND_ADMIN_TOKEN"
```

What this does: authenticates with the admin bearer token and clears the pause
switch.

Health check:

```bash
curl -s https://playground.example.com/api/live/health
```

Admin health check:

```bash
curl -s http://127.0.0.1:8101/admin/health \
  -H "Authorization: Bearer $PLAYGROUND_ADMIN_TOKEN"
```

During pause, health reports `"killed":true` and session creation returns HTTP
503 with a paused-demo message.

## Monitoring

Poll `/api/live/health` and alert on:

| Signal | Why it matters |
|---|---|
| `ok:false` | Broker is paused, out of global budget, or gate is closed |
| `budget_remaining` near `0` | The demo is about to stop accepting sessions |
| `in_use` near `capacity` | Visitors are queued out by the concurrency cap |
| `session_starts_last_minute` spike | Bot traffic or an invite code shared more broadly than planned |
| Repeated HTTP 403 on session creation | Bot traffic, invalid Turnstile tokens, or bad invite flow |
| Repeated HTTP 429 | Abuse pressure or caps set too low for the audience |
| Repeated HTTP 503 on `/api/live/message` | Model provider is out of credits, has bad credentials, or is rate-limiting; check provider billing and the model key |

Also configure the model provider's own billing alert or hard spend cap. The
broker's in-process budgets reset on restart and are intentionally not a billing
system.

## Abuse response

1. Pause immediately with `SIGUSR1`.
2. Confirm health reports `"killed":true`.
3. Check provider billing and active machine count.
4. Rotate invite codes if a shared code leaked.
5. Reduce `--concurrency`, daily budgets, session TTL, or per-IP caps before
   resuming.
6. Resume with `SIGUSR2` only after the cost ceiling and bot gate are confirmed.

## Deploy and rollback

Keep the public broker as a single warm instance unless shared state is added.
The broker's token-to-lease table and daily budgets are in memory. Running two
brokers without shared state can split sessions, double budgets, and route a
visitor to a broker that does not recognize its token.

Deploy sequence:

1. Build and publish the VM image.
2. Start the broker with explicit budgets and Turnstile enabled.
3. Check `/api/live/health`.
4. Run one valid session through the public hostname.
5. Run one invalid Turnstile/session request and confirm it fails closed.
6. Pause with `SIGUSR1`, confirm session creation returns HTTP 503, then resume.

Rollback sequence:

1. Pause the current broker with `SIGUSR1`.
2. Redeploy the prior broker image or config.
3. Confirm health and budget values.
4. Run the invalid-token and pause/resume checks again before sending traffic
   back.
