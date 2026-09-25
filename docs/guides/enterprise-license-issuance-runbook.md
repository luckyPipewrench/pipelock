<!--
Copyright 2026 Josh Waldrep
SPDX-License-Identifier: Apache-2.0
-->

# Enterprise License Issuance Runbook

This runbook covers the technical path for issuing and installing an Enterprise
license that grants the `fleet` feature.

## License service probes

The license service keeps `GET /health` as unconditional liveness, while `GET /ready` reports whether a Polar provider read has succeeded within `PROVIDER_SUCCESS_WINDOW` (default `15m`). Point readiness probes at `/ready` and liveness probes at `/health` so a provider outage removes the pod from service without restarting it.

## License recovery

A customer who lost their license email can ask the service to send it again. The endpoint is off by default; set `SELF_SERVE_RESEND_ENABLED=true` to expose `POST /v1/license/resend`.

```bash
curl -sS -X POST https://licenses.vendor.example/v1/license/resend \
  -H 'Content-Type: application/json' \
  -d '{"email":"buyer@vendor.example"}'
```

What this does: queues a lookup and returns `202 Accepted` with the same body whether or not the address has a license. For every active, unexpired, unrevoked license whose persisted issuance is on record for that address, the service re-sends the existing token to the address on record. It never mints a new token, never moves an expiry, and never sends anything to an address other than the one stored for the license. An HTML form posting an `email` field works too. When `SELF_SERVE_RESEND_RETURN_URL` is set to an absolute `https` URL, a form submission is redirected there instead of receiving the plain-text reply.

Admitted requests are limited per address (one per 15 minutes, three per 24 hours). One admitted request re-sends up to 10 qualifying licenses for that address, and every email it sends counts against a service-wide budget of 60 per hour. The limits live in the service database, so a restart does not reset them. Each license is recorded as `license_resend_requested` in the audit ledger before it is sent, and is not sent if that entry cannot be written; completion is recorded as `license_resent` and a limiter refusal as `license_resend_throttled`. The caller cannot see any of these.

When the pending-request queue is full, the endpoint answers `503 Service Unavailable` with `Retry-After`. That depends only on load, not on the address. On shutdown the service finishes the requests it already accepted before it exits, within the shutdown deadline.

## Feature Mapping

The license service maps commercial tiers to runtime feature flags in
`enterprise/licenseservice`. The Enterprise, Enterprise Eval, and Enterprise Trial tiers must grant:

```text
agents
fleet
```

The runtime gate checks the feature string, not the tier label. Conductor,
fleet-sink, bootstrap, enrollment-token operations, and follower-side conductor
runtime all call the `fleet` gate and fail closed without it.

## Issuance Proof

Run:

```bash
go test -tags enterprise -count=1 ./enterprise/licenseservice ./enterprise/cli ./internal/license ./internal/cli/runtime
```

What this proves:

- Enterprise/Eval/Enterprise Trial tier mapping includes `fleet`.
- Pro/agents-only and Assess-only licenses do not unlock fleet features.
- Missing, malformed, expired, and revoked fleet licenses fail closed.
- Follower-side Conductor runtime tears down on fleet-license loss while the
  free detection path keeps running.

## Customer Install

```bash
pipelock license install "$PIPELOCK_LICENSE_KEY" \
  --path /etc/pipelock/license/license.token
```

What this does: writes the signed license token to the path mounted by the
Conductor or follower deployment.

```bash
pipelock license status
```

What this does: prints the verified tier, features, and expiry. The feature list
must include `fleet` before starting Conductor.

## Negative Checks

No license:

```bash
PIPELOCK_LICENSE_KEY= pipelock conductor serve \
  --storage-dir /var/lib/pipelock/conductor \
  --tls-cert /etc/pipelock/conductor/tls.crt \
  --tls-key /etc/pipelock/conductor/tls.key \
  --client-ca /etc/pipelock/conductor/client-ca.crt \
  --publisher-token-file /etc/pipelock/tokens/publisher \
  --publisher-org org-acme \
  --auditor-token-file /etc/pipelock/tokens/auditor \
  --admin-token-file /etc/pipelock/tokens/admin \
  --auditor-org org-acme \
  --admin-org org-acme
```

Expected result: command exits before binding a listener with a fleet-license
error.

Wrong tier:

```bash
pipelock license status
```

Expected result: features omit `fleet`; Conductor and fleet commands refuse to
start.
