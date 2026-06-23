<!--
Copyright 2026 Josh Waldrep
SPDX-License-Identifier: Apache-2.0
-->

# Enterprise License Issuance Runbook

This runbook covers the technical path for issuing and installing an Enterprise
license that grants the `fleet` feature.

## Feature Mapping

The license service maps commercial tiers to runtime feature flags in
`enterprise/licenseservice`. The Enterprise and Enterprise Eval tiers must grant:

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

- Enterprise/Eval tier mapping includes `fleet`.
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
