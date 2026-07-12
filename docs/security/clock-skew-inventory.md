<!--
Copyright 2026 Josh Waldrep
SPDX-License-Identifier: Apache-2.0
-->

# v3.1.0 Clock-Skew Inventory

This inventory records the v3.1.0 sweep for the class where one host stamps a
time and another host validates it with its own clock. The rule used here:

- Cross-host `not_before` / created-time gates may tolerate bounded positive
  skew.
- Expiry remains strict; skew must not extend an authorization after it ends.
- Local timers, retry windows, rate windows, and cache TTLs are not cross-host
  validity checks.

## Inventory

| Surface | Code | Cross-host? | Verdict |
|---|---|---:|---|
| Conductor policy bundle validity | `enterprise/conductor/messages.go:NotBeforeReached`, `withinValidity`; `enterprise/conductor/controlplane/store.go:latestBundleForFollower` | Yes | Fixed in v3.0.0. `not_before` uses `MessageNotBeforeSkew`; `expires_at` remains strict. |
| Conductor remote-kill validity | `enterprise/conductor/messages.go:RemoteKillMessage.ValidateAtTime`; `enterprise/conductor/emergency/remote_kill.go`; `enterprise/conductor/controlplane/emergency_store.go` | Yes | Fixed in v3.0.0 through shared `withinValidity`. |
| Conductor rollback validity | `enterprise/conductor/messages.go:RollbackAuthorization.ValidateAtTime`; `enterprise/conductor/controlplane/emergency_store.go`; `enterprise/conductor/policysync/rollback_poller.go` | Yes | Fixed in v3.0.0 through shared `withinValidity`. |
| Conductor stream switch validity | `enterprise/conductor/messages.go:PolicyBundle.ValidateAtTime`; `enterprise/conductor/controlplane/store.go` | Yes | Fixed in v3.0.0 through shared bundle validity and `DefaultStreamSwitchMaxValidity`. |
| Conductor audit-batch created time | `enterprise/conductor/messages.go:AuditBatchEnvelope.ValidateForConductor`; `enterprise/conductor/capabilities.go` | Yes | Already bounded by negotiated `MaxCreatedSkew`; future and stale created times fail closed outside the window. |
| Conductor enrollment-token expiry | `enterprise/conductor/controlplane/enrollment.go:ConsumeEnrollmentToken` | Yes, but bearer-token TTL | No skew relaxation. Expiry is a credential lifetime; accepting past expiry would extend a leaked token. There is no `not_before` side. |
| Conductor backup manifest timestamp | `enterprise/cli/conductor/store_offline.go:conductorBackupManifest` | No | Local metadata only, not an authorization gate. |
| License token expiry | `internal/license/license.go:VerifyAt`; `internal/license/expiry.go` | Yes | Strict by design. License entitlement must not be extended by skew; there is no `not_before` token gate in the license payload. |
| License intermediate certificate window | `internal/license/intermediate.go:VerifyIntermediateAt` | Yes | Strict PKI-style validity. Keeping this strict prevents accepting a future intermediate before its intended activation. |
| License CRL expiry and freshness | `internal/license/crl.go`; `internal/license/crl_highwater.go` | Yes | Strict expiry plus monotonic high-water. Relaxing expiry would extend revoked-license exposure; freshness checks already fail closed. |
| Mediation-envelope signature created/expires | `internal/envelope/verify.go:validateSignatureTiming`; `internal/envelope/replay.go` | Yes | Already has bounded created-time skew (`created_skew_seconds`) and strict effective expiry/replay retention. |
| SVID / trust-bundle action-time validation | `internal/svid/svid.go:ValidateSVID`; `internal/svidsidecar/svidsidecar.go` | Yes | Strict by design. The verifier validates at the claimed action time; allowing skew would weaken point-in-time proof. |
| Receipt chain timestamps | `internal/receipt/chain.go` | No for authorization | Informational ordering/reporting. Signature and hash-chain checks are the security boundary, not wall-clock acceptance. |
| HITL / defer / airlock timeouts | `internal/hitl`, `internal/mcp/defer_resolver.go`, `internal/cli/runtime` | No | Local fail-closed timers; no remote-stamped validity. |
| Rate limits / adaptive windows / session TTLs | `internal/scanner`, `internal/decide`, `internal/session`, `internal/mcp/chains` | No | Local accounting windows. Skew relaxation is not applicable. |
| License-service webhook timestamp tolerance | `enterprise/licenseservice/polar.go` | Yes, third-party webhook | Already has explicit bounded tolerance; outside tolerance fails closed. |

## Tests / Proof Commands

Run these from the repository root:

```bash
go test -tags enterprise -count=1 ./enterprise/conductor ./enterprise/conductor/controlplane ./enterprise/conductor/emergency ./enterprise/conductor/policysync
```

The conductor package includes regression coverage for bounded `not_before`
skew while keeping expiry strict. The control-plane, emergency, and
poller packages exercise the same validity helpers through handler/store/poller
paths.
