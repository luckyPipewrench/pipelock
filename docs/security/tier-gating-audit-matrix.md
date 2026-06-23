# Tier Gating Audit Matrix

This matrix records the v2.7 runtime entitlement audit for paid Pipelock
surfaces. Originally audited at `521cdbbd`; the follower-side Conductor
revocation parity gap described in "v2.7 update: Conductor live revocation"
(below) was closed during the 2026-06-07 v2.7 release-hardening pass.

Rule: detection, blocking, scanning, verification, and single-agent enforcement
stay free. Paid code must fail closed at runtime with `License.HasFeature`, not
only by living behind the `enterprise` build tag.

## Entitlement Map

| Entitlement | Tier | Runtime gate |
|-------------|------|--------------|
| `license.FeatureAgents` (`agents`) | Pro | `enterprise.EnforceLicenseGate` strips named agent profiles unless the verified license carries `agents`. |
| `license.FeatureAssess` (`assess`) | Assess | `assess checkAssessLicense` emits full signed assessments only when the verified license carries `assess`. |
| `license.FeatureFleet` (`fleet`) | Enterprise | `license.VerifyFleet` gates Conductor, fleet sink, bootstrap, and follower-side Conductor runtime. |

## Paid Surface Matrix

| Paid surface | Tier | Entitlement | Gate site | Tokenless deny | Under-tier deny | Correct allow | Malformed / expired / revoked deny | Reload / revocation parity |
|--------------|------|-------------|-----------|----------------|-----------------|---------------|------------------------------------|----------------------------|
| Named agent profiles | Pro | `FeatureAgents` | `enterprise/config.go` via `config.EnforceLicenseGateFunc` | `TestEnforceLicenseGate_NoLicenseKey`; `TestLicenseGateViaLoad` | `TestEnforceLicenseGate_MissingFeature` | `TestEnforceLicenseGate_ValidLicense`; `TestLicenseGateViaLoad_WithValidToken` | `TestEnforceLicenseGate_InvalidToken`; `TestEnforceLicenseGate_ExpiredLicense`; `TestEnforceLicenseGate_RevokedLicense` | `TestServer_ReloadLicenseRevocationStripsAgents` |
| Per-agent listeners | Pro | `FeatureAgents` | Same `agents:` gate; listener sockets are derived from surviving named profiles | Same as named agent profiles | Same as named agent profiles | Same as named agent profiles plus `TestAgentRegistryPorts` | Same as named agent profiles | `TestServer_ReloadLicenseRevocationStripsAgents`; listener changes remain restart-only in `TestServer_Reload_PreservesRestartOnlyFields` |
| Source CIDR to agent mapping | Pro | `FeatureAgents` | Same `agents:` gate | Same as named agent profiles | Same as named agent profiles | `TestAgentRegistryMatchCIDR`; `TestAgentRegistryResolveFromRequest_CIDR` | Same as named agent profiles | Same as named agent profiles |
| Per-agent DLP, rate limits, budgets, mode, enforce, API allowlist, trusted domains, session thresholds, MCP tool policy, crypto address allowlists, and sandbox profiles | Pro | `FeatureAgents` | Same `agents:` gate; values are applied only after profile resolution. `agents[*].allowed_addresses` is additionally ignored by the core scanner unless `FeatureAgents` has been verified at runtime. | Same as named agent profiles; `TestScanRequestBody_NamedAgentAddressAllowlistIgnoredWithoutFeatureAgents` | Same as named agent profiles | `TestAgentRegistryProfiles`; `TestAgentRegistryBudgetIntegration`; `TestValidateMergedAgent_InvalidAnomalyAction`; `TestScanRequestBody_AddressWithAgentID` | Same as named agent profiles | Same as named agent profiles |
| Full signed assessment artifacts (`assessment.json`, `assessment.html`, manifest signature, attestation/badge when requested) | Assess | `FeatureAssess` | `internal/cli/assess/finalize.go` | `TestCheckAssessLicenseFeatureGate/tokenless denies paid assessment` | `TestCheckAssessLicenseFeatureGate/under-tier agents token denies paid assessment` | `TestCheckAssessLicenseFeatureGate/assess feature allows paid assessment`; `TestAssessFinalize_Licensed_AutoSigns` | `TestCheckAssessLicenseFeatureGate/malformed token denies paid assessment`; expired, revoked, and unloadable-CRL subtests | Not a hot-reloaded service; every finalize invocation re-reads and verifies the current config/license/CRL |
| Conductor signed policy distribution (follower bundle poller + apply cache) | Enterprise | `FeatureFleet` | `internal/cli/runtime/server.go` calls `license.VerifyFleet` when `conductor.enabled` is true | `TestNewServer_ConductorEnabledRequiresFleetLicense`; `TestRequireFleet_NoLicenseFailsClosed` | `TestRequireFleet_AgentsOnlyLicenseRejected`; `TestRequireFleet_AssessOnlyLicenseRejected` | `TestRequireFleet_FleetFeatureAccepted`; `TestNewServer_WiresConductorBundlePoller` | `TestRequireFleet_InvalidSignatureRejected`; `TestRequireFleet_ExpiredLicenseRejected`; `TestVerifyFleet_CRLRejectsRevokedFleetLicense`; `TestNewServer_ConductorEnabledRejectsRevokedFleetLicense` | `TestServer_ReloadCannotActivateConductorWithNewLicense`; conductor settings are restart-only in `TestServer_Reload_PreservesRestartOnlyFields` |
| Conductor emergency remote kill | Enterprise | `FeatureFleet` | Same follower-side `conductor.enabled` gate | Same as Conductor signed policy distribution | Same as Conductor signed policy distribution | `TestServer_StartRunsConductorRemoteKillPoller` | Same as Conductor signed policy distribution | Same as Conductor signed policy distribution |
| Conductor durable audit aggregation / audit batch producer | Enterprise | `FeatureFleet` | Same follower-side `conductor.enabled` gate for follower producer; server-side `pipelock conductor serve` gate for ingest | `TestNewServer_ConductorEnabledRequiresFleetLicense`; `TestServeCmd_NoFleetLicenseFailsClosed` | `TestRequireFleet_AgentsOnlyLicenseRejected` | `TestNewServer_ConductorAuditProducerFromConfig`; `TestRequireFleet_FleetFeatureAccepted` | Fleet malformed, expired, and revoked tests above | Same as Conductor signed policy distribution |
| `pipelock conductor serve` control plane | Enterprise | `FeatureFleet` | `enterprise/cli/conductor/cmd.go` calls `license.VerifyFleet` before listener bind | `TestServeCmd_NoFleetLicenseFailsClosed` | `TestRequireFleet_AgentsOnlyLicenseRejected`; shared `VerifyFleet` gate | `TestRequireFleet_FleetFeatureAccepted`; command setup tests exercise post-gate server build with test licenses | `TestRequireFleet_InvalidSignatureRejected`; `TestRequireFleet_ExpiredLicenseRejected`; CRL revoked tests | Not hot-reloaded; command start verifies before serving |
| `pipelock conductor follower remove` | Enterprise | `FeatureFleet` | `enterprise/cli/conductor/follower.go` calls `license.VerifyFleet` before building the control-plane client | Shared `VerifyFleet` gate; command refuses without fleet license before request | Shared `VerifyFleet` gate | `TestFollowerRemoveSendsDeleteAndRendersSummary`; `TestHandlerRemoveFollowerDecommissionsAuditKey` | Shared malformed/expired/revoked `VerifyFleet` tests; handler rejects auditor/non-admin and unknown follower | Not hot-reloaded; each invocation re-verifies before mutating Conductor enrollment state |
| `pipelock conductor store backup` / `restore` | Enterprise | `FeatureFleet` | `enterprise/cli/conductor/store_offline.go` calls `license.VerifyFleet` before copying/restoring storage | `TestStoreBackupRestoreRoundTrip` via command gate with test fleet license; shared tokenless gate style from offline store commands | Shared `VerifyFleet` gate | `TestStoreBackupRestoreRoundTrip` | Shared malformed/expired/revoked `VerifyFleet` tests; backup rejects destination inside storage | Offline operator action; run while Conductor is stopped or from a volume snapshot |
| `pipelock fleet-sink` standalone audit sink | Enterprise | `FeatureFleet` | `enterprise/cli/fleet/sink.go` calls `license.VerifyFleet` before listener bind or disk IO | `TestSinkCmd_NoFleetLicenseFailsClosed` | `TestRequireFleet_AgentsOnlyLicenseRejected`; shared `VerifyFleet` gate | `TestRequireFleet_FleetFeatureAccepted`; sink command tests exercise post-gate validation with test licenses | `TestRequireFleet_InvalidSignatureRejected`; `TestRequireFleet_ExpiredLicenseRejected`; CRL revoked tests | Not hot-reloaded; command start verifies before serving |
| `pipelock conductor bootstrap` automation | Enterprise | `FeatureFleet` | `enterprise/cli/conductor/bootstrap.go` calls `license.VerifyFleet` before key/material generation | `TestBootstrapCmd_NoFleetLicenseFailsClosed` | `TestRequireFleet_AgentsOnlyLicenseRejected`; shared `VerifyFleet` gate | `TestBootstrapCmd_StandsUpFleet` | `TestRequireFleet_InvalidSignatureRejected`; `TestRequireFleet_ExpiredLicenseRejected`; CRL revoked tests | Not hot-reloaded; command start verifies before writing material |
| Enterprise Eval fulfillment | Enterprise | `FeatureFleet` token minting | `enterprise/licenseservice` maps `enterprise_eval` to `agents` + `fleet` and rejects unconfigured or malformed eval orders | n/a: this is token issuance, not an end-user runtime surface | `TestTierToFeatures` ensures only Enterprise/Eval get `fleet` | `TestHandleOrderPaid_MintsEvalToken`; `TestHandleOrderPaid_MintedTokenVerifies` | `TestHandleOrderPaid_RejectsInvalidOrders`; `TestHandleOrderRefund_RevokesMintedEval` | Issued eval token expiry and refund revocation are tested by eval store/webhook tests |
| License-service tier to feature minting | Entitlement authority | n/a | `enterprise/licenseservice/webhook.go:tierToFeatures` | Unknown tier returns nil in `TestTierToFeatures` | Pro/trial/founding Pro map only to `agents`; Assess maps only to `assess` | Enterprise and Enterprise Eval map to `agents` + `fleet` | Product metadata must be recognized by `mapProductToTier`; unknown tiers fail closed | n/a: license service persists entitlement state and revocations rather than hot-reloading runtime gates |

## Free Surfaces Verified Ungated

The audit found no license gate on core detection/enforcement surfaces. Scanner
pipeline, proxy modes, TLS interception, WebSocket scanning, MCP scanning,
tool poisoning detection, tool policy, session binding, chain detection, kill
switch, audit logging, receipts/verification, metrics, sandbox default policy,
and free CLI operational commands remain outside `HasFeature` gates.

Free assessment summary artifacts are intentionally ungated: unlicensed or
under-tiered users receive `summary.json`/`summary.html` without a paid signed
assessment artifact. This is tested by `TestAssessFinalize_Unlicensed_Summary`
and `TestAssess_EndToEnd_Unlicensed`.

## v2.7 update: Conductor live revocation (parity with agents)

The original audit recorded the follower-side Conductor runtime (Enterprise
`fleet` feature) as start-gated and restart-only: the fleet license was verified
at startup, and a config reload could not activate Conductor, but a license
revoked/expired/downgraded at runtime left an already-running follower
participating until process restart. Agent listeners (`agents` feature) did not
have this gap — they are torn down live by `EnforceLicenseGate` on a revocation
reload and by the runtime CRL watcher. v2.7 closes the asymmetry so the fleet
feature enforces revocation at runtime exactly like agents do:

- The runtime CRL watcher now starts when `conductor.enabled` (not only when
  agent listeners exist) and, on a fail-closed CRL result, tears down the
  Conductor runtime as well as agent listeners.
- Config load now folds the env-provided CRL path and verifier public key
  (`PIPELOCK_LICENSE_CRL_FILE`, `PIPELOCK_LICENSE_PUBLIC_KEY`) into the resolved
  config (inline values still win), so an env-supplied CRL is enforced at
  runtime by the watcher, not only at startup by `VerifyFleet`. This closes a
  pre-existing env-CRL fail-open that affected agent listeners too.
- The config reload path re-verifies the fleet entitlement on a license-input
  change and tears down Conductor when the new license is revoked, expired, or
  no longer carries `fleet`.
- The license-expiry timer stops the Conductor runtime on expiry.
- Teardown cancels the follower pollers, detaches the durable-audit observer,
  closes the audit producer, and blocks further `ApplyConductorPolicyBundle`
  calls — while leaving the proxy/detection path running (losing a paid fleet
  entitlement never disables free detection). Conductor stays down until
  restart; a reload still cannot re-activate it.

Tests: `TestRefreshLicenseCRL_RevokedTearsDownConductor`,
`TestReload_FleetDowngradeTearsDownConductor`,
`TestExpireLicensedRuntime_TearsDownConductor`,
`TestTeardownConductor_StopsRuntimeAndIsIdempotent`,
`TestTeardownConductor_NoopWhenNotRunning`,
`TestApplyConductorPolicyBundle_FailsAfterTeardown`,
`TestTeardownConductor_BeforeCancelPublishedFailsClosed`, the env-CRL fold
`TestLicenseRuntimeVerificationFromEnv`, and the negative control
`TestReload_NoLicenseChangeKeepsConductor`.
