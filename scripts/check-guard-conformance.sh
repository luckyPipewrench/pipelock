#!/usr/bin/env bash
# Copyright 2026 Josh Waldrep
# SPDX-License-Identifier: Apache-2.0
#
# Runs the Linux HTTP/HTTPS Guard preview's hostile-input release gate. The
# package tests drive the built `pipelock guard -- COMMAND` path and keep the
# direct-egress, filesystem, control-transport, proof, and claim boundaries in
# one CI entry point.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

go test -race -count=1 -timeout=5m ./internal/guard \
  -run '^(TestExecutionProofBindsEffectiveInvocation|TestReadExecEnvironmentOwnsInheritedDescriptor|TestOpenExecStatusWriterValidatesAndOwnsDescriptor|TestReadExecEnvironmentRoundTripAndClose|TestReadExecEnvironmentRejectsDuplicateKeys|TestDecodeExecEnvironmentRejectsMalformedAndOversizedPayloads|TestExecEntryPointsRejectInvalidControls|TestRunExecWithAppliesPolicyAndReplacesProcess|TestRunExecWithRefusesIncompleteControlsAndEnforcement|TestRunExecWithReportsExecFailureAfterEnforcement)$'

go test -race -count=1 -timeout=5m ./internal/sandbox \
  -run '^(TestIntegration_GuardHostileConformance|TestIntegration_InitChildrenRejectMalformedLaunchState|TestReadGuardExecutionProofRejectsExecFailureAndTrailingSuccess|TestDeveloperEnvironmentCodecFailsClosed|TestDeveloperEnvironmentControlDescriptorFailsClosed|TestLaunchStandaloneRejectsInvalidGuardLaunchBeforeChildStart)$'

go test -race -count=1 -timeout=5m ./internal/cli/runtime \
  -run '^(TestLaunchGuardRejectsMalformedChildProof|TestLaunchGuardFailureDoesNotEmitEnforcementEvidence|TestValidateGuardRuntimeFailsClosed|TestGuardEvidenceRecordsPreExecApplicationWithoutClaimingCommandStart|TestGuardEvidenceActivationHandlesUnhealthyEmitter)$'

go test -race -count=1 -timeout=5m ./internal/destination ./internal/scanner ./internal/proxy \
  -run '^(TestNewGrant_|TestGrantSet_|TestGuard)'

echo "PASS: Guard hostile-input conformance gate held"
