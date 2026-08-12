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

if [[ "$(go env GOOS)" != "linux" ]]; then
  echo "FAIL: Guard hostile-input conformance requires Linux" >&2
  exit 1
fi

# `go test -run` exits successfully when its pattern matches no test. Pin every
# exact-name contract and require each prefix-based package group to be nonempty
# before running the race-enabled gate.
require_tests() {
  local package="$1"
  shift
  local listed
  listed="$(go test -list '.*' "$package")"
  local name
  for name in "$@"; do
    if ! grep -Fqx -- "$name" <<<"$listed"; then
      echo "FAIL: $package no longer defines $name" >&2
      exit 1
    fi
  done
}

require_pattern() {
  local package="$1"
  local pattern="$2"
  local listed
  listed="$(go test -list "$pattern" "$package")"
  if ! grep -Eq -- "$pattern" <<<"$listed"; then
    echo "FAIL: $package has no tests matching $pattern" >&2
    exit 1
  fi
}

require_tests ./internal/guard \
  TestExecutionProofBindsEffectiveInvocation \
  TestReadExecEnvironmentOwnsInheritedDescriptor \
  TestOpenExecStatusWriterValidatesAndOwnsDescriptor \
  TestReadExecEnvironmentRoundTripAndClose \
  TestReadExecEnvironmentRejectsDuplicateKeys \
  TestDecodeExecEnvironmentRejectsMalformedAndOversizedPayloads \
  TestExecEntryPointsRejectInvalidControls \
  TestRunExecWithAppliesPolicyAndReplacesProcess \
  TestRunExecWithRefusesIncompleteControlsAndEnforcement \
  TestRunExecWithReportsExecFailureAfterEnforcement

require_tests ./internal/sandbox \
  TestIntegration_GuardHostileConformance \
  TestIntegration_InitChildrenRejectMalformedLaunchState \
  TestReadGuardExecutionProofRejectsExecFailureAndTrailingSuccess \
  TestDeveloperEnvironmentCodecFailsClosed \
  TestDeveloperEnvironmentControlDescriptorFailsClosed \
  TestLaunchStandaloneRejectsInvalidGuardLaunchBeforeChildStart

require_tests ./internal/cli/runtime \
  TestLaunchGuardRejectsMalformedChildProof \
  TestLaunchGuardFailureDoesNotEmitEnforcementEvidence \
  TestValidateGuardRuntimeFailsClosed \
  TestGuardEvidenceRecordsPreExecApplicationWithoutClaimingCommandStart \
  TestGuardEvidenceActivationHandlesUnhealthyEmitter

group_pattern='^(TestNewGrant_|TestGrantSet_|TestGuard)'
require_pattern ./internal/destination "$group_pattern"
require_pattern ./internal/scanner "$group_pattern"
require_pattern ./internal/proxy "$group_pattern"

go test -race -count=1 -timeout=5m ./internal/guard \
  -run '^(TestExecutionProofBindsEffectiveInvocation|TestReadExecEnvironmentOwnsInheritedDescriptor|TestOpenExecStatusWriterValidatesAndOwnsDescriptor|TestReadExecEnvironmentRoundTripAndClose|TestReadExecEnvironmentRejectsDuplicateKeys|TestDecodeExecEnvironmentRejectsMalformedAndOversizedPayloads|TestExecEntryPointsRejectInvalidControls|TestRunExecWithAppliesPolicyAndReplacesProcess|TestRunExecWithRefusesIncompleteControlsAndEnforcement|TestRunExecWithReportsExecFailureAfterEnforcement)$'

go test -race -count=1 -timeout=5m ./internal/sandbox \
  -run '^(TestIntegration_GuardHostileConformance|TestIntegration_InitChildrenRejectMalformedLaunchState|TestReadGuardExecutionProofRejectsExecFailureAndTrailingSuccess|TestDeveloperEnvironmentCodecFailsClosed|TestDeveloperEnvironmentControlDescriptorFailsClosed|TestLaunchStandaloneRejectsInvalidGuardLaunchBeforeChildStart)$'

go test -race -count=1 -timeout=5m ./internal/cli/runtime \
  -run '^(TestLaunchGuardRejectsMalformedChildProof|TestLaunchGuardFailureDoesNotEmitEnforcementEvidence|TestValidateGuardRuntimeFailsClosed|TestGuardEvidenceRecordsPreExecApplicationWithoutClaimingCommandStart|TestGuardEvidenceActivationHandlesUnhealthyEmitter)$'

go test -race -count=1 -timeout=5m ./internal/destination ./internal/scanner ./internal/proxy \
  -run '^(TestNewGrant_|TestGrantSet_|TestGuard)'

echo "PASS: Guard hostile-input conformance gate held"
