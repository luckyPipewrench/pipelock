// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package aarp

import (
	"reflect"
	"testing"
)

// TestComputeOverclaimRisks exercises the risk computation directly: each risk
// fires only when its trigger claim is present and the stronger sibling axis is
// absent, and the output is sorted and de-duplicated. This is the unit-level gate
// that no claim ever ships without its paired "do not over-read this" warning.
func TestComputeOverclaimRisks(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		verified []struct{ claim, axis string }
		want     []string
	}{
		{
			name: "signature only triggers transparency risk",
			verified: []struct{ claim, axis string }{
				{ClaimReceiptSignatureValid, AxisIntegrity},
			},
			want: []string{RiskSignatureValidNotTransparency},
		},
		{
			name: "chain link present triggers contiguity risk",
			verified: []struct{ claim, axis string }{
				{ClaimReceiptSignatureValid, AxisIntegrity},
				{ClaimReceiptTimestampMonotonicChainPresent, AxisIntegrity},
			},
			want: []string{
				RiskChainLinkNotContiguousChain,
				RiskSignatureValidNotTransparency,
			},
		},
		{
			name: "svid bound triggers deployment risk",
			verified: []struct{ claim, axis string }{
				{ClaimReceiptSignatureValid, AxisIntegrity},
				{ClaimSigningWorkloadSVIDBound, AxisIdentity},
			},
			want: []string{
				RiskSignatureValidNotTransparency,
				RiskSVIDIdentityNotDeploymentNonBypass,
			},
		},
		{
			name: "transparency axis populated suppresses transparency risk",
			verified: []struct{ claim, axis string }{
				{ClaimReceiptSignatureValid, AxisIntegrity},
				// A future external-witness claim on the transparency axis must
				// auto-suppress the "not transparency" warning.
				{"external_witness_checkpoint_signature_valid", AxisTransparency},
			},
			want: nil,
		},
		{
			name: "deployment axis populated suppresses svid deployment risk",
			verified: []struct{ claim, axis string }{
				{ClaimSigningWorkloadSVIDBound, AxisIdentity},
				{"k8s_pod_spec_proxy_injection_observed", AxisDeployment},
			},
			want: nil,
		},
		{
			name: "authority axis populated suppresses chain continuity risk",
			verified: []struct{ claim, axis string }{
				{ClaimReceiptTimestampMonotonicChainPresent, AxisIntegrity},
				// A future stream-level proof lands on the authority axis.
				{"receipt_timestamp_contiguous_chain_verified", AxisAuthority},
			},
			want: nil,
		},
		{
			name:     "no verified claims yields no risks",
			verified: nil,
			want:     nil,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ap := newAppraisal()
			for _, v := range tc.verified {
				ap.addVerified(v.claim, v.axis)
			}
			got := ap.computeOverclaimRisks()
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("computeOverclaimRisks = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestAxesWithVerifiedClaims confirms the assurance descriptor is the sorted set
// of axes that actually hold a verified claim, and that an axis whose slice was
// created but left empty is not reported as covered.
func TestAxesWithVerifiedClaims(t *testing.T) {
	t.Parallel()
	ap := newAppraisal()
	ap.addVerified(ClaimReceiptSignatureValid, AxisIntegrity)
	ap.addVerified(ClaimMediatorKeyPinned, AxisIdentity)
	ap.addVerified(ClaimReceiptTimestampMonotonicChainPresent, AxisIntegrity)
	// An axis key with an empty slice must not count as covered.
	ap.Axes[AxisDeployment] = []string{}

	got := ap.axesWithVerifiedClaims()
	want := []string{AxisIdentity, AxisIntegrity}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("axesWithVerifiedClaims = %v, want %v", got, want)
	}
}

// TestAddDoesNotAssertDedup proves a paired negative is appended once even when
// added twice, and that the fixed general list is preserved.
func TestAddDoesNotAssertDedup(t *testing.T) {
	t.Parallel()
	ap := newAppraisal()
	base := len(ap.DoesNotAssert)
	ap.addDoesNotAssert(DNAssertNetworkNonBypassFromIdentity)
	ap.addDoesNotAssert(DNAssertNetworkNonBypassFromIdentity) // duplicate, must be a no-op
	ap.addDoesNotAssert(DNAssertDeploymentEnforcementFromIdentity)

	if got := len(ap.DoesNotAssert); got != base+2 {
		t.Fatalf("does_not_assert length = %d, want %d", got, base+2)
	}
	if c := countOccurrences(ap.DoesNotAssert, DNAssertNetworkNonBypassFromIdentity); c != 1 {
		t.Fatalf("paired negative appears %d times, want 1", c)
	}
	// A general-list entry that pre-existed must still be present exactly once.
	if !containsString(ap.DoesNotAssert, "complete_mediation") {
		t.Fatal("fixed does_not_assert entry was dropped")
	}
}

// TestFinalizeIsIdempotent confirms running finalize twice yields the same
// derived outputs (it never accumulates duplicate risks across calls).
func TestFinalizeIsIdempotent(t *testing.T) {
	t.Parallel()
	ap := newAppraisal()
	ap.addVerified(ClaimReceiptSignatureValid, AxisIntegrity)
	ap.addVerified(ClaimSigningWorkloadSVIDBound, AxisIdentity)
	ap.finalize()
	first := append([]string(nil), ap.OverclaimRisks...)
	firstAxes := append([]string(nil), ap.Assurance.AxesWithVerifiedClaims...)
	ap.finalize()
	if !reflect.DeepEqual(ap.OverclaimRisks, first) {
		t.Fatalf("overclaim risks not idempotent: %v vs %v", ap.OverclaimRisks, first)
	}
	if !reflect.DeepEqual(ap.Assurance.AxesWithVerifiedClaims, firstAxes) {
		t.Fatalf("assurance axes not idempotent: %v vs %v", ap.Assurance.AxesWithVerifiedClaims, firstAxes)
	}
}

func countOccurrences(xs []string, s string) int {
	n := 0
	for _, x := range xs {
		if x == s {
			n++
		}
	}
	return n
}
