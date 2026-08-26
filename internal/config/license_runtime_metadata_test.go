// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import "testing"

func TestCanonicalPolicyHash_ExcludesRuntimeLicenseWarningMetadata(t *testing.T) {
	base := Defaults()
	withLicenseMetadata := base.Clone()
	withLicenseMetadata.LicenseID = "lic_runtime"
	withLicenseMetadata.LicenseIssuedAt = 1_778_900_400
	withLicenseMetadata.LicenseExpiresAt = 1_782_788_400
	withLicenseMetadata.LicenseTier = "trial"

	view := withLicenseMetadata.policySemanticView().Config
	if view.LicenseID != "" || view.LicenseIssuedAt != 0 || view.LicenseExpiresAt != 0 || view.LicenseTier != "" {
		t.Fatalf("canonical view retained runtime license warning metadata: id=%q issued=%d expires=%d tier=%q", view.LicenseID, view.LicenseIssuedAt, view.LicenseExpiresAt, view.LicenseTier)
	}

	if got, want := withLicenseMetadata.CanonicalPolicyHash(), base.CanonicalPolicyHash(); got != want {
		t.Fatalf("runtime license metadata changed canonical policy hash: got %s want %s", got, want)
	}
}
