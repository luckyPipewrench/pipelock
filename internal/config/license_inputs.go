// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package config

import "bytes"

// SameLicenseInputs compares the materialized inputs used to establish an
// entitlement. Runtime claims and unrelated policy settings are not inputs.
func SameLicenseInputs(a, b *Config) bool {
	return a != nil && b != nil &&
		a.LicenseKey == b.LicenseKey &&
		a.LicenseFile == b.LicenseFile &&
		a.LicensePublicKey == b.LicensePublicKey &&
		a.LicenseCRLFile == b.LicenseCRLFile &&
		a.LicenseIntermediateFile == b.LicenseIntermediateFile &&
		bytes.Equal(a.LicenseIntermediateCert, b.LicenseIntermediateCert) &&
		a.LicenseIntermediateLoadError == b.LicenseIntermediateLoadError &&
		a.LicenseRequireIntermediateResolved == b.LicenseRequireIntermediateResolved &&
		a.LicenseCRLMaxAgeResolved == b.LicenseCRLMaxAgeResolved
}
