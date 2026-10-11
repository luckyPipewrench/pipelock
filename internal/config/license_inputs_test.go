// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"testing"
	"time"
)

func TestSameLicenseInputs(t *testing.T) {
	t.Parallel()
	base := Defaults()
	if SameLicenseInputs(nil, base) || SameLicenseInputs(base, nil) || SameLicenseInputs(nil, nil) {
		t.Fatal("unknown inputs compared equal")
	}
	for _, tc := range []struct {
		name   string
		change func(*Config)
	}{
		{"LicenseKey", func(c *Config) { c.LicenseKey = "changed" }},
		{"LicenseFile", func(c *Config) { c.LicenseFile = "changed" }},
		{"LicensePublicKey", func(c *Config) { c.LicensePublicKey = "changed" }},
		{"LicenseCRLFile", func(c *Config) { c.LicenseCRLFile = "changed" }},
		{"LicenseIntermediateFile", func(c *Config) { c.LicenseIntermediateFile = "changed" }},
		{"LicenseIntermediateCert", func(c *Config) { c.LicenseIntermediateCert = []byte("changed") }},
		{"LicenseIntermediateLoadError", func(c *Config) { c.LicenseIntermediateLoadError = "changed" }},
		{"LicenseRequireIntermediateResolved", func(c *Config) { c.LicenseRequireIntermediateResolved = !c.LicenseRequireIntermediateResolved }},
		{"LicenseCRLMaxAgeResolved", func(c *Config) { c.LicenseCRLMaxAgeResolved += time.Hour }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			next := base.Clone()
			if !SameLicenseInputs(base, next) {
				t.Fatal("clone inputs changed")
			}
			tc.change(next)
			if SameLicenseInputs(base, next) || SameLicenseInputs(next, base) {
				t.Fatal("changed input compared equal")
			}
		})
	}
	next := base.Clone()
	next.Logging.IncludeAllowed = !base.Logging.IncludeAllowed
	next.LicenseExpiresAt = 123
	if !SameLicenseInputs(base, next) {
		t.Fatal("runtime claims or unrelated policy changed input identity")
	}
}
