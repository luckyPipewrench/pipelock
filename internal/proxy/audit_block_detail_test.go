// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestAuditDetailFromResult_MapsDNSInfrastructureError(t *testing.T) {
	t.Parallel()

	got := auditDetailFromResult(scanner.Result{
		Class:        scanner.ClassInfrastructureError,
		DNSErrorKind: scanner.DNSErrorTimeout,
	})

	if got.Class != audit.BlockClassInfrastructureError {
		t.Fatalf("Class = %q, want %q", got.Class, audit.BlockClassInfrastructureError)
	}
	if got.DNSErrorKind != string(scanner.DNSErrorTimeout) {
		t.Fatalf("DNSErrorKind = %q, want %q", got.DNSErrorKind, scanner.DNSErrorTimeout)
	}
}

func TestAuditDetailFromResult_ThreatKeepsLegacyZeroClass(t *testing.T) {
	t.Parallel()

	got := auditDetailFromResult(scanner.Result{Class: scanner.ClassThreat})

	if got.Class != "" {
		t.Fatalf("Class = %q, want empty legacy threat class", got.Class)
	}
	if got.DNSErrorKind != "" {
		t.Fatalf("DNSErrorKind = %q, want empty", got.DNSErrorKind)
	}
}

func TestAuditDetailFromResult_MapsNonThreatClasses(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		class     scanner.ResultClass
		wantClass string
	}{
		{"protective", scanner.ClassProtective, audit.BlockClassProtective},
		{"config mismatch", scanner.ClassConfigMismatch, audit.BlockClassConfigMismatch},
		{"structural exemption", scanner.ClassStructuralExemption, audit.BlockClassStructuralExemption},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := auditDetailFromResult(scanner.Result{Class: tc.class})
			if got.Class != tc.wantClass {
				t.Fatalf("Class = %q, want %q", got.Class, tc.wantClass)
			}
		})
	}
}
