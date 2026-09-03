// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestResolveBestEffortOverrideRejectsMixedProvenance(t *testing.T) {
	for _, tt := range []struct {
		name                                   string
		cliEnabled, cliReasonSet, cliExpirySet bool
		configEnabled                          bool
	}{
		{name: "command line override with configuration expiry", cliEnabled: true, cliReasonSet: true},
		{name: "command line override with configuration reason", cliEnabled: true, cliExpirySet: true},
		{name: "configuration override with command line reason", cliReasonSet: true, configEnabled: true},
		{name: "configuration override with command line expiry", cliExpirySet: true, configEnabled: true},
		{name: "both sources fully populated", cliEnabled: true, cliReasonSet: true, cliExpirySet: true, configEnabled: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, _, _, err := resolveBestEffortOverride(
				tt.cliEnabled,
				"command line reason",
				"1h",
				tt.cliReasonSet,
				tt.cliExpirySet,
				tt.configEnabled,
				"configuration reason",
				"2h",
			)
			if err == nil || !strings.Contains(err.Error(), "command-line") || !strings.Contains(err.Error(), "configuration") {
				t.Fatalf("resolveBestEffortOverride() error = %v, want command-line/configuration refusal", err)
			}
		})
	}
}

func TestResolveBestEffortOverrideKeepsOneSource(t *testing.T) {
	for _, tt := range []struct {
		name                                   string
		cliEnabled, cliReasonSet, cliExpirySet bool
		configEnabled                          bool
		wantReason, wantExpiry                 string
	}{
		{name: "command line", cliEnabled: true, cliReasonSet: true, cliExpirySet: true, wantReason: "command line reason", wantExpiry: "1h"},
		{name: "configuration", configEnabled: true, wantReason: "configuration reason", wantExpiry: "2h"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			enabled, reason, expiry, err := resolveBestEffortOverride(
				tt.cliEnabled,
				"command line reason",
				"1h",
				tt.cliReasonSet,
				tt.cliExpirySet,
				tt.configEnabled,
				"configuration reason",
				"2h",
			)
			if err != nil || !enabled || reason != tt.wantReason || expiry != tt.wantExpiry {
				t.Fatalf("resolveBestEffortOverride() = %t, %q, %q, %v; want enabled %q, %q", enabled, reason, expiry, err, tt.wantReason, tt.wantExpiry)
			}
		})
	}
}

func TestResolveBestEffortOverrideRejectsMetadataWithoutOverride(t *testing.T) {
	_, _, _, err := resolveBestEffortOverride(
		false,
		"command line reason",
		"1h",
		true,
		true,
		false,
		"",
		"",
	)
	if err == nil || !strings.Contains(err.Error(), "require a best-effort override") {
		t.Fatalf("resolveBestEffortOverride() error = %v, want orphaned metadata refusal", err)
	}
}

func TestReportBestEffortAdmission(t *testing.T) {
	var buf bytes.Buffer
	reportBestEffortAdmission(&buf)
	for _, want := range []string{"admission only", "does not stop a running child", "every later launch requires re-authorization"} {
		if !strings.Contains(buf.String(), want) {
			t.Fatalf("admission output = %q, want %q", buf.String(), want)
		}
	}
}

func TestBestEffortExpiryFlagHelpDescribesAdmission(t *testing.T) {
	for _, tt := range []struct {
		name  string
		usage string
	}{
		{name: "standalone", usage: SandboxCmd().Flags().Lookup("best-effort-expiry").Usage},
		{name: "mcp", usage: mcpProxyCmd().Flags().Lookup("sandbox-best-effort-expiry").Usage},
	} {
		t.Run(tt.name, func(t *testing.T) {
			for _, want := range []string{"admission-time", "does not stop a running child", "later launches require re-authorization"} {
				if !strings.Contains(tt.usage, want) {
					t.Fatalf("expiry flag help = %q, want %q", tt.usage, want)
				}
			}
		})
	}
}

func TestAnchorBestEffortExpiryAnchorsDurationsOnce(t *testing.T) {
	before := time.Now()
	got, err := anchorBestEffortExpiry("test override", "1h")
	if err != nil {
		t.Fatalf("anchorBestEffortExpiry(duration): %v", err)
	}
	at, err := time.Parse(time.RFC3339Nano, got)
	if err != nil {
		t.Fatalf("anchored expiry %q is not RFC3339: %v", got, err)
	}
	if at.Before(before.Add(59*time.Minute)) || at.After(time.Now().Add(61*time.Minute)) {
		t.Fatalf("anchored expiry %s is not about one hour from validation", at)
	}

	absolute := time.Now().Add(30 * time.Minute).UTC().Truncate(time.Second)
	got, err = anchorBestEffortExpiry("test override", absolute.Format(time.RFC3339))
	if err != nil {
		t.Fatalf("anchorBestEffortExpiry(absolute): %v", err)
	}
	if at, _ := time.Parse(time.RFC3339Nano, got); !at.Equal(absolute) {
		t.Fatalf("absolute expiry changed: got %s, want %s", at, absolute)
	}

	if _, err := anchorBestEffortExpiry("test override", "0s"); err == nil {
		t.Fatal("expired duration must be refused at anchoring")
	}
}
