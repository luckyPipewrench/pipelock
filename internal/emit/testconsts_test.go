// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package emit

// Test-shared constants for the emit test suite.
const (
	testStr                 = "test"
	testHostName            = "test-host"
	testEvilURL             = "https://evil.com"
	testBlocklistRsn        = "blocklist"
	testFieldReason         = "reason"
	testSyslogAddr514       = "syslog.example.com:514"
	testFieldURL            = "url"
	testInstanceName        = "test-instance"
	testActionStrip         = "strip"
	testCaseUnknownInfo     = "unknown defaults to info"
	testCaseBlockIsCritical = "block is critical"
	testCaseWarnIsWarn      = "warn is warn"
	testCaseEmptyIsWarn     = "empty is warn"
)
