// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package capture

// Test-shared constants for internal capture tests (package capture).
// External capture_test tests have their own block in writer_test.go.
const (
	testCIDRLoopback  = "127.0.0.0/8"
	testCIDRIPv6      = "::1/128"
	testSubsurface    = "forward"
	testHTTPDestRule  = "http_destination"
	testRepoBarURL    = "https://api.example.com/repos/bar"
	testRuleNamerRf   = "Block rm -rf"
	testAPIExampleCom = "api.example.com"
	testJSONKeyPaths  = "paths"
	testJSONKeyHost   = "host"
	testJSONKeyValue  = "value"
	testConfidenceOne = "1.0"
)
