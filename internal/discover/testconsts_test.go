// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package discover

// Test-shared string constants. Extracted to satisfy goconst on the
// discover test suite and keep fixture data consistent across files.
const (
	testHTTPMCPURL          = "https://api.example.com/mcp"
	testServerFilesystemPkg = "@modelcontextprotocol/server-filesystem"
	testCmdNpx              = "npx"
	testCmdNode             = "node"
	testDataDir             = "/data"
	testServerJS            = "server.js"
)
