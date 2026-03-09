//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

// Package entcli provides enterprise CLI commands (license management).
// The init function registers these commands with the core CLI via the
// RegisterCommand hook.
package entcli

import "github.com/luckyPipewrench/pipelock/internal/cli"

func init() {
	cli.RegisterCommand(LicenseCmd())
}
