// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package contain implements the `pipelock contain` family of subcommands
// for workstation-tier containment.
//
// In v0.1 only `verify` is implemented; the four mutating subcommands
// (install, rollback, add-tool, ca-refresh) are registered as stubs and
// return a "not yet implemented" error.
package contain
