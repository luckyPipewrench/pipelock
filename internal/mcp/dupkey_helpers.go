// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"errors"

	"github.com/luckyPipewrench/pipelock/internal/redact"
)

// isDuplicateKeyBlock reports whether err is the specific
// redact.NoDuplicateJSONKeys outcome for an actual duplicate object
// member name. Generic malformed-JSON failures from the same call also
// surface as *redact.BlockError with ReasonBodyUnparseable; those should
// fall through to the caller's existing parse-error handling so logs
// and metrics stay attributed to the JSON-parse cause rather than to
// duplicate-key blocking.
func isDuplicateKeyBlock(err error) bool {
	var be *redact.BlockError
	if !errors.As(err, &be) {
		return false
	}
	return be.Reason == redact.ReasonDuplicateKey
}
