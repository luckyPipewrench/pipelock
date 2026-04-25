// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"errors"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/redact"
)

// hasNonIdentityEncoding reports whether the Content-Encoding header carries
// any encoding other than "identity" (which means no encoding). Mirrors the
// helper in internal/proxy/bodyscan.go; duplicated here to avoid pulling the
// proxy package into mcp callers.
func hasNonIdentityEncoding(ce string) bool {
	if ce == "" {
		return false
	}
	for _, enc := range strings.Split(ce, ",") {
		enc = strings.TrimSpace(strings.ToLower(enc))
		if enc != "" && enc != "identity" {
			return true
		}
	}
	return false
}

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
