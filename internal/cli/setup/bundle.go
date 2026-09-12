// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"fmt"
	"io"

	"github.com/luckyPipewrench/pipelock/internal/rules"
)

func reportBundleLoadResult(stderr io.Writer, result *rules.LoadResult) {
	for _, e := range result.Errors {
		_, _ = fmt.Fprintf(stderr, "pipelock: warning: bundle %s: %s\n", e.Name, e.Reason)
	}
	for _, w := range result.Warnings {
		_, _ = fmt.Fprintf(stderr, "pipelock: warning: %s\n", w)
	}
}
