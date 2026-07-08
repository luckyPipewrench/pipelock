// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
)

func recordResponseScanExemptOverCapUnscanned(m *metrics.Metrics, logger *audit.Logger, actx audit.LogContext, host, transport string, bytesWritten, scanCapBytes int64) {
	if scanCapBytes <= 0 || bytesWritten <= scanCapBytes {
		return
	}
	// Metric is bounded to transport only (host would be unbounded cardinality
	// under exempt_domains wildcards); the audit log carries the hostname.
	m.RecordResponseScanExemptOverCapUnscanned(transport)
	if logger != nil {
		labelHost := strings.ToLower(strings.TrimSpace(host))
		if labelHost == "" {
			labelHost = "_unknown"
		}
		logger.LogResponseScanExemptOverCapUnscanned(actx, labelHost, transport, bytesWritten, scanCapBytes)
	}
}
