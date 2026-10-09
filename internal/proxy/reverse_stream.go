// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"errors"
	"io"
	"net/http"

	"github.com/luckyPipewrench/pipelock/internal/mcp"
)

// reverseStreamBody observes read failures without replacing them: the stdlib
// reverse proxy must receive the error to abort the downstream HTTP stream.
type reverseStreamBody struct {
	io.ReadCloser
	resp *http.Response
	rp   *ReverseProxyHandler
	read int64
}

func (b *reverseStreamBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	b.read += int64(n)
	// SSE findings, incomplete scans, and required-receipt failures already
	// recorded their own outcome before closing the stream pipe.
	if err != nil && !errors.Is(err, io.EOF) && !IsSSEStreamFinding(err) && !IsSSEStreamScanError(err) && !errors.Is(err, mcp.ErrReceiptRequired) {
		r := b.resp.Request
		actx := newHTTPAuditContext(r.Context(), b.rp.logger, httpAuditEvent{
			Method: r.Method, TargetURL: r.URL.String(), ClientIP: reverseClientIP(r), Agent: reverseCaptureAgent(r),
		})
		reason := recordStreamError(r.Context(), b.rp.logger, actx, err)
		reverseOutcomeFromContext(r.Context()).Record(b.resp.StatusCode, b.read, reason)
	}
	return n, err
}
