// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import "github.com/luckyPipewrench/pipelock/internal/mcp/transport"

// serverIdentityMessageWriter checks again at the output boundary. A reload
// may occur during scanning or a wait for operator approval, after the
// per-message admission check has passed.
type serverIdentityMessageWriter struct {
	writer transport.MessageWriter
	opts   MCPProxyOpts
}

func (w *serverIdentityMessageWriter) WriteMessage(msg []byte) error {
	if err := w.opts.checkServerIdentity(); err != nil {
		return err
	}
	return w.writer.WriteMessage(msg)
}
