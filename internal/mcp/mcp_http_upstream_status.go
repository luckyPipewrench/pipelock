// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"encoding/json"
	"mime"
	"net/http"
	"strings"
	"unicode/utf8"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/decide"
	"github.com/luckyPipewrench/pipelock/internal/jsonscan"

	"github.com/luckyPipewrench/pipelock/internal/mcp/jsonrpc"
	"github.com/luckyPipewrench/pipelock/internal/mcp/transport"
)

// relayedUpstreamErrorHeaders are the upstream headers a relayed 4xx keeps.
// They are what a client needs to act on the refusal: the authorization
// challenge that starts OAuth discovery and token refresh, the methods a 405
// permits, when a 429 may retry, and how to read the body. Session, cookie and
// caching headers stay behind; a refusal establishes no state.
var relayedUpstreamErrorHeaders = [...]string{"Content-Type", "WWW-Authenticate", "Allow", "Retry-After"}

// upstreamClientError is an upstream 4xx reply held for scanning and relay.
type upstreamClientError struct {
	status int
	header http.Header
	body   []byte
}

// validateFraming prevents a refusal from becoming an alternate MCP message
// transport. Only a correlated error may carry a JSON-RPC envelope; results,
// server requests and SSE need the full message pipeline, not an error wrapper.
// A declared charset must agree with the UTF-8 bytes the scanner inspected.
func (e upstreamClientError) validateFraming(id json.RawMessage) bool {
	for _, values := range e.header {
		for _, value := range values {
			if !utf8.ValidString(value) || strings.ContainsAny(value, "\r\n\x00") {
				return false
			}
		}
	}
	contentTypes := e.header.Values("Content-Type")
	if len(contentTypes) > 1 {
		return false
	}
	mediaType := ""
	if len(contentTypes) == 1 {
		var params map[string]string
		var err error
		mediaType, params, err = mime.ParseMediaType(contentTypes[0])
		if err != nil || mediaType == "text/event-stream" {
			return false
		}
		if charset := params["charset"]; charset != "" && !strings.EqualFold(charset, "utf-8") {
			return false
		}
	}
	body := bytes.TrimSpace(e.body)
	if len(body) == 0 {
		return true
	}
	if body[0] == '[' {
		return false // MCP does not support batch messages.
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(body, &fields) != nil {
		return mediaType != "application/json"
	}
	if jsonscan.RejectDuplicateKeys(body) != nil {
		return false
	}
	for _, name := range []string{"jsonrpc", "id", "method", "result", "params"} {
		for key := range fields {
			if strings.EqualFold(key, name) {
				return transport.IsClientErrorReply(body, id)
			}
		}
	}
	return true // Ordinary HTTP/OAuth errors have no MCP message envelope.
}

// readUpstreamClientError captures a 4xx reply. The body is bounded, decoded
// and required to be UTF-8 by transport.ReadClientErrorBody.
func readUpstreamClientError(resp *http.Response) (upstreamClientError, error) {
	body, err := transport.ReadClientErrorBody(resp)
	if err != nil {
		return upstreamClientError{}, err
	}
	header := make(http.Header)
	for _, name := range relayedUpstreamErrorHeaders {
		for _, value := range resp.Header.Values(name) {
			header.Add(name, value)
		}
	}
	return upstreamClientError{status: resp.StatusCode, header: header, body: body}, nil
}

// scanEnvelope frames the relayed header values and body as one JSON-RPC
// error so the ordinary response scanner inspects them. A JSON body is
// embedded as JSON, so escaped text is decoded before matching and duplicate
// keys or excessive depth refuse the scan; any other body is embedded as a
// string. The header values join the message, since a client acts on them.
func (e upstreamClientError) scanEnvelope() []byte {
	var headerText strings.Builder
	for _, name := range relayedUpstreamErrorHeaders {
		for _, value := range e.header.Values(name) {
			headerText.WriteString(value)
			headerText.WriteByte('\n')
		}
	}
	data := json.RawMessage(bytes.TrimSpace(e.body))
	if len(data) == 0 || !json.Valid(data) {
		data, _ = json.Marshal(string(e.body)) //nolint:errcheck // a string always marshals
	}
	envelope, _ := json.Marshal(rpcError{ //nolint:errcheck // known-good struct around valid JSON
		JSONRPC: jsonrpc.Version,
		ID:      json.RawMessage(jsonrpc.Null),
		Error: rpcErrorDetail{
			Code:    -32003,
			Message: headerText.String(),
			Data:    data,
		},
	})
	return envelope
}

// scan reports whether the reply may be relayed. Only a clean verdict relays:
// an error body is not a tool result, so there is nothing for warn, strip or
// ask to preserve, and any finding falls back to the sanitized gateway error
// the listener returned for every 4xx before relaying existed.
func (e upstreamClientError) scan(opts MCPProxyOpts) (bool, string) {
	sc := opts.scanner()
	if sc == nil {
		return false, "response scanner unavailable"
	}
	verdict := ScanResponseOpts(e.scanEnvelope(), sc, opts.responseScanOptions())
	if verdict.Clean && verdict.Error == "" {
		return true, ""
	}
	return false, upstreamClientErrorFinding(verdict)
}

// upstreamClientErrorFinding names why a reply was withheld without echoing
// the reply: matched text could be the secret or the payload itself.
func upstreamClientErrorFinding(verdict jsonrpc.ScanVerdict) string {
	switch {
	case len(verdict.Matches) > 0:
		return "injection pattern " + verdict.Matches[0].PatternName
	case len(verdict.DLPMatches) > 0:
		return "DLP pattern " + verdict.DLPMatches[0].PatternName
	case verdict.Error != "":
		return "uninspectable reply"
	default:
		return "response scan finding"
	}
}

// write relays the reply with its status, kept headers and body.
func (e upstreamClientError) write(w http.ResponseWriter) {
	for name, values := range e.header {
		for _, value := range values {
			w.Header().Add(name, value)
		}
	}
	if len(e.body) > 0 && w.Header().Get("Content-Type") == "" {
		// Without a declared type the server would sniff one from the body.
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	}
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(e.status)
	_, _ = w.Write(e.body)
}

// writeIfActive makes the final refusal write share the listener's revocation
// boundary. Reading and scanning can take time; check live response gates after
// both and before committing any upstream header or byte.
func (e upstreamClientError) writeIfActive(w http.ResponseWriter, state *mcpListenerClientState, opts MCPProxyOpts) (bool, string) {
	reason := ""
	if !state.commitIfActive(func() {
		if opts.checkServerIdentity() != nil {
			reason = "upstream identity changed"
			return
		}
		if opts.KillSwitch != nil && opts.KillSwitch.IsActiveMCP(nil).Active {
			reason = "kill switch blocks responses"
			return
		}
		if opts.Rec != nil && decide.UpgradeAction("", opts.Rec.EscalationLevel(), opts.adaptiveCfg()) == config.ActionBlock {
			reason = "session escalation blocks responses"
			return
		}
		withListenerWriteDeadline(w, listenerDownstreamWriteTimeout, func() { e.write(w) })
	}) {
		return false, "listener state revoked"
	}
	return reason == "", reason
}
