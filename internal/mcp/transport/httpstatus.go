// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"unicode/utf8"

	"github.com/luckyPipewrench/pipelock/internal/responseencoding"
)

// MaxClientErrorBodySize bounds how much of an upstream 4xx reply is read for
// relaying. A refusal carries a short explanation, not a payload; a larger body
// is not relayed at all rather than relayed in part.
const MaxClientErrorBodySize = 64 << 10

// ErrClientErrorNotRelayable reports a 4xx reply whose body cannot be relayed
// faithfully: too large, in an encoding that cannot be decoded, or not UTF-8
// text the response scanner reads the same way the client will.
var ErrClientErrorNotRelayable = errors.New("upstream error reply cannot be relayed")

// AcceptedWithoutBody reports whether resp is a successful reply that carries
// no JSON-RPC message, which is how an MCP server acknowledges a notification
// or a client response. The specification asks for 202 Accepted, but servers
// also answer 204 No Content, and both mean the input was taken. 205 never has
// content either. Any other non-200 2xx counts only when it declares an empty
// body: a reply of unknown length may carry content, and content on a status
// the transport does not expect is refused rather than ignored.
func AcceptedWithoutBody(resp *http.Response) bool {
	switch resp.StatusCode {
	case http.StatusAccepted, http.StatusNoContent, http.StatusResetContent:
		return true
	case http.StatusOK:
		// 200 is the message-carrying status; its own path handles an empty one.
		return false
	}
	return resp.StatusCode >= 200 && resp.StatusCode < 300 && resp.ContentLength == 0
}

// ExpectsReply reports whether msg is a JSON-RPC request: a method and a
// non-null ID, so the sender is owed a result or an error. An empty
// acknowledgment answers a notification or a client response; for a request it
// would report success while the answer never arrives. The original 202 for
// requests is kept for servers that answer on the GET stream.
func ExpectsReply(msg []byte) bool {
	var fields map[string]json.RawMessage
	if json.Unmarshal(msg, &fields) != nil {
		return false
	}
	id := fields["id"]
	return fields["method"] != nil && len(id) != 0 && string(id) != "null"
}

// IsClientError reports a 4xx status: the upstream refused this request, as
// opposed to failing (5xx) or redirecting (3xx). A refusal is the upstream's
// answer and belongs to the client; a failure is the gateway's problem.
func IsClientError(status int) bool {
	return status >= 400 && status < 500
}

// ReadClientErrorBody reads a 4xx reply's body so it can be scanned and relayed.
// A supported Content-Encoding is decoded first, because the scanner has to see
// the text the client will read. Anything that cannot be read in full and as
// UTF-8 returns ErrClientErrorNotRelayable, so the caller falls back to its
// sanitized error instead of relaying something it could not inspect.
func ReadClientErrorBody(resp *http.Response) ([]byte, error) {
	if resp.Body == nil {
		return nil, nil
	}
	if responseencoding.HasNonIdentityContentEncoding(resp.Header) {
		if err := responseencoding.DecodeResponse(resp); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrClientErrorNotRelayable, err)
		}
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxClientErrorBodySize+1))
	if err != nil {
		// A broken read is an incomplete response, the same as a 200 body
		// that fails mid-read, not a property of the refusal.
		return nil, fmt.Errorf("%w: %w: reading body: %w", ErrClientErrorNotRelayable, ErrIncompleteResponse, err)
	}
	if len(body) > MaxClientErrorBodySize {
		return nil, fmt.Errorf("%w: body exceeds %d bytes", ErrClientErrorNotRelayable, MaxClientErrorBodySize)
	}
	if !utf8.Valid(body) {
		return nil, fmt.Errorf("%w: body is not UTF-8 text", ErrClientErrorNotRelayable)
	}
	return body, nil
}
