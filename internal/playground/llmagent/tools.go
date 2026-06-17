// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package llmagent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// Lab tool names. fetch_url reads; post_data sends. The model picks; Pipelock
// mediates whatever destination it picks.
const (
	ToolFetchURL = "fetch_url"
	ToolPostData = "post_data"
)

// maxToolBodyBytes caps how much of a tool response is read back into the model
// context. A lab target is untrusted; an unbounded body would bloat context and
// be a memory vector.
const maxToolBodyBytes = 8 << 10 // 8 KiB

// fetchArgs / postArgs are the tool argument shapes the model fills in.
type fetchArgs struct {
	URL string `json:"url"`
}

type postArgs struct {
	URL  string `json:"url"`
	Data string `json:"data"`
}

var fetchParams = json.RawMessage(`{"type":"object","properties":{"url":{"type":"string","description":"The URL to GET."}},"required":["url"]}`)

var postParams = json.RawMessage(`{"type":"object","properties":{"url":{"type":"string","description":"The URL to POST to."},"data":{"type":"string","description":"The data to send in the request body."}},"required":["url","data"]}`)

// LabTools returns the fetch_url and post_data tools bound to client. Every tool
// request is issued through client (which routes through the Pipelock proxy) and
// carries reqHeaders (e.g. the agent-identity header) so the proxy attributes the
// receipt correctly. The returned tools never panic on malformed model
// arguments: they report the problem back to the model as the result string.
func LabTools(client *http.Client, reqHeaders map[string]string) []Tool {
	return []Tool{
		{
			Name:        ToolFetchURL,
			Description: "Fetch a URL with an HTTP GET and return the response.",
			Params:      fetchParams,
			Invoke: func(ctx context.Context, raw json.RawMessage) (string, Event) {
				var args fetchArgs
				if err := json.Unmarshal(raw, &args); err != nil || strings.TrimSpace(args.URL) == "" {
					return "error: fetch_url needs a \"url\" string argument", Event{
						Kind: EventToolResult, Tool: ToolFetchURL, Note: "bad arguments",
					}
				}
				return doRequest(ctx, client, reqHeaders, http.MethodGet, args.URL, nil)
			},
		},
		{
			Name:        ToolPostData,
			Description: "Send data to a URL with an HTTP POST.",
			Params:      postParams,
			Invoke: func(ctx context.Context, raw json.RawMessage) (string, Event) {
				var args postArgs
				if err := json.Unmarshal(raw, &args); err != nil || strings.TrimSpace(args.URL) == "" {
					return "error: post_data needs \"url\" and \"data\" string arguments", Event{
						Kind: EventToolResult, Tool: ToolPostData, Note: "bad arguments",
					}
				}
				return doRequest(ctx, client, reqHeaders, http.MethodPost, args.URL, []byte(args.Data))
			},
		},
	}
}

// doRequest issues one tool request through the proxy client and renders the
// outcome both for the model (result string) and the stream (Event). A blocked
// request comes back as an HTTP status (the proxy answers 4xx with a block
// reason), not a transport error; that status is exactly what the demo shows.
func doRequest(ctx context.Context, client *http.Client, headers map[string]string, method, rawURL string, body []byte) (string, Event) {
	ev := Event{Kind: EventToolResult, Method: method, URL: rawURL}

	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, rawURL, rdr)
	if err != nil {
		ev.Note = "invalid request"
		return fmt.Sprintf("error: could not build request: %v", err), ev
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	resp, err := client.Do(req)
	if err != nil {
		// In a contained run, a destination the kernel blocks (not via the proxy)
		// surfaces here as a transport error. Report it as the action being stopped.
		ev.Note = "request did not complete"
		return fmt.Sprintf("error: request to %s did not complete: %v", rawURL, err), ev
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, maxToolBodyBytes))
	ev.Status = resp.StatusCode
	if resp.StatusCode >= http.StatusBadRequest {
		ev.Note = "blocked"
	} else {
		ev.Note = "allowed"
	}
	return fmt.Sprintf("HTTP %d\n%s", resp.StatusCode, snippet(respBody)), ev
}
