// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package llmagent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Lab tool names. fetch_url reads; post_data sends. The model picks; Pipelock
// mediates whatever destination it picks.
const (
	ToolFetchURL = "fetch_url"
	ToolPostData = "post_data"
	// CanaryEgressHeader marks a tool request whose body carried the lab secret
	// value. It is demo PROVENANCE metadata for the receipt/UI ("this request
	// carried the lab secret"); it is NOT a trusted control. The real DLP scan
	// runs independently of this header, and the header is set inside the agent's
	// own trust domain, so it must never be the sole basis for a block.
	CanaryEgressHeader = "X-Pipelock-Demo-Canary-Egress"
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

// ToolRuntimeConfig controls local lab-tool behavior that must stay outside the
// model API request path.
type ToolRuntimeConfig struct {
	// ScratchDir is the working directory for the shell/filesystem tools
	// (run_command, read_file relative paths, list_dir default). The deploy mints
	// this per session and wipes it on teardown.
	ScratchDir string
	// AllowExec requests the run_command shell tool. It is OFF by default, takes
	// effect only where the target can kill the command's whole process group,
	// and must only be set where the host enforces kernel containment. An
	// arbitrary shell's child processes egress through the host stack, not the
	// agent's proxy-only Go transport. See shellTools for the full rationale.
	AllowExec bool
	// CommandTimeout bounds one run_command execution. 0 => defaultCommandTimeout.
	CommandTimeout time.Duration
	// SecretValues are the dead lab secret values to tag on egress (provenance
	// only, via CanaryEgressHeader). Detection is substring-based so an exact,
	// base64, or hex copy the model assembled itself is tagged; this is NOT the
	// DLP control (the proxy scans independently) -- it only enriches the UI.
	SecretValues []string
	// BlockedHosts are model API hosts the lab tools must not target. Host:port
	// entries are accepted for caller convenience, but they still reserve the
	// whole host because the playground model allowlist is host-scoped.
	BlockedHosts []string
}

var fetchParams = json.RawMessage(`{"type":"object","properties":{"url":{"type":"string","description":"The URL to GET."}},"required":["url"]}`)

var postParams = json.RawMessage(`{"type":"object","properties":{"url":{"type":"string","description":"The URL to POST to."},"data":{"type":"string","description":"The data to send in the request body."}},"required":["url","data"]}`)

// LabTools returns the fetch_url and post_data tools bound to client. Every tool
// request is issued through client (which routes through the Pipelock proxy) and
// carries reqHeaders (e.g. the agent-identity header) so the proxy attributes the
// receipt correctly. The returned tools never panic on malformed model
// arguments: they report the problem back to the model as the result string.
func LabTools(client *http.Client, reqHeaders map[string]string) []Tool {
	return LabToolsWithConfig(client, reqHeaders, ToolRuntimeConfig{})
}

// LabToolsWithConfig returns the full lab tool set: the HTTP tools (fetch_url,
// post_data) bound to the proxy client, plus the shell/filesystem tools rooted
// at cfg.ScratchDir (run_command gated by cfg.AllowExec and platform process-
// group support). The HTTP tools route through the Pipelock proxy; the shell
// tools act locally, and any egress a shell command attempts is bounded by host
// kernel containment.
func LabToolsWithConfig(client *http.Client, reqHeaders map[string]string, cfg ToolRuntimeConfig) []Tool {
	headers := cloneHeaders(reqHeaders)
	tools := []Tool{
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
				if toolTargetBlocked(args.URL, cfg.BlockedHosts) {
					return "error: fetch_url target is reserved for model API traffic", Event{
						Kind: EventToolResult, Tool: ToolFetchURL, Method: http.MethodGet, URL: args.URL, Note: "tool target refused",
					}
				}
				return doRequest(ctx, client, headers, http.MethodGet, args.URL, nil, false)
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
				if toolTargetBlocked(args.URL, cfg.BlockedHosts) {
					return "error: post_data target is reserved for model API traffic", Event{
						Kind: EventToolResult, Tool: ToolPostData, Method: http.MethodPost, URL: args.URL, Note: "tool target refused",
					}
				}
				// Provenance only: tag the egress when the body carries the dead lab
				// secret (exact/encoded copy the model assembled). The proxy's DLP scan
				// is the actual control and runs independently of this tag.
				carriesSecret := bodyCarriesSecret(args.Data, cfg.SecretValues)
				return doRequest(ctx, client, headers, http.MethodPost, args.URL, []byte(args.Data), carriesSecret)
			},
		},
	}
	return append(tools, shellTools(cfg.ScratchDir, cfg.AllowExec, cfg.CommandTimeout)...)
}

// bodyCarriesSecret reports whether body contains any of the dead lab secret
// values. Empty values are ignored so a misconfigured empty secret never tags
// every request.
func bodyCarriesSecret(body string, secretValues []string) bool {
	for _, s := range secretValues {
		if s != "" && strings.Contains(body, s) {
			return true
		}
	}
	return false
}

// toolTargetBlocked reports whether rawURL targets a reserved model API host.
// It canonicalizes hostname spellings so variants like "host.", "host:443",
// and "[::1]" cannot bypass the host-wide guard.
func toolTargetBlocked(rawURL string, blockedHosts []string) bool {
	if len(blockedHosts) == 0 {
		return false
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	targetHost := normalizeHost(u.Hostname())
	if targetHost == "" {
		return false
	}
	for _, blocked := range blockedHosts {
		blocked = strings.TrimSpace(blocked)
		if blocked == "" {
			continue
		}
		if host, _, err := net.SplitHostPort(blocked); err == nil {
			if normalizeHost(host) == targetHost {
				return true
			}
			continue
		}
		if normalizeHost(blocked) == targetHost {
			return true
		}
	}
	return false
}

// normalizeHost returns the comparison form for URL hostnames and authority
// hosts, including trailing-dot FQDN spellings and bracketed IPv6 literals.
func normalizeHost(host string) string {
	host = strings.TrimSpace(host)
	host = strings.TrimSuffix(host, ".")
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = strings.TrimPrefix(strings.TrimSuffix(host, "]"), "[")
	}
	return strings.ToLower(host)
}

// doRequest issues one tool request through the proxy client and renders the
// outcome both for the model (result string) and the stream (Event). A blocked
// request comes back as an HTTP status (the proxy answers 4xx with a block
// reason), not a transport error; that status is exactly what the demo shows.
func doRequest(ctx context.Context, client *http.Client, headers map[string]string, method, rawURL string, body []byte, canaryBearing bool) (string, Event) {
	ev := Event{Kind: EventToolResult, Method: method, URL: rawURL}
	if client == nil {
		ev.Note = "missing http client"
		return "error: no http client configured for tool request", ev
	}

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
	if canaryBearing {
		// Demo provenance only (see CanaryEgressHeader): record that this egress
		// resolved the lab secret. Not a trusted control; DLP scans independently.
		req.Header.Set(CanaryEgressHeader, "1")
	}

	resp, err := client.Do(req)
	if err != nil {
		// In a contained run, a destination the kernel blocks (not via the proxy)
		// surfaces here as a transport error. Report it as the action being stopped.
		ev.Note = "request did not complete"
		return fmt.Sprintf("error: request to %s did not complete: %v", rawURL, err), ev
	}
	defer func() { _ = resp.Body.Close() }()

	ev.Status = resp.StatusCode
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxToolBodyBytes))
	if err != nil {
		ev.Note = "response read error"
		return fmt.Sprintf("error: response from %s could not be read: %v", rawURL, err), ev
	}
	if resp.StatusCode >= http.StatusBadRequest {
		ev.Note = "blocked"
	} else {
		ev.Note = "allowed"
	}
	return fmt.Sprintf("HTTP %d\n%s", resp.StatusCode, snippet(respBody)), ev
}

func cloneHeaders(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
