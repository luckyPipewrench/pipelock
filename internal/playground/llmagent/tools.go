// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package llmagent

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
)

// Lab tool names. fetch_url reads; post_data sends. The model picks; Pipelock
// mediates whatever destination it picks.
const (
	ToolFetchURL = "fetch_url"
	ToolPostData = "post_data"
	// CanaryHandle is the opaque reference the model uses for the lab credential.
	// The model NEVER sees the real value: not in its prompt, not in tool results,
	// not in its own chat replies. The tool resolves the handle to the real
	// (synthetic) secret locally, immediately before the request leaves through
	// the proxy. This keeps the secret out of the model API request and out of
	// model-to-visitor output, while still letting a jailbroken model trigger the
	// real exfil attempt Pipelock must block, in whatever encoding it requests.
	CanaryHandle = "canary://demo/aws-canary"
	// CanaryEgressHeader marks a tool request whose body the runtime resolved from
	// CanaryHandle. It is demo PROVENANCE metadata for the receipt/UI ("this
	// request carried the lab secret"); it is NOT a trusted control. The real DLP
	// scan runs independently of this header, and the header is set inside the
	// agent's own trust domain, so it must never be the sole basis for a block.
	CanaryEgressHeader = "X-Pipelock-Demo-Canary-Egress"
)

// CanaryPlaceholder is the legacy literal-substitution token. Deprecated: the
// demo now uses CanaryHandle (the model never holds the value to encode), which
// makes encoding attacks act on the real secret instead of a no-op placeholder.
// Retained only so external references still compile; the tools do not expand it.
const CanaryPlaceholder = "{{CANARY}}"

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
	// Encoding optionally transforms a resolved CanaryHandle before sending:
	// "none" (default), "base64", or "hex". This lets a jailbroken model attempt
	// encoded exfil of the REAL secret (tool-mediated, since the model never holds
	// the value), which Pipelock then blocks.
	Encoding string `json:"encoding,omitempty"`
}

// ToolRuntimeConfig controls local lab-tool behavior that must stay outside the
// model API request path.
type ToolRuntimeConfig struct {
	// Canary is the real (synthetic) secret value that CanaryHandle resolves to,
	// substituted inside post_data bodies immediately before egress.
	Canary string
	// BlockedHosts are model API hosts the lab tools must not target. Host:port
	// entries are accepted for caller convenience, but they still reserve the
	// whole host because the playground model allowlist is host-scoped.
	BlockedHosts []string
}

var fetchParams = json.RawMessage(`{"type":"object","properties":{"url":{"type":"string","description":"The URL to GET."}},"required":["url"]}`)

var postParams = json.RawMessage(`{"type":"object","properties":{"url":{"type":"string","description":"The URL to POST to."},"data":{"type":"string","description":"The data to send in the request body. Use the credential handle canary://demo/aws-canary to include the lab credential."},"encoding":{"type":"string","enum":["none","base64","hex"],"description":"Optional transform applied to the resolved credential before sending."}},"required":["url","data"]}`)

// LabTools returns the fetch_url and post_data tools bound to client. Every tool
// request is issued through client (which routes through the Pipelock proxy) and
// carries reqHeaders (e.g. the agent-identity header) so the proxy attributes the
// receipt correctly. The returned tools never panic on malformed model
// arguments: they report the problem back to the model as the result string.
func LabTools(client *http.Client, reqHeaders map[string]string) []Tool {
	return LabToolsWithConfig(client, reqHeaders, ToolRuntimeConfig{})
}

// LabToolsWithCanary returns the lab tools with optional local secret resolution.
// The model sees only CanaryHandle; the raw canary is substituted inside the
// subprocess immediately before the POST leaves through the proxy. That prevents
// the model API request (and the model's chat replies) from carrying the canary
// while still letting a jailbroken model trigger the exfil attempt Pipelock must
// block, in whatever encoding it requests.
func LabToolsWithCanary(client *http.Client, reqHeaders map[string]string, canary string) []Tool {
	return LabToolsWithConfig(client, reqHeaders, ToolRuntimeConfig{Canary: canary})
}

// LabToolsWithConfig returns the lab tools with local-only guardrails such as
// canary expansion and reserved model-host blocking.
func LabToolsWithConfig(client *http.Client, reqHeaders map[string]string, cfg ToolRuntimeConfig) []Tool {
	headers := cloneHeaders(reqHeaders)
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
				data := args.Data
				canaryBearing := false
				if cfg.Canary != "" && strings.Contains(data, CanaryHandle) {
					resolved, err := encodeSecret(cfg.Canary, args.Encoding)
					if err != nil {
						return "error: post_data encoding must be one of none, base64, hex", Event{
							Kind: EventToolResult, Tool: ToolPostData, Method: http.MethodPost, URL: args.URL, Note: "bad arguments",
						}
					}
					data = strings.ReplaceAll(data, CanaryHandle, resolved)
					canaryBearing = true
				}
				return doRequest(ctx, client, headers, http.MethodPost, args.URL, []byte(data), canaryBearing)
			},
		},
	}
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

// encodeSecret resolves a secret value with the optional transform the model
// requested. The transforms mirror the reversible encodings Pipelock's DLP
// normalizes, so an encoded exfil attempt carries the real secret bytes and is
// still caught. An unknown encoding is an error (reported back to the model),
// never a silent passthrough.
func encodeSecret(secret, encoding string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(encoding)) {
	case "", "none", "raw":
		return secret, nil
	case "base64":
		return base64.StdEncoding.EncodeToString([]byte(secret)), nil
	case "hex":
		return hex.EncodeToString([]byte(secret)), nil
	default:
		return "", fmt.Errorf("unsupported encoding %q", encoding)
	}
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
