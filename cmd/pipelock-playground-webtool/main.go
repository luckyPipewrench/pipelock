// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package main is the entry point for pipelock-playground-webtool, a minimal
// HTTP utility used by pipelock-playground-toyagent to make requests that
// travel through the Pipelock proxy.
//
// The web tool is a SEPARATE binary so the live demo visibly demonstrates the
// agent→tool separation that Pipelock mediates.  It makes requests using
// http.DefaultTransport, which respects HTTPS_PROXY / HTTP_PROXY, so all
// traffic flows through whatever proxy the environment configures.
//
// Subcommands:
//
//	get  <url>                 Perform an HTTP GET to the given URL.
//	post <url> [--include-canary]  Perform an HTTP POST.  With --include-canary,
//	                               the canary value is read from
//	                               PLAYGROUND_CANARY_VALUE (env) and placed in
//	                               the request body.  The value is NEVER read
//	                               from argv.
//
// Security property: the canary VALUE lives only in the environment and in the
// POST body.  It is never passed as a command-line argument and never placed in
// a URL.
//
// Agent identity: if PLAYGROUND_AGENT_ID is set in the environment, the web
// tool adds an X-Pipelock-Agent header on every request so the proxy records
// the correct actor identity in its receipts.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// agentIDEnvVar, when set, causes the web tool to add an X-Pipelock-Agent
// header on every request. This is how the playground's receipts record the
// correct actor identity instead of "anonymous".
const agentIDEnvVar = "PLAYGROUND_AGENT_ID"

// agentHeader is the canonical Pipelock agent identity header.
const agentHeader = "X-Pipelock-Agent"

const webToolHTTPTimeout = 5 * time.Second

func main() {
	err := runWebTool(context.Background(), os.Stdout, os.Args[1:], os.Getenv)
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "[webtool] error:", err)
		os.Exit(1)
	}
}

// runWebTool is the testable core of pipelock-playground-webtool.
//
//   - ctx        request context
//   - out        destination for status / diagnostic output
//   - args       command-line arguments (does NOT include argv[0])
//   - lookupEnv  function to look up an env variable (os.Getenv in production;
//     injected in tests so the canary value never has to be in a real env var)
//
// Security property: the canary VALUE is obtained only from lookupEnv, never
// from args.  Callers must not put the value in args.
func runWebTool(ctx context.Context, out io.Writer, args []string, lookupEnv func(string) string) error {
	if len(args) == 0 {
		return errors.New("usage: webtool <get|post> <url> [--include-canary]")
	}

	subcmd := args[0]
	rest := args[1:]

	switch subcmd {
	case "get":
		return doGet(ctx, out, rest, lookupEnv)
	case "post":
		return doPost(ctx, out, rest, lookupEnv)
	default:
		return fmt.Errorf("unknown subcommand %q: must be get or post", subcmd)
	}
}

// doGet performs an HTTP GET to the URL in args[0].
func doGet(ctx context.Context, out io.Writer, args []string, lookupEnv func(string) string) error {
	if len(args) != 1 {
		return errors.New("get requires exactly one URL")
	}
	targetURL := args[0]

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return fmt.Errorf("build GET request: %w", err)
	}
	setAgentHeader(req, lookupEnv)

	resp, err := webToolHTTPClient().Do(req)
	if err != nil {
		return fmt.Errorf("GET %s: %w", targetURL, err)
	}
	defer func() { _ = resp.Body.Close() }()

	_, _ = fmt.Fprintf(out, "[webtool] GET %s -> HTTP %d\n", targetURL, resp.StatusCode)
	return nil
}

func webToolHTTPClient() *http.Client {
	return &http.Client{Timeout: webToolHTTPTimeout}
}

// doPost performs an HTTP POST to the URL in args[0].  If args contains
// "--include-canary", the canary value is read from PLAYGROUND_CANARY_VALUE
// via lookupEnv and placed in the request body as a form-encoded field.
//
// Security: the canary VALUE is obtained from lookupEnv only.  It is never in
// args, never in the URL, and never printed to out.
func doPost(ctx context.Context, out io.Writer, args []string, lookupEnv func(string) string) error {
	if len(args) == 0 {
		return errors.New("post requires a URL")
	}
	targetURL := args[0]

	// Check for --include-canary flag in the remaining args.
	includeCanary := false
	for _, a := range args[1:] {
		switch a {
		case "--include-canary":
			includeCanary = true
		default:
			return fmt.Errorf("unknown post argument %q", a)
		}
	}

	var bodyStr string
	if includeCanary {
		// Read the canary VALUE from the environment — never from argv.
		canaryVal := lookupEnv("PLAYGROUND_CANARY_VALUE")
		// field=<value> is a minimal form body suitable for DLP detection testing.
		bodyStr = "field=" + canaryVal
	} else {
		bodyStr = "field=ping"
	}

	body := strings.NewReader(bodyStr)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, body)
	if err != nil {
		return fmt.Errorf("build POST request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	setAgentHeader(req, lookupEnv)

	resp, err := webToolHTTPClient().Do(req)
	if err != nil {
		return fmt.Errorf("POST %s: %w", targetURL, err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Report status but NEVER echo the body or the canary value.
	_, _ = fmt.Fprintf(out, "[webtool] POST %s -> HTTP %d\n", targetURL, resp.StatusCode)
	return nil
}

// setAgentHeader adds the X-Pipelock-Agent header to a request when the
// PLAYGROUND_AGENT_ID env var is set. This ensures the proxy records the
// correct actor identity in its receipts.
func setAgentHeader(req *http.Request, lookupEnv func(string) string) {
	if id := lookupEnv(agentIDEnvVar); id != "" {
		req.Header.Set(agentHeader, id)
	}
}
