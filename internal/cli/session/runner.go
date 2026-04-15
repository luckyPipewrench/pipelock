// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package session

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
)

// newClientFn is the factory the subcommands use to build a live client.
// Tests override this variable with a closure that returns a stubbed
// client, avoiding the need to stand up an httptest server in every case.
var newClientFn = func(flags *rootFlags) (*Client, error) {
	ep, err := resolveEndpoint(flags, defaultResolverDeps())
	if err != nil {
		return nil, cliutil.ExitCodeError(2, err)
	}
	return newClient(ep), nil
}

// runClientCmd dispatches a subcommand that needs an admin API client.
// The executor receives a configured *Client, a context.Context derived
// from the parent cobra context, and the standard output writer. The
// returned error is wrapped in an exit-code-aware error so callers get a
// distinct code per failure class.
func runClientCmd(
	flags *rootFlags,
	ctx context.Context,
	stdout io.Writer,
	executor func(context.Context, *Client, io.Writer) error,
) error {
	client, err := newClientFn(flags)
	if err != nil {
		return err
	}

	if ctx == nil {
		ctx = context.Background()
	}
	if err := executor(ctx, client, stdout); err != nil {
		// Preserve any exit-code classification the executor already
		// attached (e.g. recover's interactive invalid-input path wraps
		// usage errors with ExitConfig). mapClientError is only for
		// bare API/network errors that haven't been classified yet.
		var classified *cliutil.ExitError
		if errors.As(err, &classified) {
			return err
		}
		return mapClientError(err)
	}
	return nil
}

// mapClientError converts an admin API error into a CLI exit code:
//
//	exit 1 — operational failure (404, 429, 500, network)
//	exit 2 — auth/config failure (401, missing token, malformed flags)
//
// The rule is: exit 2 means "fix your setup," exit 1 means "try again
// or escalate." Keeping those distinct lets operators script retries.
func mapClientError(err error) error {
	if err == nil {
		return nil
	}
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		switch apiErr.StatusCode {
		case http.StatusUnauthorized:
			return cliutil.ExitCodeError(2, fmt.Errorf("unauthorized — check --api-token or PIPELOCK_KILLSWITCH_API_TOKEN: %s", apiErr.Body))
		case http.StatusNotFound:
			return cliutil.ExitCodeError(1, errors.New("session not found"))
		case http.StatusTooManyRequests:
			return cliutil.ExitCodeError(1, fmt.Errorf("rate limited; retry after %s seconds", apiErr.RetryAfter))
		case http.StatusBadRequest:
			return cliutil.ExitCodeError(2, fmt.Errorf("bad request: %s", apiErr.Body))
		}
		return cliutil.ExitCodeError(1, fmt.Errorf("server error HTTP %d: %s", apiErr.StatusCode, apiErr.Body))
	}
	return cliutil.ExitCodeError(1, err)
}

// writeJSON marshals v as indented JSON to w. Used by every subcommand
// when --json is set. Returns the error from the encoder so the cobra
// RunE closure surfaces it with the right exit code.
func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
