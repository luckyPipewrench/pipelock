// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package authority

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

const (
	// HTTPHeader is Pipelock's reserved HTTP control header for an external
	// authority grant. Pipelock consumes it and never forwards it upstream.
	HTTPHeader = "Pipelock-Authority"
	// MCPMetaKey is the sole MCP carrier for an external authority grant.
	MCPMetaKey = "com.pipelock/authority"
)

var (
	ErrMissingReference      = errors.New("authority reference is missing")
	ErrMalformedReference    = errors.New("authority reference is malformed")
	ErrDuplicateReference    = errors.New("authority reference must have exactly one value")
	ErrNominatedByConnection = errors.New("authority header must not be nominated by Connection")
)

// Evaluate runs the injected verifier after transport parsing and the existing
// policy gates have completed. A nil verifier is an explicit bypass preserving
// pre-authority behavior. Once a verifier is installed, every non-allow result
// fails closed.
func Evaluate(ctx context.Context, verifier Verifier, request Request, carrierErr error) (Result, error) {
	if verifier == nil {
		return Result{}, nil
	}
	if carrierErr != nil {
		return Result{Decision: DecisionDeny, Reason: ReasonMalformedReference}, carrierErr
	}
	if request.Actor == "" || request.Action == "" || request.Destination == "" || request.AuthorityRef == "" {
		return Result{Decision: DecisionDeny, Reason: ReasonMalformedReference}, ErrMalformedReference
	}

	result := verifier.Verify(ctx, request)
	if !result.Decision.Valid() {
		return result, fmt.Errorf("authority verifier returned invalid decision %d", result.Decision)
	}
	if result.Decision != DecisionAllow {
		return result, fmt.Errorf("authority verifier returned %s", result.Decision)
	}
	return result, nil
}

// ExtractHTTPReference consumes the reserved authority header. The header is
// deleted on every path, including malformed and duplicate inputs, so opaque
// grants cannot leak to an upstream selected later in the request pipeline.
func ExtractHTTPReference(header http.Header) (string, error) {
	if header == nil {
		return "", ErrMissingReference
	}

	var values []string
	for name, current := range header {
		if strings.EqualFold(name, HTTPHeader) {
			values = append(values, current...)
			delete(header, name)
		}
	}

	for name, current := range header {
		if !strings.EqualFold(name, "Connection") {
			continue
		}
		for _, value := range current {
			for _, token := range strings.Split(value, ",") {
				if strings.EqualFold(strings.TrimSpace(token), HTTPHeader) {
					return "", ErrNominatedByConnection
				}
			}
		}
	}

	if len(values) == 0 {
		return "", ErrMissingReference
	}
	if len(values) != 1 {
		return "", ErrDuplicateReference
	}
	ref := strings.TrimSpace(values[0])
	if ref == "" || len(ref) > MaxReferenceBytes || strings.Contains(ref, ",") {
		return "", ErrMalformedReference
	}
	return ref, nil
}
