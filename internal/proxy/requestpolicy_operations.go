// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"io"
	"mime"
	"mime/multipart"

	"github.com/luckyPipewrench/pipelock/internal/reqpolicy"
)

// multipartOperationsMaxBytes caps the bytes read from a multipart "operations"
// field. That field carries only the GraphQL-over-HTTP JSON (the query and
// variables map), never the uploaded files, so 1 MiB is generous. The cap
// keeps a crafted multipart part from forcing an unbounded read.
const multipartOperationsMaxBytes = 1 * 1024 * 1024

// extractRequestPolicyOperations pulls the request's GraphQL operations from
// whichever surface carries them, then classifies with the shared extractor:
//
//   - multipart/form-data: the graphql-multipart-request spec puts the
//     GraphQL-over-HTTP JSON in the "operations" form field.
//   - GraphQL-over-GET (no body, ?query=...): the document is a query parameter.
//   - otherwise: the JSON request body (single object or batch array).
//
// The (parseOK, opaque) returns drive the caller's fail-closed handling exactly
// as for a JSON body: a multipart request with no readable "operations" field,
// or a GET whose query parameter is absent/unparseable, surfaces parseOK=false
// so on_parse_error applies.
func extractRequestPolicyOperations(in requestPolicyInput) (ops []reqpolicy.RequestOperation, parseOK, opaque bool) {
	if isMultipartFormData(in.ContentType) {
		opsJSON, ok := multipartOperationsField(in.ContentType, in.Body)
		if !ok {
			return nil, false, false
		}
		return reqpolicy.ExtractGraphQL(opsJSON)
	}
	if len(in.Body) == 0 {
		if ops, parseOK, opaque, ok := reqpolicy.ExtractGraphQLFromQuery(in.Query); ok {
			return ops, parseOK, opaque
		}
	}
	return reqpolicy.ExtractGraphQL(in.Body)
}

// isMultipartFormData reports whether ct is a multipart/form-data media type,
// ignoring parameters (boundary, charset) and case.
func isMultipartFormData(ct string) bool {
	mt, _, err := mime.ParseMediaType(ct)
	return err == nil && mt == "multipart/form-data"
}

// multipartOperationsField returns the bytes of the "operations" form field of
// a multipart/form-data body, or ok=false when the boundary is missing or no
// such field is present. Only the operations field is read (bounded); file
// parts are skipped without buffering.
func multipartOperationsField(ct string, body []byte) ([]byte, bool) {
	_, params, err := mime.ParseMediaType(ct)
	if err != nil {
		return nil, false
	}
	boundary := params["boundary"]
	if boundary == "" {
		return nil, false
	}
	mr := multipart.NewReader(bytes.NewReader(body), boundary)
	for {
		part, err := mr.NextPart()
		if err != nil {
			return nil, false
		}
		if part.FormName() == "operations" {
			// Read one past the cap so an over-cap field is detected and
			// rejected rather than silently truncated: classifying a partial
			// payload could miss a dangerous operation padded past the limit.
			data, readErr := io.ReadAll(io.LimitReader(part, multipartOperationsMaxBytes+1))
			_ = part.Close()
			if readErr != nil {
				return nil, false
			}
			if len(data) > multipartOperationsMaxBytes {
				return nil, false
			}
			return data, true
		}
		_ = part.Close()
	}
}
