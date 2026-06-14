//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package conductor

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
)

// encodeJSON marshals v to JSON bytes.
func encodeJSON(v any) ([]byte, error) {
	return json.Marshal(v)
}

// newTestDeleteRequest builds an authenticated DELETE request with a JSON body.
func newTestDeleteRequest(ctx context.Context, url string, body []byte, token string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	return req, nil
}
