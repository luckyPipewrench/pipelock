// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package playground

import (
	"errors"
	"fmt"
	"net/url"
)

// ValidatePlainHTTPURL parses raw as an http(s) URL that carries no embedded
// credentials, query string, or fragment. Playground configuration URLs use
// separate secret-file flags and fixed path construction; allowing URL-carried
// secrets here would risk exposing them in argv, logs, receipts, or error text.
func ValidatePlainHTTPURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, errors.New("must use http or https")
	}
	if u.Hostname() == "" {
		return nil, errors.New("host is required")
	}
	if u.User != nil {
		return nil, errors.New("must not include credentials")
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("must not include query strings or fragments")
	}
	return u, nil
}
