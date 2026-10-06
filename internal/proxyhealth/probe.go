// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package proxyhealth probes the existing proxy health endpoint.
package proxyhealth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
)

// Get is the common health probe used by healthcheck and exec. The caller owns
// the timeout, transport policy, and response body.
func Get(ctx context.Context, client *http.Client, proxyURL string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, proxyURL+"/health", nil)
	if err != nil {
		return nil, fmt.Errorf("health check failed: %w", err)
	}
	resp, err := client.Do(req) //nolint:gosec // G704: intentional operator-selected proxy health URL
	if err != nil {
		return nil, fmt.Errorf("health check failed: %w", err)
	}
	return resp, nil
}

// CheckLaunch requires explicit, current runtime state. Older, malformed,
// incomplete or ambiguous responses never authorize launching a command.
func CheckLaunch(resp *http.Response, requireIntercept bool) error {
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("proxy unhealthy: status %d; start or repair the Pipelock service", resp.StatusCode)
	}
	const maxHealthBytes = 64 << 10
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxHealthBytes+1))
	if err != nil {
		return fmt.Errorf("read proxy health: %w", err)
	}
	if len(data) > maxHealthBytes {
		return errors.New("proxy health response is too large; verify --proxy-url points to Pipelock")
	}
	fields, err := decodeObject(data)
	if err != nil {
		return fmt.Errorf("invalid proxy health response; verify --proxy-url points to Pipelock: %w", err)
	}
	var status string
	var forward, intercept, killed bool
	if err := json.Unmarshal(fields["status"], &status); err != nil || status != "healthy" {
		return errors.New("proxy health state is unhealthy or incomplete; start a current Pipelock service and verify --proxy-url")
	}
	for _, field := range []struct {
		name  string
		value *bool
	}{
		{"forward_proxy_enabled", &forward},
		{"tls_interception_enabled", &intercept},
		{"kill_switch_active", &killed},
	} {
		raw := fields[field.name]
		if len(raw) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return errors.New("proxy health state is incomplete; start a current Pipelock service and verify --proxy-url")
		}
		if err := json.Unmarshal(raw, field.value); err != nil {
			return fmt.Errorf("invalid proxy health field %s: %w", field.name, err)
		}
	}
	if !forward {
		return errors.New("forward proxy is disabled; enable forward_proxy.enabled in the running service config")
	}
	if requireIntercept && !intercept {
		return errors.New("TLS interception is required but disabled; enable tls_interception.enabled in the running service config")
	}
	if killed {
		return errors.New("proxy kill switch is active; inspect and clear its activation sources before launching")
	}
	return nil
}

// Decode keys exactly as the producer emits them, rejecting duplicate keys
// instead of trusting encoding/json's last-value and case-folding behavior.
func decodeObject(data []byte) (map[string]json.RawMessage, error) {
	d := json.NewDecoder(bytes.NewReader(data))
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return nil, errors.New("health response must be a JSON object")
	}
	fields := make(map[string]json.RawMessage)
	for d.More() {
		token, err := d.Token()
		if err != nil {
			return nil, err
		}
		key, ok := token.(string)
		if !ok {
			return nil, errors.New("invalid health field name")
		}
		if _, exists := fields[key]; exists {
			return nil, fmt.Errorf("duplicate health field %s", key)
		}
		var value json.RawMessage
		if err := d.Decode(&value); err != nil {
			return nil, err
		}
		fields[key] = value
	}
	if _, err := d.Token(); err != nil {
		return nil, err
	}
	var extra any
	if err := d.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, errors.New("trailing data in health response")
	}
	return fields, nil
}
