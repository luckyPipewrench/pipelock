// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/securefile"
)

const mcpListenerTokenMaxBytes = 8192

func readMCPListenerTokenFile(path string) (string, error) {
	if path == "" {
		return "", nil
	}
	data, err := securefile.Read(path, securefile.Options{
		MaxBytes:        mcpListenerTokenMaxBytes,
		DisallowedPerms: 0o027,
	})
	if err != nil {
		return "", fmt.Errorf("reading MCP listener auth token: %w", err)
	}
	token := strings.TrimSpace(string(data))
	if token == "" {
		return "", fmt.Errorf("MCP listener auth token file is empty")
	}
	for i := range len(token) {
		if token[i] < 0x21 || token[i] > 0x7e {
			return "", fmt.Errorf("MCP listener auth token must contain visible ASCII without spaces")
		}
	}
	return token, nil
}

func validateMCPListenerBoundary(listenAddr, token string, allowUnauthenticated bool) error {
	if listenAddr == "" || token != "" || allowUnauthenticated {
		return nil
	}
	host, _, err := net.SplitHostPort(listenAddr)
	if err != nil {
		return fmt.Errorf("invalid MCP listener address %q: %w", listenAddr, err)
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("non-loopback MCP listener %q requires an auth token file; unauthenticated operation is only appropriate behind a verified ingress policy and requires explicit acknowledgement", listenAddr)
	}
	return nil
}

func validateMCPListenerOrigins(origins []string) error {
	for _, origin := range origins {
		if strings.TrimSpace(origin) != origin || origin == "" || origin == "null" {
			return fmt.Errorf("invalid MCP listener allowed origin %q", origin)
		}
		u, err := url.Parse(origin)
		if err != nil || u.Scheme == "" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
			return fmt.Errorf("invalid MCP listener allowed origin %q: expected only scheme and host", origin)
		}
	}
	return nil
}
