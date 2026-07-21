// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

var defaultMCPDialLookupHost = net.DefaultResolver.LookupHost

// NewMetadataSafeDialContext returns a DialContext for configured MCP upstream
// transports. It enforces the cloud metadata hard floor at connection time while
// preserving existing support for legitimate local/private MCP servers.
func NewMetadataSafeDialContext(scannerFn func() *scanner.Scanner) func(ctx context.Context, network, addr string) (net.Conn, error) {
	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	return newMetadataSafeDialContext(scannerFn, dialer.DialContext)
}

func newMetadataSafeDialContext(
	scannerFn func() *scanner.Scanner,
	dialContext func(ctx context.Context, network, addr string) (net.Conn, error),
) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, fmt.Errorf("mcp upstream dial: split addr %q: %w", addr, err)
		}
		if ip := normalizeMCPDialIP(net.ParseIP(stripMCPDialIPv6Zone(host))); ip != nil {
			if scanner.IsCloudMetadataIP(ip) {
				return nil, mcpMetadataDialBlock(host, ip)
			}
			return dialContext(ctx, network, addr)
		}

		var sc *scanner.Scanner
		if scannerFn != nil {
			sc = scannerFn()
		}
		ips, err := lookupMCPDialHost(ctx, sc, host)
		if err != nil {
			return nil, fmt.Errorf("mcp upstream dial: DNS lookup %q: %w", host, err)
		}
		if len(ips) == 0 {
			return nil, fmt.Errorf("mcp upstream dial: DNS returned no addresses for %s", host)
		}

		dialAddrs := make([]string, 0, len(ips))
		for _, ipStr := range ips {
			ip := normalizeMCPDialIP(net.ParseIP(stripMCPDialIPv6Zone(strings.TrimSpace(ipStr))))
			if ip == nil {
				return nil, fmt.Errorf("mcp upstream dial: unparseable IP %q from DNS for %s", ipStr, host)
			}
			if scanner.IsCloudMetadataIP(ip) {
				return nil, mcpMetadataDialBlock(host, ip)
			}
			dialAddrs = append(dialAddrs, net.JoinHostPort(ip.String(), port))
		}

		var lastErr error
		for _, dialAddr := range dialAddrs {
			conn, dialErr := dialContext(ctx, network, dialAddr)
			if dialErr == nil {
				return conn, nil
			}
			lastErr = dialErr
		}
		return nil, fmt.Errorf("mcp upstream dial %s: %w", addr, lastErr)
	}
}

func lookupMCPDialHost(ctx context.Context, sc *scanner.Scanner, host string) ([]string, error) {
	if sc != nil {
		return sc.HostResolver().LookupHost(ctx, host)
	}
	return defaultMCPDialLookupHost(ctx, host)
}

func mcpMetadataDialBlock(host string, ip net.IP) error {
	return fmt.Errorf("SSRF blocked: %s resolves to cloud metadata endpoint %s (ssrf_metadata)", host, ip)
}

func normalizeMCPDialIP(ip net.IP) net.IP {
	if ip == nil {
		return nil
	}
	if v4 := ip.To4(); v4 != nil {
		return v4
	}
	return ip
}

func stripMCPDialIPv6Zone(ipStr string) string {
	if idx := strings.Index(ipStr, "%"); idx != -1 {
		return ipStr[:idx]
	}
	return ipStr
}
