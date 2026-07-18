// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/blockreason"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

type ssrfDialScanSnapshot struct {
	host string
	ips  map[string]struct{}
}

type ssrfDialBlockError struct {
	reason blockreason.Reason
	detail string
}

func (e *ssrfDialBlockError) Error() string {
	if e == nil {
		return ""
	}
	return e.detail
}

func (e *ssrfDialBlockError) blockInfo() blockreason.Info {
	if e == nil {
		return blockInfoFor(blockreason.SSRFPrivateIP, scanner.ScannerSSRF)
	}
	return blockInfoFor(e.reason, scanner.ScannerSSRF)
}

func (e *ssrfDialBlockError) logDetail() string {
	if e == nil {
		return ""
	}
	return string(e.reason) + ": " + e.detail
}

func withSSRFDialScanSnapshot(ctx context.Context, host string, ips []string) context.Context {
	if ctx == nil || host == "" || len(ips) == 0 {
		return ctx
	}
	snapshot := ssrfDialScanSnapshot{
		host: normalizeSSRFDialHost(host),
		ips:  make(map[string]struct{}, len(ips)),
	}
	for _, ipStr := range ips {
		ip := normalizeSSRFDialIP(net.ParseIP(strings.TrimSpace(stripIPv6Zone(ipStr))))
		if ip == nil {
			continue
		}
		snapshot.ips[ip.String()] = struct{}{}
	}
	if snapshot.host == "" || len(snapshot.ips) == 0 {
		return ctx
	}
	return context.WithValue(ctx, ctxKeySSRFDialScanSnapshot, snapshot)
}

func withAllowedSSRFDialScanSnapshot(ctx context.Context, sc *scanner.Scanner, host string, result scanner.Result) context.Context {
	if ctx == nil {
		return nil
	}
	clearSnapshot := func() context.Context {
		return context.WithValue(ctx, ctxKeySSRFDialScanSnapshot, ssrfDialScanSnapshot{})
	}
	if sc == nil || !result.Allowed || len(result.SSRFResolvedIPs) == 0 {
		return clearSnapshot()
	}
	for _, ipStr := range result.SSRFResolvedIPs {
		ip := normalizeSSRFDialIP(net.ParseIP(strings.TrimSpace(stripIPv6Zone(ipStr))))
		if ip == nil || scanner.IsCloudMetadataIP(ip) || sc.IsInternalIP(ip) {
			return clearSnapshot()
		}
	}
	return withSSRFDialScanSnapshot(ctx, host, result.SSRFResolvedIPs)
}

func newSSRFDialBlockError(ctx context.Context, host string, ip net.IP, detail string) *ssrfDialBlockError {
	reason := blockreason.SSRFPrivateIP
	if scanner.IsCloudMetadataIP(ip) {
		reason = blockreason.SSRFMetadata
	}
	if isSSRFDNSRebind(ctx, host, ip) {
		reason = blockreason.SSRFDNSRebind
	}
	return &ssrfDialBlockError{reason: reason, detail: detail}
}

func isSSRFDNSRebind(ctx context.Context, host string, ip net.IP) bool {
	if ctx == nil || ip == nil {
		return false
	}
	snapshot, ok := ctx.Value(ctxKeySSRFDialScanSnapshot).(ssrfDialScanSnapshot)
	if !ok || snapshot.host == "" || len(snapshot.ips) == 0 {
		return false
	}
	if normalizeSSRFDialHost(host) != snapshot.host {
		return false
	}
	ip = normalizeSSRFDialIP(ip)
	if ip == nil {
		return false
	}
	_, seenAtScanTime := snapshot.ips[ip.String()]
	return !seenAtScanTime
}

func normalizeSSRFDialHost(host string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
}

func normalizeSSRFDialIP(ip net.IP) net.IP {
	if ip == nil {
		return nil
	}
	if v4 := ip.To4(); v4 != nil {
		return v4
	}
	return ip
}

func stripIPv6Zone(ipStr string) string {
	if idx := strings.Index(ipStr, "%"); idx != -1 {
		return ipStr[:idx]
	}
	return ipStr
}

func ssrfDialBlockDetail(host string, ip net.IP) string {
	if scanner.IsCloudMetadataIP(ip) {
		return fmt.Sprintf("SSRF blocked: %s resolves to cloud metadata endpoint %s", host, ip)
	}
	return fmt.Sprintf("SSRF blocked: %s resolves to internal IP %s", host, ip)
}
