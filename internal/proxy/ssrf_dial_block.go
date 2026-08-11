// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/blockreason"
	"github.com/luckyPipewrench/pipelock/internal/destination"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

type ssrfDialScanSnapshot struct {
	host string
	// port is the exact destination TCP port that was scanned and
	// authorized. A snapshot recorded for host:443 must not vouch for a
	// dial to host:6443, so the DNS-rebind label (and, once guard grants
	// exist, the internal-address allow) only applies when the dial port
	// matches this value. Empty means the recording path had no port.
	port string
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

func withSSRFDialScanSnapshot(ctx context.Context, host, port string, ips []string) context.Context {
	if ctx == nil || host == "" || len(ips) == 0 {
		return ctx
	}
	snapshot := ssrfDialScanSnapshot{
		host: normalizeSSRFDialHost(host),
		port: normalizeSSRFDialPort(port),
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

func withAllowedSSRFDialScanSnapshot(ctx context.Context, sc *scanner.Scanner, host, port string, result scanner.Result) context.Context {
	if ctx == nil {
		return nil
	}
	clearSnapshot := func() context.Context {
		return context.WithValue(ctx, ctxKeySSRFDialScanSnapshot, ssrfDialScanSnapshot{})
	}
	if sc == nil || !result.Allowed || len(result.SSRFResolvedIPs) == 0 {
		return clearSnapshot()
	}
	guardGranted := scannerDestinationGranted(sc, host, port)
	for _, ipStr := range result.SSRFResolvedIPs {
		ip := normalizeSSRFDialIP(net.ParseIP(strings.TrimSpace(stripIPv6Zone(ipStr))))
		if ip == nil || scanner.IsNonOverridableSSRFTarget(ip) || (sc.IsInternalIP(ip) && !guardGranted) {
			return clearSnapshot()
		}
	}
	return withSSRFDialScanSnapshot(ctx, host, port, result.SSRFResolvedIPs)
}

func scannerDestinationGranted(sc *scanner.Scanner, host, port string) bool {
	value, err := strconv.ParseUint(normalizeSSRFDialPort(port), 10, 16)
	return err == nil && value != 0 && sc.IsDestinationGranted(destination.NetworkTCP, host, uint16(value))
}

// withSSRFDialPort records the exact destination port of an in-progress dial so
// isSSRFDNSRebind can require the scan-time snapshot to have been taken for the
// same port. The dialer sets this from the split dial address; a snapshot taken
// for a different port cannot influence this dial's verdict.
func withSSRFDialPort(ctx context.Context, port string) context.Context {
	if ctx == nil {
		return ctx
	}
	return context.WithValue(ctx, ctxKeySSRFDialPort, normalizeSSRFDialPort(port))
}

func ssrfDialPortFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	port, _ := ctx.Value(ctxKeySSRFDialPort).(string)
	return port
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
	// A snapshot only vouches for the exact host:port it was taken for. When
	// both the snapshot and the current dial carry a port and they differ,
	// the snapshot describes a different destination and must not apply to
	// this dial. This keeps a host:443 scan from labeling (or, with guard
	// grants, authorizing) a host:6443 dial.
	if dialPort := ssrfDialPortFromContext(ctx); dialPort != "" && snapshot.port != "" && dialPort != snapshot.port {
		return false
	}
	ip = normalizeSSRFDialIP(ip)
	if ip == nil {
		return false
	}
	_, seenAtScanTime := snapshot.ips[ip.String()]
	return !seenAtScanTime
}

func ssrfDialSnapshotContains(ctx context.Context, host string, ip net.IP) bool {
	if ctx == nil || ip == nil {
		return false
	}
	snapshot, ok := ctx.Value(ctxKeySSRFDialScanSnapshot).(ssrfDialScanSnapshot)
	if !ok || normalizeSSRFDialHost(host) != snapshot.host {
		return false
	}
	if dialPort := ssrfDialPortFromContext(ctx); dialPort == "" || snapshot.port == "" || dialPort != snapshot.port {
		return false
	}
	ip = normalizeSSRFDialIP(ip)
	if ip == nil {
		return false
	}
	_, ok = snapshot.ips[ip.String()]
	return ok
}

func normalizeSSRFDialHost(host string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
}

// normalizeSSRFDialPort trims surrounding whitespace from a port token. Every
// current producer (net.SplitHostPort and url.URL.Port) already yields a bare
// port, so no digit stripping is needed. It intentionally does not
// scheme-default an empty value: callers that know the scheme resolve the
// default before recording, and an unknown port stays empty so it never
// spuriously matches or mismatches a real port.
func normalizeSSRFDialPort(port string) string {
	return strings.TrimSpace(port)
}

// effectiveURLPort returns the explicit port of a URL, or the scheme default
// for http/https/ws/wss, so the SSRF scan snapshot and the later dial agree on
// a concrete port even when the URL omitted it.
func effectiveURLPort(u *url.URL) string {
	if u == nil {
		return ""
	}
	if p := u.Port(); p != "" {
		return p
	}
	switch strings.ToLower(u.Scheme) {
	case "https", "wss":
		return "443"
	case "http", "ws":
		return "80"
	default:
		return ""
	}
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
