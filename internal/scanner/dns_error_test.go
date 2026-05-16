// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
)

func TestClassifyDNSError_TimeoutKind(t *testing.T) {
	t.Parallel()
	err := &net.DNSError{
		Err:       "i/o timeout",
		Name:      "openrouter.ai",
		Server:    "127.0.0.53:53",
		IsTimeout: true,
	}
	kind, reason := classifyDNSError("openrouter.ai", err)
	if kind != DNSErrorTimeout {
		t.Fatalf("kind = %q, want %q", kind, DNSErrorTimeout)
	}
	if !strings.Contains(reason, "timed out") {
		t.Errorf("reason should mention timed out, got %q", reason)
	}
	if strings.Contains(reason, "SSRF check failed") {
		t.Errorf("reason must not lead with SSRF check failed on a timeout: %q", reason)
	}
}

func TestClassifyDNSError_NoSuchHostKind(t *testing.T) {
	t.Parallel()
	err := &net.DNSError{
		Err:        "no such host",
		Name:       "invalid.example.com",
		Server:     "127.0.0.53:53",
		IsNotFound: true,
	}
	kind, reason := classifyDNSError("invalid.example.com", err)
	if kind != DNSErrorNoSuchHost {
		t.Fatalf("kind = %q, want %q", kind, DNSErrorNoSuchHost)
	}
	if !strings.Contains(reason, "no such host") {
		t.Errorf("reason should mention no such host, got %q", reason)
	}
	if strings.Contains(reason, "SSRF check failed") {
		t.Errorf("reason must not lead with SSRF check failed on NXDOMAIN: %q", reason)
	}
}

func TestClassifyDNSError_TemporaryKind(t *testing.T) {
	t.Parallel()
	err := &net.DNSError{
		Err:         "server misbehaving",
		Name:        "example.com",
		Server:      "127.0.0.53:53",
		IsTemporary: true,
	}
	kind, reason := classifyDNSError("example.com", err)
	if kind != DNSErrorResolver {
		t.Fatalf("kind = %q, want %q (temporary maps to resolver_error)", kind, DNSErrorResolver)
	}
	if !strings.Contains(reason, "temporary resolver error") {
		t.Errorf("reason should mention temporary resolver error, got %q", reason)
	}
}

func TestClassifyDNSError_OtherResolverKind(t *testing.T) {
	t.Parallel()
	err := &net.DNSError{
		Err:    "DNS message format error",
		Name:   "example.com",
		Server: "127.0.0.53:53",
	}
	kind, _ := classifyDNSError("example.com", err)
	if kind != DNSErrorResolver {
		t.Fatalf("kind = %q, want %q", kind, DNSErrorResolver)
	}
}

func TestClassifyDNSError_NonDNSErrorFallsBackToResolver(t *testing.T) {
	t.Parallel()
	err := errors.New("some non-DNS wrapper error")
	kind, reason := classifyDNSError("example.com", err)
	if kind != DNSErrorResolver {
		t.Errorf("non-net.DNSError must classify as resolver_error, got %q", kind)
	}
	if !strings.Contains(reason, "example.com") {
		t.Errorf("reason should include the hostname, got %q", reason)
	}
}

// TestClassifyDNSError_NilErr is a defensive check: the call site only runs
// on err != nil, but classifyDNSError must not crash if called with nil and
// must produce a fail-closed Result-friendly kind.
func TestClassifyDNSError_NilErr(t *testing.T) {
	t.Parallel()
	kind, reason := classifyDNSError("example.com", nil)
	if kind != DNSErrorResolver {
		t.Errorf("nil err must map to resolver_error, got %q", kind)
	}
	if reason == "" {
		t.Error("reason must not be empty even on nil err")
	}
}

// TestClassifyDNSError_WrappedDNSError covers errors.As unwrapping a wrapped
// *net.DNSError so callers that funnel resolver failures through fmt.Errorf
// "%w" still get the right kind.
func TestClassifyDNSError_WrappedDNSError(t *testing.T) {
	t.Parallel()
	inner := &net.DNSError{
		Err:        "no such host",
		Name:       "missing.example",
		Server:     "127.0.0.53:53",
		IsNotFound: true,
	}
	wrapped := fmt.Errorf("resolver path: %w", inner)
	kind, _ := classifyDNSError("missing.example", wrapped)
	if kind != DNSErrorNoSuchHost {
		t.Errorf("errors.As must unwrap; got kind %q want %q", kind, DNSErrorNoSuchHost)
	}
}
