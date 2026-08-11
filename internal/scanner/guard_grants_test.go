// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"net/url"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/destination"
)

func TestGuardDestinationGrantIsExactAndActivatesDNSFloor(t *testing.T) {
	t.Parallel()

	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.Mode = config.ModeStrict
	cfg.APIAllowlist = []string{"public.vendor.example"}
	cfg.DNS.HostOverrides = map[string][]string{
		"db.internal.example": {"127.0.0.1"},
	}
	grant, err := destination.NewGrant(destination.NetworkTCP, "db.internal.example", 5432)
	if err != nil {
		t.Fatalf("NewGrant: %v", err)
	}
	grants, err := destination.NewGrantSet(grant)
	if err != nil {
		t.Fatalf("NewGrantSet: %v", err)
	}
	s, err := NewWithOptions(cfg, Options{DestinationGrants: grants})
	if err != nil {
		t.Fatalf("NewWithOptions: %v", err)
	}
	defer s.Close()

	allowed := s.Scan(context.Background(), "https://db.internal.example:5432/health")
	if !allowed.Allowed {
		t.Fatalf("exact guard grant blocked: %+v", allowed)
	}
	if len(allowed.SSRFResolvedIPs) != 1 || allowed.SSRFResolvedIPs[0] != "127.0.0.1" {
		t.Fatalf("guard-granted DNS snapshot = %#v, want internal answer retained", allowed.SSRFResolvedIPs)
	}

	wrongPort := s.Scan(context.Background(), "https://db.internal.example:443/health")
	if wrongPort.Allowed {
		t.Fatal("host grant authorized the wrong port")
	}
	if wrongPort.Scanner != ScannerAllowlist {
		t.Fatalf("wrong-port scanner = %q, want strict allowlist refusal", wrongPort.Scanner)
	}
}

func TestGuardDestinationHelpersFailClosed(t *testing.T) {
	cfg := config.Defaults()
	s := MustNew(cfg)
	defer s.Close()
	if s.IsDestinationGranted(destination.NetworkTCP, "bad host", 443) {
		t.Fatal("malformed destination was granted")
	}
	for _, testCase := range []struct {
		name string
		url  *url.URL
		ok   bool
		port uint16
	}{
		{name: "nil"},
		{name: "http default", url: &url.URL{Scheme: "http"}, ok: true, port: 80},
		{name: "https default", url: &url.URL{Scheme: "https"}, ok: true, port: 443},
		{name: "unsupported scheme", url: &url.URL{Scheme: "ftp"}},
		{name: "invalid port", url: &url.URL{Scheme: "https", Host: "vendor.example:0"}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			got, ok := urlDestination(testCase.url, "vendor.example")
			if ok != testCase.ok || ok && got.Port != testCase.port {
				t.Fatalf("destination = %+v, ok=%t", got, ok)
			}
		})
	}
	result := s.Scan(context.Background(), "https://vendor.example:0/")
	if result.Allowed || result.Scanner != ScannerParser {
		t.Fatalf("zero-port scan result = %+v", result)
	}
}

func TestGuardLiteralGrantDoesNotBroadenSiblingPort(t *testing.T) {
	t.Parallel()

	cfg := config.Defaults()
	cfg.Internal = nil
	grant, err := destination.NewGrant(destination.NetworkTCP, "127.0.0.1", 8080)
	if err != nil {
		t.Fatalf("NewGrant: %v", err)
	}
	grants, err := destination.NewGrantSet(grant)
	if err != nil {
		t.Fatalf("NewGrantSet: %v", err)
	}
	s, err := NewWithOptions(cfg, Options{DestinationGrants: grants})
	if err != nil {
		t.Fatalf("NewWithOptions: %v", err)
	}
	defer s.Close()

	exactDest, err := destination.New(destination.NetworkTCP, "127.0.0.1", 8080)
	if err != nil {
		t.Fatalf("exact destination: %v", err)
	}
	if result := s.checkCoreSSRFLiteral(exactDest); !result.Allowed {
		t.Fatalf("core literal floor blocked exact grant: %+v", result)
	}
	siblingDest, err := destination.New(destination.NetworkTCP, "127.0.0.1", 8081)
	if err != nil {
		t.Fatalf("sibling destination: %v", err)
	}
	if result := s.checkCoreSSRFLiteral(siblingDest); result.Allowed {
		t.Fatal("core literal floor authorized a sibling port")
	}

	if result := s.Scan(context.Background(), "http://127.0.0.1:8080/"); !result.Allowed {
		t.Fatalf("exact literal grant blocked: %+v", result)
	}
	if result := s.Scan(context.Background(), "http://127.0.0.1:8081/"); result.Allowed {
		t.Fatal("literal grant authorized a sibling port")
	}
}

func TestGuardHostnameGrantCannotOverrideMetadataResolution(t *testing.T) {
	t.Parallel()
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DNS.HostOverrides = map[string][]string{
		"metadata.internal.example": {"169.254.169.254"},
	}
	grant, err := destination.NewGrant(destination.NetworkTCP, "metadata.internal.example", 80)
	if err != nil {
		t.Fatalf("NewGrant: %v", err)
	}
	grants, err := destination.NewGrantSet(grant)
	if err != nil {
		t.Fatalf("NewGrantSet: %v", err)
	}
	s, err := NewWithOptions(cfg, Options{DestinationGrants: grants})
	if err != nil {
		t.Fatalf("NewWithOptions: %v", err)
	}
	defer s.Close()
	result := s.Scan(context.Background(), "http://metadata.internal.example/")
	if result.Allowed || result.Scanner != ScannerSSRFMetadata {
		t.Fatalf("metadata-resolving grant result = %+v, want metadata refusal", result)
	}
}
