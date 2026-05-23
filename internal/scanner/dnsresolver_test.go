package scanner

import (
	"context"
	"errors"
	"testing"
)

type fakeResolver struct {
	hosts map[string][]string
	err   error
}

func (f *fakeResolver) LookupHost(_ context.Context, host string) ([]string, error) {
	if f.err != nil {
		return nil, f.err
	}
	ips, ok := f.hosts[host]
	if !ok {
		return nil, errors.New("not found")
	}
	return ips, nil
}

func TestStaticOverrideResolver_HostnameOverrideReturnsConfiguredIPs(t *testing.T) {
	upstream := &fakeResolver{hosts: map[string][]string{"upstream.test": {"203.0.113.7"}}}
	r := NewStaticOverrideResolver(
		map[string][]string{
			"aeb-fixture.test": {"127.0.0.1"},
		},
		upstream,
	)
	got, err := r.LookupHost(context.Background(), "aeb-fixture.test")
	if err != nil {
		t.Fatalf("LookupHost: %v", err)
	}
	if len(got) != 1 || got[0] != "127.0.0.1" {
		t.Errorf("got %v, want [127.0.0.1]", got)
	}
}

func TestStaticOverrideResolver_HostnameNormalizationLowerAndTrailingDot(t *testing.T) {
	upstream := &fakeResolver{}
	r := NewStaticOverrideResolver(
		map[string][]string{
			"AEB-Fixture.Test.": {"127.0.0.1"},
		},
		upstream,
	)
	for _, q := range []string{"aeb-fixture.test", "AEB-FIXTURE.TEST", "aeb-fixture.test."} {
		got, err := r.LookupHost(context.Background(), q)
		if err != nil {
			t.Fatalf("LookupHost(%q): %v", q, err)
		}
		if len(got) != 1 || got[0] != "127.0.0.1" {
			t.Errorf("LookupHost(%q) = %v, want [127.0.0.1]", q, got)
		}
	}
}

func TestStaticOverrideResolver_UnknownHostnameDelegatesToUpstream(t *testing.T) {
	upstream := &fakeResolver{hosts: map[string][]string{"real.test": {"203.0.113.9"}}}
	r := NewStaticOverrideResolver(
		map[string][]string{"aeb-fixture.test": {"127.0.0.1"}},
		upstream,
	)
	got, err := r.LookupHost(context.Background(), "real.test")
	if err != nil {
		t.Fatalf("LookupHost: %v", err)
	}
	if len(got) != 1 || got[0] != "203.0.113.9" {
		t.Errorf("got %v, want [203.0.113.9]", got)
	}
}

func TestStaticOverrideResolver_IPLiteralBypassesOverride(t *testing.T) {
	// Critical security property: IP literals must NEVER hit the override
	// map. Otherwise an operator could accidentally exempt SSRF-relevant
	// IPs through a hostname-targeted mapping. A request to "127.0.0.1"
	// goes straight to the upstream resolver regardless of any override
	// that happens to map to 127.0.0.1.
	upstream := &fakeResolver{hosts: map[string][]string{"127.0.0.1": {"127.0.0.1"}}}
	r := NewStaticOverrideResolver(
		map[string][]string{
			// This map has the IP as both a key and a value; only the
			// upstream answer must be observed for an IP-literal lookup.
			"aeb-fixture.test": {"127.0.0.1"},
		},
		upstream,
	)
	got, err := r.LookupHost(context.Background(), "127.0.0.1")
	if err != nil {
		t.Fatalf("LookupHost: %v", err)
	}
	if len(got) != 1 || got[0] != "127.0.0.1" {
		t.Errorf("got %v, want [127.0.0.1]", got)
	}
}

func TestStaticOverrideResolver_TrailingDotIPLiteralBypassesOverride(t *testing.T) {
	upstream := &fakeResolver{hosts: map[string][]string{"127.0.0.1.": {"198.51.100.7"}}}
	r := NewStaticOverrideResolver(
		map[string][]string{
			"127.0.0.1.": {"127.0.0.1"},
		},
		upstream,
	)
	got, err := r.LookupHost(context.Background(), "127.0.0.1.")
	if err != nil {
		t.Fatalf("LookupHost: %v", err)
	}
	if len(got) != 1 || got[0] != "198.51.100.7" {
		t.Errorf("got %v, want upstream [198.51.100.7]; trailing-dot IP literal must not hit overrides", got)
	}
}

func TestStaticOverrideResolver_EmptyOverridesPassesThrough(t *testing.T) {
	upstream := &fakeResolver{hosts: map[string][]string{"example.com": {"93.184.216.34"}}}
	r := NewStaticOverrideResolver(nil, upstream)
	got, err := r.LookupHost(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("LookupHost: %v", err)
	}
	if len(got) != 1 || got[0] != "93.184.216.34" {
		t.Errorf("got %v, want [93.184.216.34]", got)
	}
}

func TestStaticOverrideResolver_NilUpstreamDefaultsToSystem(t *testing.T) {
	// Construction must not panic with a nil upstream; the resolver should
	// quietly install net.DefaultResolver. We don't actually call
	// LookupHost on the system resolver to keep the test hermetic.
	r := NewStaticOverrideResolver(map[string][]string{"x.test": {"127.0.0.1"}}, nil)
	if r.upstream == nil {
		t.Fatal("upstream was nil after construction")
	}
	got, err := r.LookupHost(context.Background(), "x.test")
	if err != nil {
		t.Fatalf("LookupHost(override): %v", err)
	}
	if len(got) != 1 || got[0] != "127.0.0.1" {
		t.Errorf("override lookup = %v, want [127.0.0.1]", got)
	}
}

func TestStaticOverrideResolver_CallerMutationDoesNotLeak(t *testing.T) {
	// If a caller mutates the IPs slice they passed in after construction,
	// the resolver's stored values must remain unchanged.
	ips := []string{"127.0.0.1"}
	r := NewStaticOverrideResolver(
		map[string][]string{"aeb-fixture.test": ips},
		&fakeResolver{},
	)
	ips[0] = "8.8.8.8" // simulated post-construction mutation by caller
	got, err := r.LookupHost(context.Background(), "aeb-fixture.test")
	if err != nil {
		t.Fatalf("LookupHost: %v", err)
	}
	if len(got) != 1 || got[0] != "127.0.0.1" {
		t.Errorf("got %v, want [127.0.0.1] (caller mutation must not affect resolver state)", got)
	}
}
