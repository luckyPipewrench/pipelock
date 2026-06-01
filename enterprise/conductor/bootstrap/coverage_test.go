//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package bootstrap

import (
	"bytes"
	"context"
	"crypto/x509"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/enterprise/conductor/controlplane"
	"github.com/luckyPipewrench/pipelock/internal/certgen"
)

func mustSelfCA(t *testing.T) *x509.Certificate {
	t.Helper()
	cert, _, _, err := certgen.GenerateCA("test", time.Hour)
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	return cert
}

func TestValidateOptions(t *testing.T) {
	valid := Options{
		Dir:           "x",
		TrustDomain:   defaultTrustDomain,
		OrgID:         "o",
		FleetID:       "f",
		InstanceID:    "i",
		Environment:   "e",
		ConductorID:   "c",
		ListenHost:    "127.0.0.1",
		ConductorPort: 8895,
		Validity:      time.Hour,
	}
	cases := []struct {
		name string
		opts Options
		ok   bool
	}{
		{"valid", valid, true},
		{"empty dir", withOption(valid, func(o *Options) { o.Dir = "" }), false},
		{"bad trust domain", withOption(valid, func(o *Options) { o.TrustDomain = "bad/domain" }), false},
		{"public listen host", withOption(valid, func(o *Options) { o.ListenHost = "0.0.0.0" }), false},
		{"listen host injection", withOption(valid, func(o *Options) { o.ListenHost = "localhost\n--admin-token-file=/tmp/x" }), false},
		{"port low", withOption(valid, func(o *Options) { o.ConductorPort = 0 }), false},
		{"port high", withOption(valid, func(o *Options) { o.ConductorPort = 70000 }), false},
		{"bad conductor id", withOption(valid, func(o *Options) { o.ConductorID = "-bad" }), false},
		{"bad org", withOption(valid, func(o *Options) { o.OrgID = "-bad" }), false},
		{"bad fleet", withOption(valid, func(o *Options) { o.FleetID = "bad/slash" }), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := validateOptions(c.opts)
			if c.ok && err != nil {
				t.Fatalf("validateOptions(%+v) = %v, want nil", c.opts, err)
			}
			if !c.ok && err == nil {
				t.Fatalf("validateOptions(%+v) = nil, want error", c.opts)
			}
		})
	}
}

func withOption(base Options, edit func(*Options)) Options {
	edit(&base)
	return base
}

func TestNormalizeDefaults(t *testing.T) {
	var o Options
	o.Dir = "x"
	normalize(&o)
	if o.TrustDomain != defaultTrustDomain || o.OrgID != defaultOrgID || o.FleetID != defaultFleetID ||
		o.InstanceID != defaultInstanceID || o.Environment != defaultEnvironment || o.ConductorID != defaultConductorID ||
		o.ListenHost != defaultListenHost || o.ConductorPort != defaultConductorPort || o.Validity != defaultValidity {
		t.Fatalf("normalize defaults not applied: %+v", o)
	}
	if o.Now == nil || o.Out == nil {
		t.Fatal("normalize left Now/Out nil")
	}
	if got := o.conductorURL(); got != "https://127.0.0.1:8895" {
		t.Fatalf("conductorURL = %q", got)
	}
	o.ListenHost = "::1"
	if got := o.conductorURL(); got != "https://[::1]:8895" {
		t.Fatalf("conductorURL(IPv6) = %q", got)
	}
}

func TestFollowerSPIFFEID_Errors(t *testing.T) {
	good := controlplane.FollowerIdentity{OrgID: "o", FleetID: "f", InstanceID: "i", Environment: "e"}
	if _, err := followerSPIFFEID("", good); err == nil {
		t.Fatal("empty trust domain should error")
	}
	if _, err := followerSPIFFEID("pipelock.local", controlplane.FollowerIdentity{OrgID: "-bad"}); err == nil {
		t.Fatal("invalid identity should error")
	}
	if _, err := followerSPIFFEID("pipelock.local", good); err != nil {
		t.Fatalf("valid identity errored: %v", err)
	}
}

func TestTrimScheme(t *testing.T) {
	if got := trimScheme("https://127.0.0.1:8895"); got != "127.0.0.1:8895" {
		t.Fatalf("trimScheme(https) = %q", got)
	}
	if got := trimScheme("127.0.0.1:8895"); got != "127.0.0.1:8895" {
		t.Fatalf("trimScheme(no scheme) = %q", got)
	}
}

func TestWriteQuickstartIncludesIdentityFlags(t *testing.T) {
	var out bytes.Buffer
	writeQuickstart(&out, &Result{
		Layout: Layout{
			Dir:                     "/fleet",
			ConductorStorageDir:     "/fleet/conductor/storage",
			ConductorServerCertPath: "/fleet/conductor/server.crt",
			ConductorServerKeyPath:  "/fleet/conductor/server.key",
			CACertPath:              "/fleet/ca/ca.crt",
			PublisherTokenPath:      "/fleet/conductor/publisher.token",
			AuditorTokenPath:        "/fleet/conductor/auditor.token",
			AdminTokenPath:          "/fleet/conductor/admin.token",
			RemoteKillPubPath:       "/fleet/trust/remote-kill.pub",
			RollbackPubPath:         "/fleet/trust/rollback.pub",
			FollowerConfigPath:      "/fleet/follower/follower.yaml",
			LicenseTokenPath:        "/fleet/license/license.token",
		},
		Identity:        controlplane.FollowerIdentity{OrgID: "org", FleetID: "fleet", InstanceID: "inst", Environment: "dev"},
		TrustDomain:     "custom.example",
		ConductorID:     "conductor-dev",
		ConductorURL:    "https://127.0.0.1:8895",
		RootFingerprint: "sha256:test",
		LicensePubHex:   strings.Repeat("a", 64),
	})
	got := out.String()
	for _, want := range []string{
		"--conductor-id conductor-dev",
		"--follower-trust-domain custom.example",
		"spiffe://custom.example/orgs/org/fleets/fleet/instances/inst/environments/dev",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("quickstart missing %q\n%s", want, got)
		}
	}
}

func TestSnippet(t *testing.T) {
	if got := snippet([]byte("  hi  ")); got != "hi" {
		t.Fatalf("snippet trim = %q", got)
	}
	long := strings.Repeat("a", 400)
	got := snippet([]byte(long))
	if len(got) == 0 || !strings.HasSuffix(got, "…") {
		t.Fatalf("snippet long did not truncate: len=%d", len(got))
	}
}

func TestListenIPs(t *testing.T) {
	if ips := listenIPs("127.0.0.1"); len(ips) != 1 {
		t.Fatalf("listenIPs(ip) = %v, want one IP", ips)
	}
	if ips := listenIPs("localhost"); ips != nil {
		t.Fatalf("listenIPs(hostname) = %v, want nil", ips)
	}
}

func TestRun_RejectsEmptyDir(t *testing.T) {
	if _, err := Run(context.Background(), Options{}); err == nil {
		t.Fatal("Run with empty dir should error")
	}
}

func TestRun_ForceRegenerates(t *testing.T) {
	dir := privateFleetDir(t)
	first, err := Run(context.Background(), Options{Dir: dir, SkipProof: true})
	if err != nil {
		t.Fatalf("first Run: %v", err)
	}
	caBefore, err := os.ReadFile(first.Layout.CACertPath)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Run(context.Background(), Options{Dir: dir, SkipProof: true, Force: true})
	if err != nil {
		t.Fatalf("forced Run: %v", err)
	}
	if second.Reused {
		t.Fatal("forced Run reported reused material")
	}
	caAfter, err := os.ReadFile(first.Layout.CACertPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(caBefore) == string(caAfter) {
		t.Fatal("--force did not regenerate the CA")
	}
}

func TestRun_GenerationFailsClosedOnBlockedPath(t *testing.T) {
	dir := privateFleetDir(t)
	if err := os.MkdirAll(dir, dirPerm); err != nil {
		t.Fatal(err)
	}
	layout, err := newLayout(dir)
	if err != nil {
		t.Fatal(err)
	}
	// Plant a regular file where the CA directory must be created; MkdirAll
	// then fails and generation must fail closed.
	if err := os.MkdirAll(layout.Dir, dirPerm); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(layout.Dir+"/ca", []byte("not a dir"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Run(context.Background(), Options{Dir: dir, SkipProof: true}); err == nil {
		t.Fatal("generation into a blocked CA path should fail closed")
	}
}

func TestRun_ReuseLoadFailsOnCorruptCA(t *testing.T) {
	dir := privateFleetDir(t)
	res, err := Run(context.Background(), Options{Dir: dir, SkipProof: true})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	// Corrupt the CA so the reuse load path fails closed.
	if err := os.WriteFile(res.Layout.CACertPath, []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Run(context.Background(), Options{Dir: dir, SkipProof: true}); err == nil {
		t.Fatal("reuse with corrupt CA should fail closed")
	}
}

func TestAwaitCapabilities_FailsClosed(t *testing.T) {
	client := newFollowerHTTPClient(&materialSet{caCert: mustSelfCA(t)}, "127.0.0.1")
	caller := &proofCaller{client: client, baseURL: "https://127.0.0.1:1"}
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	if err := caller.awaitCapabilities(ctx); err == nil {
		t.Fatal("awaitCapabilities against a dead endpoint should error")
	}
}

func TestProofCaller_QueryBatchRejectsMissing(t *testing.T) {
	h := newHarness(t)
	h.enroll(t)
	// Query before any batch is ingested: the proof batch id is absent.
	ok, err := h.caller.queryBatch(context.Background(), h.identity, h.material.auditorToken, "audit-does-not-exist")
	if err == nil && ok {
		t.Fatal("queryBatch should not report a missing batch as present")
	}
}

func TestProofCaller_DoRejectsBadMethod(t *testing.T) {
	c := &proofCaller{client: http.DefaultClient, baseURL: "://bad"}
	resp, err := c.do(context.Background(), "BAD METHOD", "/x", "", nil)
	if err == nil {
		_ = resp.Body.Close()
		t.Fatal("do with an invalid method/URL should error")
	}
}
