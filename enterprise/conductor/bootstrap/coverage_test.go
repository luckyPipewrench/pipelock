//go:build enterprise

// Copyright 2026 Pipelock contributors
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package bootstrap

import (
	"bytes"
	"context"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

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

// TestWriteQuickstartEnrollmentStep pins the enrollment step's operator
// contract. Every assertion here corresponds to a way the walkthrough actually
// went wrong: a follower that never enrolled because the runbook did not mint a
// token, a token written world-readable under a permissive umask, a path with a
// space that broke the pasted command, and a 409 that could not be recovered
// because `conductor enroll` had been run first.
func TestWriteQuickstartEnrollmentStep(t *testing.T) {
	// Each base directory is a character class that breaks a different one of the
	// two escaping mechanisms in the generated step. A space breaks an unquoted
	// shell word; a single quote breaks naive shell quoting; a double quote or a
	// backslash breaks a hand-wrapped YAML value. The paths are joined from the
	// base rather than written as literals so gosec does not read a *.token path
	// as a credential.
	bases := []struct {
		name string
		dir  string
	}{
		{name: "plain", dir: "/fleet"},
		{name: "space", dir: "/fleet dir"},
		{name: "single quote", dir: "/fleet's dir"},
		{name: "double quote", dir: `/fleet "q" dir`},
		{name: "backslash", dir: `/fleet\dir`},
		{name: "shell metacharacters", dir: "/fleet;$(id)`id`dir"},
	}

	for _, b := range bases {
		t.Run(b.name, func(t *testing.T) {
			bundleDir := filepath.Join(b.dir, "follower/bundles")
			tokenPath := filepath.Join(bundleDir, "enrollment.token")
			adminToken := filepath.Join(b.dir, "conductor/admin.token")
			caCert := filepath.Join(b.dir, "ca/ca.crt")

			var out bytes.Buffer
			writeQuickstart(&out, &Result{
				Layout: Layout{
					Dir:                    b.dir,
					CACertPath:             caCert,
					AdminTokenPath:         adminToken,
					FollowerClientCertPath: filepath.Join(b.dir, "follower/client.crt"),
					FollowerClientKeyPath:  filepath.Join(b.dir, "follower/client.key"),
					FollowerBundleCacheDir: bundleDir,
					FollowerConfigPath:     filepath.Join(b.dir, "follower/follower.yaml"),
					LicenseTokenPath:       filepath.Join(b.dir, "license/license.token"),
				},
				Identity:      controlplane.FollowerIdentity{OrgID: "org", FleetID: "fleet", InstanceID: "inst", Environment: "dev"},
				TrustDomain:   "custom.example",
				ConductorID:   "conductor-dev",
				ConductorURL:  "https://127.0.0.1:8895",
				LicensePubHex: strings.Repeat("a", 64),
			})
			got := out.String()

			for _, want := range []string{
				// The token is minted rather than assumed to exist, and it is
				// minted under a restrictive umask with the target removed
				// first, so a rerun cannot truncate a permissive file in place.
				"(umask 077 && rm -f " + shellQuote(tokenPath) + " && pipelock conductor enrollment-token mint",
				"--ttl 1h > " + shellQuote(tokenPath) + ")",
				"--admin-token-file " + shellQuote(adminToken),
				"--server-ca " + shellQuote(caCert),
				// The ordering trap that makes auto-enrolment fail 409 for good.
				"Do NOT run `conductor enroll` first",
			} {
				if !strings.Contains(got, want) {
					t.Fatalf("quickstart missing %q\n%s", want, got)
				}
			}

			// Every quoted path must round-trip through a REAL shell back to the
			// exact path, because "pasteable" is a claim about what /bin/sh does,
			// not about what the string looks like. A quoting bug that still
			// contains the right substring passes the checks above and fails
			// here. printf %s is used so the shell reports exactly one word.
			for _, p := range []string{tokenPath, adminToken, caCert} {
				// Handing the string to a real shell is the assertion, not an
				// oversight: the claim under test is what /bin/sh does with the
				// quoted path. The script arrives on STDIN rather than as an
				// argument, so the command line itself carries no interpolated
				// value while the shell still does the parsing.
				cmd := exec.CommandContext(t.Context(), "/bin/sh")
				cmd.Stdin = strings.NewReader("printf %s " + shellQuote(p))
				parsed, err := cmd.Output()
				if err != nil {
					t.Fatalf("shell rejected the quoted form of %q: %v", p, err)
				}
				if string(parsed) != p {
					t.Fatalf("shell parsed the quoted form of %q back as %q", p, parsed)
				}
			}

			// The generated config line must be valid YAML AND decode back to
			// the same path the token was written to. A hand-wrapped value can
			// satisfy neither for a path containing a quote or a backslash.
			line := enrollmentTokenPathLine(t, got)
			var decoded struct {
				Path string `yaml:"enrollment_token_path"`
			}
			if err := yaml.Unmarshal([]byte(line), &decoded); err != nil {
				t.Fatalf("generated config line is not valid YAML: %v\nline: %s", err, line)
			}
			if decoded.Path != tokenPath {
				t.Fatalf("enrollment_token_path decoded to %q, want %q\nline: %s", decoded.Path, tokenPath, line)
			}
		})
	}
}

// enrollmentTokenPathLine extracts the generated enrollment_token_path line with
// its leading indentation removed, so it can be parsed as a standalone YAML
// mapping.
func enrollmentTokenPathLine(t *testing.T, quickstart string) string {
	t.Helper()
	for _, line := range strings.Split(quickstart, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "enrollment_token_path:") {
			return trimmed
		}
	}
	t.Fatalf("quickstart contains no enrollment_token_path line:\n%s", quickstart)
	return ""
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

func TestProofCaller_QueryBatchRejectsSubstringAndDuplicateJSON(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{name: "substring", body: `{"batches":[{"batch_id":"prefix-proof-target-suffix"}],"count":1}`},
		{name: "duplicate count", body: `{"batches":[],"count":0,"count":1}`},
		{name: "count mismatch", body: `{"batches":[],"count":1}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(tt.body))
			}))
			defer server.Close()
			caller := &proofCaller{client: server.Client(), baseURL: server.URL}
			ok, err := caller.queryBatch(context.Background(), controlplane.FollowerIdentity{}, "token", "proof-target")
			if err == nil || ok {
				t.Fatalf("queryBatch() = (%v, %v), want false and error", ok, err)
			}
		})
	}
}

func TestReadProofResponseRejectsOversize(t *testing.T) {
	if _, err := readProofResponse(strings.NewReader("12345"), 4); err == nil {
		t.Fatal("readProofResponse accepted oversized response")
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
