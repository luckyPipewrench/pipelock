// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package playground_test

import (
	"context"
	"net"
	"os"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/playground"
)

// --------------------------------------------------------------------------
// Probe classification tests (unit-testable without containment)
// --------------------------------------------------------------------------

func TestEgressProbe_OpenTarget_ClassifiedOpen(t *testing.T) {
	t.Parallel()

	// Start a local TCP listener on a free port -- this IS reachable.
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	// Accept connections so the probe can connect.
	go func() {
		for {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return // listener closed
			}
			_ = conn.Close()
		}
	}()

	result := playground.ProbeDirectEgress(t.Context(), ln.Addr().String())
	if !result.Open {
		t.Fatalf("probe to an open listener must classify as Open, got: %+v", result)
	}
	if result.Blocked {
		t.Fatalf("probe to an open listener must not classify as Blocked, got: %+v", result)
	}
	if result.Target != ln.Addr().String() {
		t.Fatalf("target mismatch: want %q, got %q", ln.Addr().String(), result.Target)
	}
}

func TestEgressProbe_RefusedTarget_NotBlocked(t *testing.T) {
	t.Parallel()

	// 127.0.0.1:1 -- port 1 is almost never listening; connection refused is
	// the expected outcome on loopback. Refused means reachable, not blocked.
	result := playground.ProbeDirectEgress(t.Context(), "127.0.0.1:1")
	if result.Open || result.Blocked {
		t.Fatalf("probe to a refused target must be Open=false Blocked=false, got: %+v", result)
	}
}

func TestEgressProbe_ContextCancelled_NotBlocked(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	cancel() // cancel immediately

	result := playground.ProbeDirectEgress(ctx, "127.0.0.1:1")
	if result.Open || result.Blocked {
		t.Fatalf("probe with cancelled context must be Open=false Blocked=false, got: %+v", result)
	}
}

// --------------------------------------------------------------------------
// Self-test detection tests (unit-testable without containment)
// --------------------------------------------------------------------------

func TestSelfTest_DetectsOpenRoutes_WhenUncontained(t *testing.T) {
	t.Parallel()

	// In an uncontained test environment, at least some of the self-test
	// targets should be reachable (e.g. loopback ports, or public DNS if
	// the host has network access). But the key property: the self-test
	// must NOT report AllBlocked=true in an uncontained environment, because
	// that would be a false containment claim.
	//
	// We use a custom target list that includes one definitely-open target
	// (a local listener) to guarantee at least one is reachable.
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	go func() {
		for {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			_ = conn.Close()
		}
	}()

	targets := []string{
		ln.Addr().String(), // definitely open
		"127.0.0.1:1",      // definitely closed
	}

	res := playground.RunContainmentSelfTest(t.Context(), targets)

	if res.AllBlocked {
		t.Fatal("uncontained env with an open listener must NOT report AllBlocked " +
			"(would be a false containment claim)")
	}

	// Verify individual probe results are populated.
	if len(res.Probes) != len(targets) {
		t.Fatalf("expected %d probes, got %d", len(targets), len(res.Probes))
	}

	// The open listener probe must be classified Open.
	found := false
	for _, p := range res.Probes {
		if p.Target == ln.Addr().String() {
			found = true
			if !p.Open {
				t.Fatalf("probe to open listener must be Open, got: %+v", p)
			}
		}
	}
	if !found {
		t.Fatal("open listener target not found in probe results")
	}
}

func TestSelfTest_RefusedTargetsAreNotBlocked(t *testing.T) {
	t.Parallel()

	// Closed loopback ports are reachable enough to return ECONNREFUSED. That
	// is not containment: packets left the process and came back with a refusal.
	targets := []string{
		"127.0.0.1:1",
		"127.0.0.1:2",
	}

	res := playground.RunContainmentSelfTest(t.Context(), targets)

	if res.AllBlocked {
		t.Fatal("connection-refused targets must NOT prove AllBlocked=true")
	}

	for _, p := range res.Probes {
		if p.Open {
			t.Fatalf("probe %q unexpectedly classified as Open", p.Target)
		}
		if p.Blocked {
			t.Fatalf("probe %q was refused but classified as blocked: %s", p.Target, p.Detail)
		}
	}
}

func TestSelfTest_EmptyTargets_AllBlocked(t *testing.T) {
	t.Parallel()

	// Edge case: no targets -> vacuously all blocked (no open routes).
	res := playground.RunContainmentSelfTest(t.Context(), nil)
	if !res.AllBlocked {
		t.Fatal("empty target list must report AllBlocked=true (vacuous truth)")
	}
	if len(res.Probes) != 0 {
		t.Fatalf("expected 0 probes, got %d", len(res.Probes))
	}
}

// --------------------------------------------------------------------------
// Dual suite definition tests
// --------------------------------------------------------------------------

func TestEgressSuites_Defined(t *testing.T) {
	t.Parallel()

	direct := playground.DirectEgressTargets()
	mediated := playground.MediatedProxyPolicyTargets()

	if len(direct) == 0 {
		t.Fatal("DirectEgressTargets must define at least one target")
	}
	if len(mediated) == 0 {
		t.Fatal("MediatedProxyPolicyTargets must define at least one target")
	}

	// Verify direct targets are valid host:port pairs.
	for _, tgt := range direct {
		host, port, err := net.SplitHostPort(tgt)
		if err != nil {
			t.Fatalf("DirectEgressTargets entry %q is not a valid host:port: %v", tgt, err)
		}
		if host == "" || port == "" {
			t.Fatalf("DirectEgressTargets entry %q has empty host or port", tgt)
		}
	}
}

func TestDirectEgressTargets_CoversRequiredCategories(t *testing.T) {
	t.Parallel()

	targets := playground.DirectEgressTargets()

	// Check that the required categories are represented. IPv6 link-local is
	// intentionally NOT a required category: a [fe80::1] literal without a %zone
	// fails the dial with EINVAL before any packet leaves the host, so it can
	// never honestly prove an egress block (see DirectEgressTargets doc).
	categories := map[string]bool{
		"metadata":    false, // 169.254.169.254
		"rfc1918":     false, // 10.x.x.x
		"public_dns":  false, // 8.8.8.8 or 1.1.1.1
		"public_http": false, // any other public IP
	}

	for _, tgt := range targets {
		host, _, _ := net.SplitHostPort(tgt)
		// Strip brackets from IPv6
		if len(host) > 0 && host[0] == '[' {
			host = host[1 : len(host)-1]
		}
		switch {
		case host == "169.254.169.254":
			categories["metadata"] = true
		case len(host) > 3 && host[:3] == "10.":
			categories["rfc1918"] = true
		case host == "8.8.8.8" || host == "1.1.1.1":
			categories["public_dns"] = true
		case host == "93.184.216.34":
			categories["public_http"] = true
		}
	}

	for cat, found := range categories {
		if !found {
			t.Errorf("DirectEgressTargets missing required category: %s", cat)
		}
	}
}

// --------------------------------------------------------------------------
// RealContainmentHook unit tests (non-privileged behavior)
// --------------------------------------------------------------------------

func TestRealContainmentHook_Setup_FailsWithoutPrivileges(t *testing.T) {
	t.Parallel()

	if os.Geteuid() == 0 {
		t.Skip("test requires non-root to verify privilege check")
	}

	hook := playground.NewRealContainmentHook("")
	err := hook.Setup(t.Context(), playground.DemoOpts{
		Contained: true,
		RunDir:    t.TempDir(),
	})
	if err == nil {
		t.Fatal("Setup must fail without root privileges")
	}
}

func TestRealContainmentHook_Teardown_Succeeds(t *testing.T) {
	t.Parallel()

	hook := playground.NewRealContainmentHook("")
	if err := hook.Teardown(t.TempDir()); err != nil {
		t.Fatalf("Teardown must succeed (best-effort): %v", err)
	}
}

// --------------------------------------------------------------------------
// Contained end-to-end: PRIVILEGE-GATED host proof lives in the demo binary
// --------------------------------------------------------------------------
//
// The host-only kernel-containment proof is the DIFFERENTIAL split-proof, not
// an in-process self-test. Running RunContainmentSelfTest from the (root)
// operator process is the wrong model: containment drops the contained AGENT
// to uid 966 and kernel-blocks its egress, while the operator/root deliberately
// RETAINS egress (the control target). A root-process self-test would therefore
// fail for the wrong reason on a correctly contained host.
//
// The honest privileged proof is built and verified end-to-end by the demo
// binary (HostContainmentWitness, signed from a uid-966-dropped probe set) and
// is exercised by:
//   - TestHostContainmentWitness_Enforced       (DifferentialProven && DirectSuiteProven && AllAgentBlocked)
//   - TestAllAgentBlocked_HappyAndEmpty          (liverun_internal_test.go)
//   - TestVerify_Contained_NotEnforced_FailsClosed (containment_verify_test.go)
//   - `pipelock-playground-demo run --contained` + `... verify` on a real host.

func TestContainment_SelfTestGate_AbortsOnOpenRoutes(t *testing.T) {
	t.Parallel()

	// Simulate what happens when the self-test detects open routes:
	// the demo must abort with ErrContainmentSelfTestFailed.
	// We test this by checking that RunContainmentSelfTest correctly
	// reports AllBlocked=false when there are open routes, and verify
	// the error constant is usable for error wrapping.

	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	go func() {
		for {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			_ = conn.Close()
		}
	}()

	result := playground.RunContainmentSelfTest(t.Context(), []string{ln.Addr().String()})
	if result.AllBlocked {
		t.Fatal("self-test with an open listener must NOT report AllBlocked")
	}

	// Verify the error sentinel is available for wrapping/checking.
	wrapped := playground.ErrContainmentSelfTestFailed
	if wrapped == nil {
		t.Fatal("ErrContainmentSelfTestFailed must be non-nil")
	}
}
