// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/envelope"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// seedJSONBodySecret splits an AWS key across two appends on the JSON body
// stream that production would open for liveKey, then confirms it reassembles.
// It returns the exact body stream key so a later reset can be checked against
// the key PRODUCTION wrote, not the key reset happens to derive.
func seedJSONBodySecret(t *testing.T, fb *scanner.FragmentBuffer, sc *scanner.Scanner, liveKey string) string {
	t.Helper()
	buckets, _ := jsonBodyFragmentPayloads("application/json", []byte(`{"messages":[{"content":"value"}]}`), liveKey, testCEEPartitionKey)
	if len(buckets) != 1 {
		t.Fatalf("bucket count = %d, want 1", len(buckets))
	}
	var bucket string
	for bucket = range buckets {
	}
	bodyKey := ceeJSONBodyFragmentSessionKey(liveKey, bucket)
	if result := fb.Append(testCEEIdentity(bodyKey), []byte(testCEEAWSKeyPrefix)); result.CapacityExceeded {
		t.Fatal("first body fragment exceeded capacity")
	}
	if result := fb.Append(testCEEIdentity(bodyKey), []byte(testCEEAWSKeySuffix)); result.CapacityExceeded {
		t.Fatal("second body fragment exceeded capacity")
	}
	if matches := fb.ScanForSecrets(t.Context(), testCEEStream(bodyKey), sc); len(matches) == 0 {
		t.Fatal("control did not reassemble the JSON body stream")
	}
	return bodyKey
}

// A self-declared agent's CEE state lives under the folded (IP-only) live key,
// but the admin reset receives the adaptive key (agent|ip). Reset must clear the
// key PRODUCTION wrote. The expected key here is built through the live path's
// own derivation (ceeSessionKey with the self-declared grade), so a reset that
// targets a different key fails this test. Before the candidate-key fix, reset
// cleared only "agent|ip" and left the folded "ip" evidence intact.
func TestResetCEEStateClearsFoldedSelfDeclaredKey(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)

	const agent, ip = "myagent", "10.0.0.5"
	liveKey := ceeSessionKey(agent, ip, envelope.ActorAuthSelfDeclared)
	if liveKey == CeeSessionKey(agent, ip) {
		t.Fatalf("test premise broken: live key %q equals raw key; a self-declared agent must fold", liveKey)
	}

	fb := scanner.NewFragmentBuffer(1024, 10, 60)
	t.Cleanup(fb.Close)
	bodyKey := seedJSONBodySecret(t, fb, sc, liveKey)

	// Re-prime one fragment, reset, then complete the split. If reset cleared
	// the right stream the completing suffix cannot reassemble a secret.
	if result := fb.Append(testCEEIdentity(bodyKey), []byte(testCEEAWSKeyPrefix)); result.CapacityExceeded {
		t.Fatal("post-control first fragment exceeded capacity")
	}
	ResetCEEState(agent, ip, nil, fb)
	if result := fb.Append(testCEEIdentity(bodyKey), []byte(testCEEAWSKeySuffix)); result.CapacityExceeded {
		t.Fatal("post-reset second fragment exceeded capacity")
	}
	if matches := fb.ScanForSecrets(t.Context(), testCEEStream(bodyKey), sc); len(matches) != 0 {
		t.Fatalf("reset left the folded self-declared JSON body stream intact: %#v", matches)
	}
}

// The entropy tracker keys the same way, so a self-declared reset must also
// clear the folded entropy state.
func TestResetCEEStateClearsFoldedEntropyKey(t *testing.T) {
	const agent, ip = "myagent", "10.0.0.5"
	liveKey := ceeSessionKey(agent, ip, envelope.ActorAuthSelfDeclared)

	et := scanner.NewEntropyTracker(8, 60)
	t.Cleanup(et.Close)
	et.Record(testCEEIdentity(liveKey), []byte("aZ9$kQ2%mV7&pL0#xR4!wB6^tE1@nH3*"))
	if et.CurrentUsage(testCEEIdentity(liveKey)) == 0 {
		t.Fatal("control: entropy was not recorded under the live key")
	}
	ResetCEEState(agent, ip, et, nil)
	if got := et.CurrentUsage(testCEEIdentity(liveKey)); got != 0 {
		t.Fatalf("reset left folded entropy usage = %v, want 0", got)
	}
}

// A bound agent keeps its name in the live key. Reset clears the full candidate
// set, so it clears that named key too. This confirms the fix did not merely
// swap one shape for the other.
func TestResetCEEStateClearsBoundNamedKey(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)

	const agent, ip = "myagent", "10.0.0.7"
	liveKey := ceeSessionKey(agent, ip, envelope.ActorAuthBound)
	if liveKey != agent+"|"+ip {
		t.Fatalf("bound live key = %q, want %q", liveKey, agent+"|"+ip)
	}
	fb := scanner.NewFragmentBuffer(1024, 10, 60)
	t.Cleanup(fb.Close)
	bodyKey := seedJSONBodySecret(t, fb, sc, liveKey)

	if result := fb.Append(testCEEIdentity(bodyKey), []byte(testCEEAWSKeyPrefix)); result.CapacityExceeded {
		t.Fatal("post-control first fragment exceeded capacity")
	}
	ResetCEEState(agent, ip, nil, fb)
	if result := fb.Append(testCEEIdentity(bodyKey), []byte(testCEEAWSKeySuffix)); result.CapacityExceeded {
		t.Fatal("post-reset second fragment exceeded capacity")
	}
	if matches := fb.ScanForSecrets(t.Context(), testCEEStream(bodyKey), sc); len(matches) != 0 {
		t.Fatalf("reset left the bound named JSON body stream intact: %#v", matches)
	}
}

// DeletePrefix on one session's body-json namespace must not reach another
// session whose key is a textual prefix of it. 10.0.0.5 is a byte prefix of
// 10.0.0.50, yet "10.0.0.5|body-json|" is not a prefix of "10.0.0.50|body-json|"
// because the delimiter follows the full session key. Agent names cannot contain
// "|", so no base key can be a structural prefix of another's body-json space.
func TestResetCEEStateBodyJSONPrefixDoesNotReachSiblingSession(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)

	fb := scanner.NewFragmentBuffer(1024, 10, 60)
	t.Cleanup(fb.Close)

	// Both sessions are anonymous (folded to IP), so their live keys are the IPs.
	victimKey := ceeSessionKey("", "10.0.0.5", envelope.ActorAuthSelfDeclared)
	siblingKey := ceeSessionKey("", "10.0.0.50", envelope.ActorAuthSelfDeclared)
	if victimKey != "10.0.0.5" || siblingKey != "10.0.0.50" {
		t.Fatalf("unexpected keys victim=%q sibling=%q", victimKey, siblingKey)
	}

	victimBody := seedJSONBodySecret(t, fb, sc, victimKey)
	siblingBody := seedJSONBodySecret(t, fb, sc, siblingKey)

	// Reset the victim only.
	ResetCEEState("", "10.0.0.5", nil, fb)

	// Victim body stream cleared.
	if result := fb.Append(testCEEIdentity(victimBody), []byte(testCEEAWSKeyPrefix)); result.CapacityExceeded {
		t.Fatal("victim re-prime exceeded capacity")
	}
	if result := fb.Append(testCEEIdentity(victimBody), []byte(testCEEAWSKeySuffix)); result.CapacityExceeded {
		t.Fatal("victim complete exceeded capacity")
	}
	// After a reset the victim stream started empty, so only prefix+suffix are
	// present and reassemble once; that is expected. The invariant under test is
	// the sibling: it must STILL hold its pre-seeded secret untouched.
	if matches := fb.ScanForSecrets(t.Context(), testCEEStream(siblingBody), sc); len(matches) == 0 {
		t.Fatal("resetting 10.0.0.5 wrongly cleared sibling 10.0.0.50 body-json stream")
	}
}

// A JSON body larger than maxCEEBodyRead is truncated before the partitioner
// sees it. Truncated JSON does not parse, but the leaves completed before the
// cut must still become keyed streams (reason "incomplete"), while the tail
// after the last complete leaf stays on the raw stream. The driver's decision
// was to partition what parses rather than raise the read cap, so a body just
// over the cap must not lose the complete leaves before it. This regression
// fails if the partitioner discards partial leaves on truncation.
func TestExtractOutboundPayloadsPartitionsTruncatedBody(t *testing.T) {
	secret := testCEEAWSKeyPrefix + testCEEAWSKeySuffix
	var b strings.Builder
	b.WriteString(`{"secret":"` + secret + `"`)
	i := 0
	for b.Len() < maxCEEBodyRead+4096 {
		fmt.Fprintf(&b, `,"pad%d":"%s"`, i, strings.Repeat("x", 64))
		i++
	}
	b.WriteString("}")
	body := b.String()
	if len(body) <= maxCEEBodyRead {
		t.Fatalf("test body %d not larger than cap %d", len(body), maxCEEBodyRead)
	}

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "http://api.vendor.example/x", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.ContentLength = int64(len(body))

	res := extractOutboundPayloads(req, true, "10.0.0.5", testCEEPartitionKey)

	if len(res.bodyFragmentPayloads) == 0 {
		t.Fatal("truncated body produced no keyed streams; complete leaves were lost")
	}
	if res.partitionReason != ceeJSONPartitionReasonIncomplete {
		t.Fatalf("partition reason = %q, want %q", res.partitionReason, ceeJSONPartitionReasonIncomplete)
	}
	var joined strings.Builder
	for _, v := range res.bodyFragmentPayloads {
		joined.Write(v)
	}
	if !strings.Contains(joined.String(), secret) {
		t.Fatal("complete leaf before the cut was not partitioned")
	}
	if len(res.outbound) == 0 || len(res.outbound) > maxCEEBodyRead {
		t.Fatalf("raw outbound length = %d, want within (0, %d]", len(res.outbound), maxCEEBodyRead)
	}
}
