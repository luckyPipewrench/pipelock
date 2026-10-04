// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/envelope"
	"github.com/luckyPipewrench/pipelock/internal/identitykey"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// A sibling JSON field that hashes into the same fixed bucket used to be
// concatenated with the secret field. The completing request then saw
// prefix+sibling and suffix+sibling, so the secret was no longer contiguous
// and the request was allowed. The sibling must not hide a real split, and
// two different fields must not be glued into a secret either.
func TestCEEJSONSiblingInSameBucketDoesNotHideOrInventASecret(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.CrossRequestDetection.Enabled = true
	cfg.CrossRequestDetection.Action = config.ActionBlock
	cfg.CrossRequestDetection.EntropyBudget.Enabled = false
	cfg.CrossRequestDetection.FragmentReassembly.Enabled = true
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)

	clientIP := "203.0.113.44"
	session := identitykey.NewCEEIdentity("", clientIP, envelope.ActorAuthSelfDeclared).Key()

	admit := func(t *testing.T, fb *scanner.FragmentBuffer, decoy, content, decoyValue string) ceeResult {
		t.Helper()
		body := `{"messages":[{"role":"user","content":"` + content + `"}],"` + decoy + `":"` + decoyValue + `"}`
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "http://api.vendor.example/v1/messages", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		payloads := extractOutboundPayloads(req, true, session, fb.PartitionKey())
		return ceeAdmit(t.Context(), ceeAdmitOptions{
			ClientIP:             clientIP,
			Outbound:             payloads.outbound,
			BodyFragmentPayloads: payloads.bodyFragmentPayloads,
			BodyFragmentLeaves:   payloads.bodyFragmentLeaves,
			Config:               cfg.CrossRequestDetection,
			Fragments:            fb,
			Scanner:              sc,
			Logger:               audit.NewNop(),
			Metrics:              metrics.New(),
		})
	}

	t.Run("split field still blocks", func(t *testing.T) {
		fb := scanner.NewFragmentBuffer(1<<20, 8, 300)
		t.Cleanup(fb.Close)
		decoy := collidingJSONDecoy(t, session, fb.PartitionKey())
		body := `{"messages":[{"role":"user","content":"` + testCEEAWSKeyPrefix + `"}],"` + decoy + `":"INTRUDERTEXT"}`
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "http://api.vendor.example/v1/messages", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		payloads := extractOutboundPayloads(req, true, session, fb.PartitionKey())
		if !bucketHoldsBoth(payloads.bodyFragmentPayloads, testCEEAWSKeyPrefix, "INTRUDERTEXT") {
			t.Fatalf("decoy %q did not share the content bucket: %#v", decoy, payloads.bodyFragmentPayloads)
		}
		if got := admit(t, fb, decoy, testCEEAWSKeyPrefix, "INTRUDERTEXT"); got.Blocked {
			t.Fatalf("first half blocked: %+v", got)
		}
		got := admit(t, fb, decoy, testCEEAWSKeySuffix, "INTRUDERTEXT")
		if !got.Blocked || !got.FragmentHit {
			t.Fatalf("completing half = %+v, want a fragment block", got)
		}
	})

	t.Run("sibling halves do not block", func(t *testing.T) {
		fb := scanner.NewFragmentBuffer(1<<20, 8, 300)
		t.Cleanup(fb.Close)
		decoy := collidingJSONDecoy(t, session, fb.PartitionKey())
		if got := admit(t, fb, decoy, "xxxxordinary", testCEEAWSKeyPrefix); got.Blocked {
			t.Fatalf("first sibling body blocked: %+v", got)
		}
		got := admit(t, fb, decoy, testCEEAWSKeySuffix, "yyyyordinary")
		if got.Blocked || got.FragmentHit {
			t.Fatalf("sibling fields formed a secret: %+v", got)
		}
	})
}

func collidingJSONDecoy(t *testing.T, session string, key []byte) string {
	t.Helper()
	marker := "CONTENTMARKER"
	base, reason := jsonBodyFragmentPayloads("application/json", []byte(`{"messages":[{"role":"user","content":"`+marker+`"}]}`), session, key)
	if reason != "" {
		t.Fatalf("base partition reason = %q", reason)
	}
	var contentBucket string
	for bucket, value := range base {
		if strings.Contains(string(value), marker) {
			contentBucket = bucket
			break
		}
	}
	if contentBucket == "" {
		t.Fatal("content leaf was not partitioned")
	}
	for i := range 20000 {
		name := "d" + strconv.Itoa(i)
		body := `{"messages":[{"role":"user","content":"` + marker + `"}],"` + name + `":"INTRUDERTEXT"}`
		got, _ := jsonBodyFragmentPayloads("application/json", []byte(body), session, key)
		blob := string(got[contentBucket])
		if strings.Contains(blob, marker) && strings.Contains(blob, "INTRUDERTEXT") {
			return name
		}
	}
	t.Fatal("no sibling field shared the content bucket")
	return ""
}

func bucketHoldsBoth(payloads map[string][]byte, first, second string) bool {
	for _, value := range payloads {
		blob := string(value)
		if strings.Contains(blob, first) && strings.Contains(blob, second) {
			return true
		}
	}
	return false
}
