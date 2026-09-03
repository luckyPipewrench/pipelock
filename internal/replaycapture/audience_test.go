// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !js

package replaycapture

import (
	"strings"
	"testing"
)

// captureWithTargetHost drives a real capture and then rewrites the decisive
// receipt's target to the given URL.
//
// The rewrite is deliberate and is what makes the fixture useful: the shipped
// scenarios only ever reach synthetic lab hosts, which is exactly why a
// real-host receipt was never exercised before it reached a live visitor.
// Assembly consumes the in-memory ActionRecord, so this drives the publication
// gate under test. Chain and signature verification happen upstream of assembly
// and are covered by the chain tests, not here.
func captureWithTargetHost(t *testing.T, target string) *CapturedScenario {
	t.Helper()
	eng := newTestEngine(t)

	var scenario Scenario
	for _, s := range DefaultScenarios() {
		if s.ExpectedVerdict == verdictBlock {
			scenario = s
			break
		}
	}
	if scenario.ID == "" {
		t.Fatal("no blocking scenario available to build a fixture from")
	}

	cs, err := eng.Capture(scenario)
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}
	if len(cs.Receipts) == 0 {
		t.Fatal("capture produced no receipts")
	}
	cs.Receipts[len(cs.Receipts)-1].ActionRecord.Target = target
	return cs
}

// A real target host must still stop a gallery publication. The hostname itself
// is the disclosure, so the verdict on that action is not the deciding fact and
// a blocked attempt earns no exemption.
func TestAssemblePacketFor_GalleryStillRefusesRealHost(t *testing.T) {
	for _, tc := range []struct {
		name     string
		audience Audience
	}{
		{name: "explicit_gallery", audience: AudiencePublicGallery},
		{name: "zero_value_defaults_to_gallery", audience: Audience(0)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cs := captureWithTargetHost(t, "https://sts.amazonaws.com/")
			_, err := AssemblePacketFor(cs, t.TempDir(), fixedStamp(), tc.audience)
			if err == nil {
				t.Fatal("a real target host must not be publishable to the gallery")
			}
			if !strings.Contains(err.Error(), "allowlist") {
				t.Fatalf("error %v must name the allowlist refusal", err)
			}
		})
	}
}

// The default entry point keeps the strict behavior, so introducing an audience
// cannot weaken an existing caller that never names one.
func TestAssemblePacket_DefaultRemainsGallery(t *testing.T) {
	cs := captureWithTargetHost(t, "https://sts.amazonaws.com/")
	if _, err := AssemblePacket(cs, t.TempDir(), fixedStamp()); err == nil {
		t.Fatal("AssemblePacket must keep refusing a real host")
	}
}

// The visitor's own session assembles with the real host intact. They watched
// that decision stream past live, so withholding the same fact from their signed
// evidence protects nobody and denies them the proof the run exists to give.
func TestAssemblePacketFor_SessionOwnerKeepsRealHost(t *testing.T) {
	cs := captureWithTargetHost(t, "https://sts.amazonaws.com/")
	want := len(cs.Receipts)

	res, err := AssemblePacketFor(cs, t.TempDir(), fixedStamp(), AudienceSessionOwner)
	if err != nil {
		t.Fatalf("a session owner must receive their own evidence: %v", err)
	}
	if res == nil || res.PacketDir == "" {
		t.Fatal("assembly produced no packet")
	}
	if res.Receipts != want {
		t.Fatalf("packet carries %d receipts, want all %d; the chain must never be trimmed to make it publishable", res.Receipts, want)
	}
}

// A synthetic lab host assembles for both audiences, which proves the refusals
// above come from the real hostname rather than from anything else the fixture
// happens to carry.
func TestAssemblePacketFor_LabHostServesBothAudiences(t *testing.T) {
	for _, tc := range []struct {
		name     string
		audience Audience
	}{
		{name: "gallery", audience: AudiencePublicGallery},
		{name: "session_owner", audience: AudienceSessionOwner},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cs := captureWithTargetHost(t, "http://intake.lab.test/")
			if _, err := AssemblePacketFor(cs, t.TempDir(), fixedStamp(), tc.audience); err != nil {
				t.Fatalf("a synthetic lab host must assemble for %s: %v", tc.name, err)
			}
		})
	}
}
