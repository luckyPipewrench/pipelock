// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// Test-local constants for repeated strings.
const (
	testReasonEmpty          = ""
	testMCPStableKey         = "mcp-server-1"
	testToolRead             = "read_file"
	testToolWrite            = "write_file"
	testToolExec             = "exec_command"
	testToolUnknown          = "unknown_tool"
	testTransportUnknown     = "carrier_pigeon"
	testTierUnknown          = "maximum_overdrive"
	testReasonDrain          = "airlock: drain tier blocks all traffic"
	testReasonUnknownTier    = "airlock: unknown tier"
	testReasonUnknownTransit = "airlock: hard tier blocks unknown transport"
)

func TestAirlockState_NewDefaults(t *testing.T) {
	a := NewAirlockState()
	if tier := a.Tier(); tier != config.AirlockTierNone {
		t.Errorf("new airlock tier: got %q, want %q", tier, config.AirlockTierNone)
	}
	if got := a.InFlight(); got != 0 {
		t.Errorf("new airlock in-flight: got %d, want 0", got)
	}
}

func TestAirlockState_SetTier_Upward(t *testing.T) {
	tests := []struct {
		name   string
		from   string
		to     string
		wantOK bool
		wantTo string
	}{
		{"none to soft", config.AirlockTierNone, config.AirlockTierSoft, true, config.AirlockTierSoft},
		{"none to hard (fast-forward)", config.AirlockTierNone, config.AirlockTierHard, true, config.AirlockTierHard},
		{"none to drain (fast-forward)", config.AirlockTierNone, config.AirlockTierDrain, true, config.AirlockTierDrain},
		{"soft to hard", config.AirlockTierSoft, config.AirlockTierHard, true, config.AirlockTierHard},
		{"soft to drain (fast-forward)", config.AirlockTierSoft, config.AirlockTierDrain, true, config.AirlockTierDrain},
		{"hard to drain", config.AirlockTierHard, config.AirlockTierDrain, true, config.AirlockTierDrain},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := NewAirlockState()
			if tt.from != config.AirlockTierNone {
				// Set initial tier by stepping up.
				a.mu.Lock()
				a.tier = tt.from
				a.enteredAt = time.Now()
				a.mu.Unlock()
			}
			changed, from, to := a.SetTier(tt.to)
			if changed != tt.wantOK {
				t.Errorf("changed: got %v, want %v", changed, tt.wantOK)
			}
			if from != tt.from {
				t.Errorf("from: got %q, want %q", from, tt.from)
			}
			if to != tt.wantTo {
				t.Errorf("to: got %q, want %q", to, tt.wantTo)
			}
			if a.Tier() != tt.wantTo {
				t.Errorf("Tier() after set: got %q, want %q", a.Tier(), tt.wantTo)
			}
		})
	}
}

func TestAirlockState_SetTier_DownwardRejected(t *testing.T) {
	tests := []struct {
		name    string
		current string
		target  string
	}{
		{"hard to soft", config.AirlockTierHard, config.AirlockTierSoft},
		{"hard to none", config.AirlockTierHard, config.AirlockTierNone},
		{"drain to hard", config.AirlockTierDrain, config.AirlockTierHard},
		{"drain to none", config.AirlockTierDrain, config.AirlockTierNone},
		{"soft to none", config.AirlockTierSoft, config.AirlockTierNone},
		{"same tier (none)", config.AirlockTierNone, config.AirlockTierNone},
		{"same tier (hard)", config.AirlockTierHard, config.AirlockTierHard},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := NewAirlockState()
			a.mu.Lock()
			a.tier = tt.current
			a.enteredAt = time.Now()
			a.mu.Unlock()

			changed, from, to := a.SetTier(tt.target)
			if changed {
				t.Error("expected downward/same transition to be rejected")
			}
			if from != tt.current || to != tt.current {
				t.Errorf("from/to should equal current: got from=%q to=%q, want %q", from, to, tt.current)
			}
			if a.Tier() != tt.current {
				t.Errorf("tier should be unchanged: got %q, want %q", a.Tier(), tt.current)
			}
		})
	}
}

func TestAirlockState_SetTier_InvalidTier(t *testing.T) {
	a := NewAirlockState()
	changed, _, _ := a.SetTier(testTierUnknown)
	if changed {
		t.Error("invalid tier should be rejected")
	}
	if a.Tier() != config.AirlockTierNone {
		t.Errorf("tier should remain none: got %q", a.Tier())
	}
}

func TestAirlockState_SetTier_ResetsEnteredAt(t *testing.T) {
	a := NewAirlockState()
	a.mu.Lock()
	a.enteredAt = time.Now().Add(-1 * time.Hour)
	a.mu.Unlock()

	before := time.Now()
	a.SetTier(config.AirlockTierSoft)

	a.mu.Lock()
	entered := a.enteredAt
	a.mu.Unlock()

	if entered.Before(before) {
		t.Error("enteredAt should be reset on tier change")
	}
}

func TestAirlockState_TryDeescalate(t *testing.T) {
	timers := &config.AirlockTimers{
		SoftMinutes:  10,
		HardMinutes:  5,
		DrainMinutes: 2,
	}

	tests := []struct {
		name     string
		tier     string
		age      time.Duration
		wantOK   bool
		wantFrom string
		wantTo   string
	}{
		{"soft expired", config.AirlockTierSoft, 11 * time.Minute, true, config.AirlockTierSoft, config.AirlockTierNone},
		{"soft not expired", config.AirlockTierSoft, 5 * time.Minute, false, config.AirlockTierSoft, config.AirlockTierSoft},
		{"hard expired", config.AirlockTierHard, 6 * time.Minute, true, config.AirlockTierHard, config.AirlockTierSoft},
		{"hard not expired", config.AirlockTierHard, 3 * time.Minute, false, config.AirlockTierHard, config.AirlockTierHard},
		{"drain expired", config.AirlockTierDrain, 3 * time.Minute, true, config.AirlockTierDrain, config.AirlockTierHard},
		{"drain not expired", config.AirlockTierDrain, 1 * time.Minute, false, config.AirlockTierDrain, config.AirlockTierDrain},
		{"none is no-op", config.AirlockTierNone, 1 * time.Hour, false, config.AirlockTierNone, config.AirlockTierNone},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := NewAirlockState()
			a.mu.Lock()
			a.tier = tt.tier
			a.enteredAt = time.Now().Add(-tt.age)
			a.mu.Unlock()

			changed, from, to := a.TryDeescalate(timers)
			if changed != tt.wantOK {
				t.Errorf("changed: got %v, want %v", changed, tt.wantOK)
			}
			if from != tt.wantFrom {
				t.Errorf("from: got %q, want %q", from, tt.wantFrom)
			}
			if to != tt.wantTo {
				t.Errorf("to: got %q, want %q", to, tt.wantTo)
			}
		})
	}
}

func TestAirlockState_TryDeescalate_ZeroTimerDisables(t *testing.T) {
	tests := []struct {
		name   string
		tier   string
		timers config.AirlockTimers
	}{
		{"soft zero", config.AirlockTierSoft, config.AirlockTimers{SoftMinutes: 0, HardMinutes: 5, DrainMinutes: 2}},
		{"hard zero", config.AirlockTierHard, config.AirlockTimers{SoftMinutes: 10, HardMinutes: 0, DrainMinutes: 2}},
		{"drain zero", config.AirlockTierDrain, config.AirlockTimers{SoftMinutes: 10, HardMinutes: 5, DrainMinutes: 0}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := NewAirlockState()
			a.mu.Lock()
			a.tier = tt.tier
			a.enteredAt = time.Now().Add(-1 * time.Hour) // well past any timer
			a.mu.Unlock()

			changed, _, _ := a.TryDeescalate(&tt.timers)
			if changed {
				t.Error("zero timer should disable auto-deescalation")
			}
		})
	}
}

func TestAirlockState_ExtendTimer(t *testing.T) {
	a := NewAirlockState()
	a.mu.Lock()
	a.tier = config.AirlockTierHard
	a.enteredAt = time.Now().Add(-10 * time.Minute)
	a.mu.Unlock()

	before := time.Now()
	a.ExtendTimer()

	a.mu.Lock()
	entered := a.enteredAt
	a.mu.Unlock()

	if entered.Before(before) {
		t.Error("ExtendTimer should reset enteredAt to now")
	}

	// After extension, deescalation should NOT fire (timer was 5 min default).
	timers := &config.AirlockTimers{HardMinutes: 5}
	changed, _, _ := a.TryDeescalate(timers)
	if changed {
		t.Error("deescalation should not fire after timer extension")
	}
}

func TestAirlockState_HalfClose(t *testing.T) {
	a := NewAirlockState()
	called := 0
	a.RegisterCancel(func() { called++ })
	a.RegisterCancel(func() { called++ })

	a.HalfClose()
	if called != 2 {
		t.Errorf("HalfClose should call all cancel funcs: got %d calls, want 2", called)
	}

	// Verify cancel funcs are cleared.
	a.HalfClose()
	if called != 2 {
		t.Errorf("second HalfClose should be no-op: got %d calls, want 2", called)
	}
}

func TestAirlockState_FullClose(t *testing.T) {
	a := NewAirlockState()
	called := 0
	a.RegisterCancel(func() { called++ })

	a.FullClose()
	if called != 1 {
		t.Errorf("FullClose should call all cancel funcs: got %d calls, want 1", called)
	}
}

func TestAirlockState_SetTier_HardCallsCancelFuncs(t *testing.T) {
	a := NewAirlockState()
	called := 0
	a.RegisterCancel(func() { called++ })

	a.SetTier(config.AirlockTierHard)
	if called != 1 {
		t.Errorf("SetTier to hard should call cancel funcs: got %d, want 1", called)
	}
}

func TestAirlockState_SetTier_DrainCallsCancelFuncs(t *testing.T) {
	a := NewAirlockState()
	called := 0
	a.RegisterCancel(func() { called++ })
	a.RegisterCancel(func() { called++ })

	a.SetTier(config.AirlockTierDrain)
	if called != 2 {
		t.Errorf("SetTier to drain should call cancel funcs: got %d, want 2", called)
	}
}

func TestAirlockState_InFlight(t *testing.T) {
	a := NewAirlockState()

	a.IncrementInFlight()
	a.IncrementInFlight()
	a.IncrementInFlight()
	if got := a.InFlight(); got != 3 {
		t.Errorf("InFlight after 3 increments: got %d, want 3", got)
	}

	a.DecrementInFlight()
	if got := a.InFlight(); got != 2 {
		t.Errorf("InFlight after decrement: got %d, want 2", got)
	}
}

func TestAirlockState_InFlight_Concurrent(t *testing.T) {
	a := NewAirlockState()
	const goroutines = 100

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for range goroutines {
		go func() {
			defer wg.Done()
			a.IncrementInFlight()
		}()
	}
	wg.Wait()

	if got := a.InFlight(); got != goroutines {
		t.Errorf("concurrent InFlight: got %d, want %d", got, goroutines)
	}
}

func TestClassifyAction_NoneTier(t *testing.T) {
	transports := []string{
		TransportFetch, TransportForward, TransportConnect,
		TransportWS, TransportMCP, TransportScanAPI,
	}
	methods := []string{http.MethodGet, http.MethodPost, http.MethodDelete}

	for _, transport := range transports {
		for _, method := range methods {
			t.Run(transport+"/"+method, func(t *testing.T) {
				allowed, reason := ClassifyAction(config.AirlockTierNone, method, transport, false)
				if !allowed {
					t.Errorf("none tier should allow all: got blocked with reason %q", reason)
				}
				if reason != testReasonEmpty {
					t.Errorf("none tier reason should be empty: got %q", reason)
				}
			})
		}
	}
}

func TestClassifyAction_SoftTier(t *testing.T) {
	// Soft tier is observe-only, same as none for classification.
	allowed, reason := ClassifyAction(config.AirlockTierSoft, http.MethodPost, TransportForward, false)
	if !allowed {
		t.Errorf("soft tier should allow all: got blocked with reason %q", reason)
	}
}

func TestClassifyAction_HardTier_Forward(t *testing.T) {
	tests := []struct {
		name      string
		method    string
		wantAllow bool
	}{
		{"GET allowed", http.MethodGet, true},
		{"HEAD allowed", http.MethodHead, true},
		{"OPTIONS allowed", http.MethodOptions, true},
		{"POST blocked", http.MethodPost, false},
		{"PUT blocked", http.MethodPut, false},
		{"PATCH blocked", http.MethodPatch, false},
		{"DELETE blocked", http.MethodDelete, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			allowed, reason := ClassifyAction(config.AirlockTierHard, tt.method, TransportForward, false)
			if allowed != tt.wantAllow {
				t.Errorf("allowed: got %v, want %v (reason: %q)", allowed, tt.wantAllow, reason)
			}
			if tt.wantAllow && reason != testReasonEmpty {
				t.Errorf("allowed should have empty reason: got %q", reason)
			}
			if !tt.wantAllow && reason == testReasonEmpty {
				t.Error("blocked should have non-empty reason")
			}
		})
	}
}

func TestClassifyAction_HardTier_Fetch(t *testing.T) {
	// Fetch is always allowed (read-only transport).
	methods := []string{http.MethodGet, http.MethodPost}
	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			allowed, _ := ClassifyAction(config.AirlockTierHard, method, TransportFetch, false)
			if !allowed {
				t.Error("fetch should always be allowed in hard tier")
			}
		})
	}
}

func TestClassifyAction_HardTier_ScanAPI(t *testing.T) {
	// Scan API is evaluation-plane, always allowed.
	allowed, _ := ClassifyAction(config.AirlockTierHard, http.MethodPost, TransportScanAPI, false)
	if !allowed {
		t.Error("scan_api should always be allowed in hard tier")
	}
}

func TestClassifyAction_HardTier_Connect(t *testing.T) {
	tests := []struct {
		name             string
		method           string
		tlsIntercepted   bool
		wantAllow        bool
		wantReasonSubstr string
	}{
		{"no TLS interception blocked", http.MethodGet, false, false, "without TLS interception"},
		{"TLS + GET allowed", http.MethodGet, true, true, testReasonEmpty},
		{"TLS + HEAD allowed", http.MethodHead, true, true, testReasonEmpty},
		{"TLS + POST blocked", http.MethodPost, true, false, "write methods"},
		{"TLS + DELETE blocked", http.MethodDelete, true, false, "write methods"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			allowed, reason := ClassifyAction(config.AirlockTierHard, tt.method, TransportConnect, tt.tlsIntercepted)
			if allowed != tt.wantAllow {
				t.Errorf("allowed: got %v, want %v (reason: %q)", allowed, tt.wantAllow, reason)
			}
			if tt.wantReasonSubstr != testReasonEmpty {
				if reason == testReasonEmpty {
					t.Error("expected non-empty reason")
				}
			}
		})
	}
}

func TestClassifyAction_HardTier_WebSocket(t *testing.T) {
	tests := []struct {
		name      string
		method    string
		wantAllow bool
	}{
		{"server-to-client (GET) allowed", http.MethodGet, true},
		{"client-to-server (POST) blocked", http.MethodPost, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			allowed, reason := ClassifyAction(config.AirlockTierHard, tt.method, TransportWS, false)
			if allowed != tt.wantAllow {
				t.Errorf("allowed: got %v, want %v (reason: %q)", allowed, tt.wantAllow, reason)
			}
		})
	}
}

func TestClassifyAction_HardTier_MCP(t *testing.T) {
	// MCP is delegated to frozen tool registry, always allowed at classify level.
	allowed, _ := ClassifyAction(config.AirlockTierHard, http.MethodPost, TransportMCP, false)
	if !allowed {
		t.Error("MCP should be allowed in hard tier (frozen tool check is separate)")
	}
}

func TestClassifyAction_HardTier_UnknownTransport(t *testing.T) {
	allowed, reason := ClassifyAction(config.AirlockTierHard, http.MethodGet, testTransportUnknown, false)
	if allowed {
		t.Error("unknown transport should be blocked in hard tier")
	}
	if reason != testReasonUnknownTransit {
		t.Errorf("reason: got %q, want %q", reason, testReasonUnknownTransit)
	}
}

func TestClassifyAction_DrainTier(t *testing.T) {
	transports := []string{
		TransportFetch, TransportForward, TransportConnect,
		TransportWS, TransportMCP, TransportScanAPI,
	}

	for _, transport := range transports {
		t.Run(transport, func(t *testing.T) {
			allowed, reason := ClassifyAction(config.AirlockTierDrain, http.MethodGet, transport, true)
			if allowed {
				t.Error("drain tier should block everything")
			}
			if reason != testReasonDrain {
				t.Errorf("reason: got %q, want %q", reason, testReasonDrain)
			}
		})
	}
}

func TestClassifyAction_UnknownTier(t *testing.T) {
	allowed, reason := ClassifyAction(testTierUnknown, http.MethodGet, TransportFetch, false)
	if allowed {
		t.Error("unknown tier should be blocked (fail-closed)")
	}
	if reason != testReasonUnknownTier {
		t.Errorf("reason: got %q, want %q", reason, testReasonUnknownTier)
	}
}

func TestFrozenToolRegistry_FreezeAndQuery(t *testing.T) {
	r := NewFrozenToolRegistry()

	if r.IsFrozen(testMCPStableKey) {
		t.Error("should not be frozen before Freeze()")
	}

	// Unfrozen key allows anything.
	if !r.IsToolAllowed(testMCPStableKey, testToolUnknown) {
		t.Error("unfrozen key should allow any tool")
	}

	r.Freeze(testMCPStableKey, []string{testToolRead, testToolWrite})

	if !r.IsFrozen(testMCPStableKey) {
		t.Error("should be frozen after Freeze()")
	}

	if !r.IsToolAllowed(testMCPStableKey, testToolRead) {
		t.Error("frozen tool should be allowed")
	}
	if !r.IsToolAllowed(testMCPStableKey, testToolWrite) {
		t.Error("frozen tool should be allowed")
	}
	if r.IsToolAllowed(testMCPStableKey, testToolExec) {
		t.Error("non-frozen tool should be denied")
	}
}

func TestFrozenToolRegistry_FirstFreezeWins(t *testing.T) {
	r := NewFrozenToolRegistry()

	r.Freeze(testMCPStableKey, []string{testToolRead})
	r.Freeze(testMCPStableKey, []string{testToolRead, testToolWrite, testToolExec})

	// Second freeze should be ignored.
	if r.IsToolAllowed(testMCPStableKey, testToolExec) {
		t.Error("second Freeze should be no-op; exec_command should not be in frozen set")
	}
}

func TestFrozenToolRegistry_Unfreeze(t *testing.T) {
	r := NewFrozenToolRegistry()
	r.Freeze(testMCPStableKey, []string{testToolRead})

	if !r.IsFrozen(testMCPStableKey) {
		t.Error("should be frozen")
	}

	r.Unfreeze(testMCPStableKey)

	if r.IsFrozen(testMCPStableKey) {
		t.Error("should not be frozen after Unfreeze()")
	}

	// After unfreeze, all tools allowed again.
	if !r.IsToolAllowed(testMCPStableKey, testToolExec) {
		t.Error("unfrozen key should allow any tool")
	}
}

func TestFrozenToolRegistry_UnfreezeNonExistent(t *testing.T) {
	r := NewFrozenToolRegistry()
	// Should not panic.
	r.Unfreeze("nonexistent-key")
}

func TestFrozenToolRegistry_EmptyToolSet(t *testing.T) {
	r := NewFrozenToolRegistry()
	r.Freeze(testMCPStableKey, []string{})

	if !r.IsFrozen(testMCPStableKey) {
		t.Error("empty tool set should still mark as frozen")
	}
	if r.IsToolAllowed(testMCPStableKey, testToolRead) {
		t.Error("empty frozen set should deny all tools")
	}
}

func TestFrozenToolRegistry_Concurrent(t *testing.T) {
	r := NewFrozenToolRegistry()
	const goroutines = 50

	var wg sync.WaitGroup
	wg.Add(goroutines * 3)

	// Concurrent freezes for different keys.
	for i := range goroutines {
		key := testMCPStableKey + "-" + string(rune('a'+i%26))
		go func() {
			defer wg.Done()
			r.Freeze(key, []string{testToolRead})
		}()
		go func() {
			defer wg.Done()
			r.IsFrozen(key)
		}()
		go func() {
			defer wg.Done()
			r.IsToolAllowed(key, testToolRead)
		}()
	}
	wg.Wait()
}

func TestFrozenToolRegistry_RefreezeAfterUnfreeze(t *testing.T) {
	r := NewFrozenToolRegistry()
	r.Freeze(testMCPStableKey, []string{testToolRead})
	r.Unfreeze(testMCPStableKey)

	// Re-freeze with different tool set should work.
	r.Freeze(testMCPStableKey, []string{testToolExec})

	if !r.IsToolAllowed(testMCPStableKey, testToolExec) {
		t.Error("re-frozen tool should be allowed")
	}
	if r.IsToolAllowed(testMCPStableKey, testToolRead) {
		t.Error("previously frozen tool should not be allowed after re-freeze with different set")
	}
}

func TestAirlockTierOrder(t *testing.T) {
	// Verify ordering is monotonically increasing.
	tiers := []string{
		config.AirlockTierNone,
		config.AirlockTierSoft,
		config.AirlockTierHard,
		config.AirlockTierDrain,
	}
	for i := 1; i < len(tiers); i++ {
		prev := AirlockTierOrder[tiers[i-1]]
		curr := AirlockTierOrder[tiers[i]]
		if curr <= prev {
			t.Errorf("tier order not monotonic: %s (%d) should be > %s (%d)",
				tiers[i], curr, tiers[i-1], prev)
		}
	}
}

func TestAirlockState_TryDeescalate_ResetsEnteredAt(t *testing.T) {
	a := NewAirlockState()
	a.mu.Lock()
	a.tier = config.AirlockTierHard
	a.enteredAt = time.Now().Add(-10 * time.Minute)
	a.mu.Unlock()

	timers := &config.AirlockTimers{HardMinutes: 5}
	before := time.Now()
	changed, _, _ := a.TryDeescalate(timers)
	if !changed {
		t.Fatal("expected deescalation")
	}

	a.mu.Lock()
	entered := a.enteredAt
	a.mu.Unlock()

	if entered.Before(before) {
		t.Error("enteredAt should be reset after deescalation")
	}
}

func TestAirlockState_RegisterCancel_Concurrent(t *testing.T) {
	a := NewAirlockState()
	const goroutines = 50
	var count atomic.Int32

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for range goroutines {
		go func() {
			defer wg.Done()
			a.RegisterCancel(func() { count.Add(1) })
		}()
	}
	wg.Wait()

	a.HalfClose()
	if got := count.Load(); got != goroutines {
		t.Errorf("cancel count: got %d, want %d", got, goroutines)
	}
}

func TestClassifyAction_HardTier_ConnectPassthroughBlocked(t *testing.T) {
	// CONNECT with TLS interception but passthrough domain: the caller
	// sets isTLSIntercepted=false for passthrough, so it's blocked.
	allowed, reason := ClassifyAction(config.AirlockTierHard, http.MethodGet, TransportConnect, false)
	if allowed {
		t.Error("CONNECT passthrough (no TLS interception) should be blocked in hard tier")
	}
	if reason == testReasonEmpty {
		t.Error("expected non-empty reason for blocked CONNECT")
	}
}

func TestAirlockState_TryDeescalate_InvalidTier(t *testing.T) {
	// Cover the default branch in TryDeescalate's switch for unknown tiers.
	a := NewAirlockState()
	a.mu.Lock()
	a.tier = testTierUnknown
	a.enteredAt = time.Now().Add(-1 * time.Hour)
	a.mu.Unlock()

	timers := &config.AirlockTimers{SoftMinutes: 10, HardMinutes: 5, DrainMinutes: 2}
	changed, from, to := a.TryDeescalate(timers)
	if changed {
		t.Error("unknown tier should not deescalate")
	}
	if from != testTierUnknown || to != testTierUnknown {
		t.Errorf("from/to should be the unknown tier: got from=%q to=%q", from, to)
	}
}

func TestAirlockState_ForceSetTier_Downward(t *testing.T) {
	a := NewAirlockState()
	// Escalate to hard.
	a.SetTier(config.AirlockTierSoft)
	a.SetTier(config.AirlockTierHard)

	// ForceSetTier allows downward transition (SetTier would reject this).
	changed, from, to := a.ForceSetTier(config.AirlockTierSoft)
	if !changed || from != config.AirlockTierHard || to != config.AirlockTierSoft {
		t.Errorf("expected hard->soft, got changed=%v from=%q to=%q", changed, from, to)
	}

	// Force all the way to none.
	changed, from, to = a.ForceSetTier(config.AirlockTierNone)
	if !changed || from != config.AirlockTierSoft || to != config.AirlockTierNone {
		t.Errorf("expected soft->none, got changed=%v from=%q to=%q", changed, from, to)
	}
	if a.Tier() != config.AirlockTierNone {
		t.Errorf("expected none, got %q", a.Tier())
	}
}

func TestAirlockState_ForceSetTier_SameTier(t *testing.T) {
	a := NewAirlockState()
	a.SetTier(config.AirlockTierSoft)

	// Same tier is a no-op.
	changed, _, _ := a.ForceSetTier(config.AirlockTierSoft)
	if changed {
		t.Error("same-tier ForceSetTier should be a no-op")
	}
}

func TestAirlockState_ForceSetTier_InvalidTier(t *testing.T) {
	a := NewAirlockState()
	changed, _, _ := a.ForceSetTier("bogus")
	if changed {
		t.Error("invalid tier should be rejected")
	}
}

func TestAirlockState_ForceSetTier_ClearsCancelOnNone(t *testing.T) {
	a := NewAirlockState()
	a.SetTier(config.AirlockTierSoft)
	a.SetTier(config.AirlockTierHard)

	var called bool
	a.RegisterCancel(func() { called = true })

	// Release to none should clear cancel funcs (not call them).
	a.ForceSetTier(config.AirlockTierNone)

	// Verify cancel funcs were cleared by escalating again; they should not fire.
	a.SetTier(config.AirlockTierSoft)
	a.SetTier(config.AirlockTierHard) // would call cancel funcs if still registered
	if called {
		t.Error("cancel funcs should have been cleared on ForceSetTier to none")
	}
}

func TestAirlockState_ForceSetTier_Upward(t *testing.T) {
	a := NewAirlockState()
	// ForceSetTier should also work for upward transitions.
	changed, from, to := a.ForceSetTier(config.AirlockTierDrain)
	if !changed || from != config.AirlockTierNone || to != config.AirlockTierDrain {
		t.Errorf("expected none->drain, got changed=%v from=%q to=%q", changed, from, to)
	}
}
