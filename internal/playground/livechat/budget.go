// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package livechat

import (
	"sync"
	"time"
)

// DailyBudget is the global spend kill switch for the live playground. Every
// visitor message drives a real model call that costs money, so per-code and
// per-IP rate limits (which bound the RATE) are not enough on their own: a flood
// of distinct codes/IPs, each under its own limit, still adds up. DailyBudget is
// the hard ceiling on TOTAL turns per UTC day. Once the day's count reaches the
// cap, Charge fails closed until the next UTC day, so a busy (or abusive) day
// cannot run an unbounded model bill.
//
// A cap of 0 means unlimited (no global ceiling) - only for --dev / local runs.
// Public exposure MUST set a positive cap.
//
// The count is held in memory and is PROCESS-LOCAL: a server restart resets it
// to the full cap for the current UTC day (there is no on-disk persistence by
// design - the demo run dirs are ephemeral). So this is the in-app layer of a
// double cap; the durable backstop against a restart loop spending more than
// intended is the model PROVIDER's own account/spend cap, which must also be set
// for public exposure.
type DailyBudget struct {
	mu    sync.Mutex
	cap   int
	day   string
	count int
	now   func() time.Time // injectable for tests
}

// NewDailyBudget returns a budget capping total charges per UTC day. limit <= 0
// disables the ceiling (unlimited).
func NewDailyBudget(limit int) *DailyBudget {
	return &DailyBudget{cap: limit, now: time.Now}
}

// dayKey is the UTC calendar day a time falls in. The budget resets when this
// changes, so the cap is a per-UTC-day ceiling.
func dayKey(t time.Time) string {
	return t.UTC().Format("2006-01-02")
}

// Charge records one unit against today's budget and reports whether it fit. It
// resets the count at the UTC day boundary. With an unlimited cap (<= 0) it always
// allows and records nothing. Fail-closed semantics: at the cap, it returns false
// WITHOUT incrementing, so a rejected charge does not consume tomorrow's headroom.
func (b *DailyBudget) Charge() bool {
	if b == nil || b.cap <= 0 {
		return true
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	today := dayKey(b.now())
	if today != b.day {
		b.day = today
		b.count = 0
	}
	if b.count >= b.cap {
		return false
	}
	b.count++
	return true
}

// Refund returns one already-admitted charge to today's budget. It is used only
// when the server reserved budget but the session was already sealed before the
// turn could start. Refund never creates extra headroom: it only decrements a
// positive count for the same UTC day.
func (b *DailyBudget) Refund() {
	if b == nil || b.cap <= 0 {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if dayKey(b.now()) != b.day || b.count <= 0 {
		return
	}
	b.count--
}

// Remaining reports today's remaining budget, or -1 when unlimited.
func (b *DailyBudget) Remaining() int {
	if b == nil || b.cap <= 0 {
		return -1
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if dayKey(b.now()) != b.day {
		return b.cap
	}
	if b.count >= b.cap {
		return 0
	}
	return b.cap - b.count
}

// Open reports whether the budget has headroom right now (without charging).
func (b *DailyBudget) Open() bool {
	if b == nil || b.cap <= 0 {
		return true
	}
	return b.Remaining() > 0
}
