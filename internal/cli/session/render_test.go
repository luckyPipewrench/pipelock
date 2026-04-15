// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package session

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/proxy"
)

func TestRenderList_EmptyPrintsPlaceholder(t *testing.T) {
	var buf bytes.Buffer
	if err := renderList(&buf, nil); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "No sessions") {
		t.Errorf("empty list output: %q", buf.String())
	}
}

func TestRenderList_PopulatesColumns(t *testing.T) {
	var buf bytes.Buffer
	if err := renderList(&buf, makeSnapshotList()); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	wantContains := []string{"KEY", "AGENT", "TIER", testKeyIdent, "hard"}
	for _, w := range wantContains {
		if !strings.Contains(out, w) {
			t.Errorf("list output missing %q: %s", w, out)
		}
	}
}

func TestRenderList_HandlesEmptyFields(t *testing.T) {
	var buf bytes.Buffer
	snaps := []proxy.SessionSnapshot{{Key: "k1", LastActivity: testFixedTime()}}
	if err := renderList(&buf, snaps); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "none") {
		t.Errorf("empty tier should render as 'none': %s", out)
	}
}

func TestRenderDetail_ContainsAllFields(t *testing.T) {
	var buf bytes.Buffer
	if err := renderDetail(&buf, makeDetail()); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	want := []string{
		testKeyIdent, "hard", "airlock_entered", "recent_events",
		"dlp secret", "in_flight:", "3",
	}
	for _, w := range want {
		if !strings.Contains(out, w) {
			t.Errorf("detail missing %q in:\n%s", w, out)
		}
	}
}

func TestRenderDetail_NoEvents(t *testing.T) {
	d := makeDetail()
	d.RecentEvents = nil
	var buf bytes.Buffer
	if err := renderDetail(&buf, d); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "(none)") {
		t.Errorf("empty events should print (none): %s", buf.String())
	}
}

func TestRenderDetail_ZeroAirlockEntered(t *testing.T) {
	d := makeDetail()
	d.AirlockEnteredAt = time.Time{}
	var buf bytes.Buffer
	if err := renderDetail(&buf, d); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "airlock_entered:  -") {
		t.Errorf("zero time should render as '-': %s", buf.String())
	}
}

func TestRenderExplanation_QuarantinedSession(t *testing.T) {
	var buf bytes.Buffer
	if err := renderExplanation(&buf, makeExplanation()); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	want := []string{"hard", "on_critical", "evidence:", "dlp secret", "next_deescalation", "soft"}
	for _, w := range want {
		if !strings.Contains(out, w) {
			t.Errorf("explanation missing %q in:\n%s", w, out)
		}
	}
}

func TestRenderExplanation_NormalSession(t *testing.T) {
	exp := proxy.SessionExplanation{
		Key:    "normal|1.2.3.4",
		Tier:   "none",
		Reason: "session not quarantined",
	}
	var buf bytes.Buffer
	if err := renderExplanation(&buf, exp); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "session not quarantined") {
		t.Errorf("output: %s", buf.String())
	}
	if !strings.Contains(buf.String(), "(none recorded)") {
		t.Errorf("should note missing evidence: %s", buf.String())
	}
}

func TestFormatDuration(t *testing.T) {
	tests := []struct {
		d    time.Duration
		want string
	}{
		{-time.Second, "0s"},
		{500 * time.Millisecond, "0s"},
		{10 * time.Second, "10s"},
		{90 * time.Second, "1m"},
		{2 * time.Hour, "2h"},
	}
	for _, tt := range tests {
		if got := formatDuration(tt.d); got != tt.want {
			t.Errorf("formatDuration(%v): got %q, want %q", tt.d, got, tt.want)
		}
	}
}

func TestRelativeTime_Zero(t *testing.T) {
	if got := relativeTime(time.Time{}); got != "-" {
		t.Errorf("zero time: got %q, want -", got)
	}
}

func TestDefaultDash(t *testing.T) {
	if got := defaultDash(""); got != "-" {
		t.Error("empty should be -")
	}
	if got := defaultDash("foo"); got != "foo" {
		t.Error("non-empty should be unchanged")
	}
}

func TestDefaultIfEmpty(t *testing.T) {
	if got := defaultIfEmpty("", "fallback"); got != "fallback" {
		t.Error("empty should use fallback")
	}
	if got := defaultIfEmpty("real", "fallback"); got != "real" {
		t.Error("non-empty should win")
	}
}

// ensure io.Writer is honored: a writer that errors propagates the error.
func TestRenderList_PropagatesWriteError(t *testing.T) {
	err := renderList(errWriter{}, nil)
	if err == nil {
		t.Error("expected error from failing writer")
	}
}

type errWriter struct{}

func (errWriter) Write([]byte) (int, error) { return 0, errors.New("boom") }
