// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package recorder

import (
	"errors"
	"os"
	"testing"
)

func TestSetGroupFileVerifierState(t *testing.T) {
	noop := func(string, string, os.FileInfo) error { return nil }
	for _, tc := range []struct {
		name   string
		rec    *Recorder
		verify func(string, string, os.FileInfo) error
	}{
		{"nil", nil, noop},
		{"nop", &Recorder{nop: true}, noop},
		{"nil_verifier", &Recorder{}, nil},
		{"no_group", &Recorder{}, noop},
		{"closing", &Recorder{groupSessions: map[string]*SessionState{}, groupClosing: true}, noop},
		{"closed", &Recorder{groupSessions: map[string]*SessionState{}, closed: true}, noop},
		{"already_set", &Recorder{groupSessions: map[string]*SessionState{}, groupFileVerifier: noop}, noop},
		{"written", &Recorder{groupSessions: map[string]*SessionState{"one": {seq: 1}}}, noop},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.rec.SetGroupFileVerifier(tc.verify, nil); err == nil {
				t.Fatal("invalid verifier installation accepted")
			}
		})
	}
	r := &Recorder{groupSessions: map[string]*SessionState{"one": {}}}
	if err := r.SetGroupFileVerifier(noop, nil); err != nil {
		t.Fatal(err)
	}
	if r.groupFileVerifier == nil {
		t.Fatal("verifier was not retained")
	}
}

func TestGroupFileVerifierFailureStillClosesFile(t *testing.T) {
	dir := t.TempDir()
	r, err := New(Config{Enabled: true, Dir: dir}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	if err := r.Record(Entry{SessionID: "test", Type: "test", Summary: "before close"}); err != nil {
		t.Fatal(err)
	}
	want := errors.New("segment verifier refused")
	calls := 0
	r.groupFileVerifier = func(session, path string, _ os.FileInfo) error {
		calls++
		if session != "test" || path == "" {
			t.Fatalf("unexpected verifier arguments: %q %q", session, path)
		}
		return want
	}
	if err := r.Close(); !errors.Is(err, want) {
		t.Fatalf("close=%v want verifier failure", err)
	}
	if calls != 1 || r.file != nil || r.writer != nil {
		t.Fatalf("failed verification did not close file: calls=%d", calls)
	}
}
