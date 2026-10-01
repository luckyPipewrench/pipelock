// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"errors"
	"reflect"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

func TestWalkReceiptsFromSessionDir(t *testing.T) {
	for _, tc := range []struct {
		name, kind string
		detail     any
		wantErr    bool
	}{
		{name: "receipts", kind: recorderEntryType},
		{name: "unknown_type", kind: "unknown", wantErr: true},
		{name: "malformed_receipt", kind: recorderEntryType, detail: "invalid", wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			rec, err := recorder.New(recorder.Config{Enabled: true, Dir: dir, MaxEntriesPerFile: 2}, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			_, priv := generateTestKey(t)
			chain := buildChain(t, priv, 7)
			for _, r := range chain {
				detail := tc.detail
				if detail == nil {
					detail = r
				}
				if err := rec.Record(recorder.Entry{SessionID: chainTestSession, Type: tc.kind, Detail: detail}); err != nil {
					t.Fatal(err)
				}
			}
			if err := rec.Close(); err != nil {
				t.Fatal(err)
			}
			var walked []Receipt
			err = WalkReceiptsFromSessionDir(dir, chainTestSession, func(r Receipt) error { walked = append(walked, r); return nil })
			if tc.wantErr {
				if err == nil {
					t.Fatal("invalid extraction succeeded")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			materialized, err := ExtractReceiptsFromSessionDir(dir, chainTestSession)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(walked, materialized) || len(walked) != len(chain) {
				t.Fatal("stream differs from materialized extraction")
			}
			callbackErr := errors.New("consumer failure")
			if err := WalkReceiptsFromSessionDir(dir, chainTestSession, func(Receipt) error { return callbackErr }); !errors.Is(err, callbackErr) {
				t.Fatalf("callback error: %v", err)
			}
		})
	}
	if err := WalkReceiptsFromSessionDir(t.TempDir(), chainTestSession, nil); err == nil {
		t.Fatal("nil consumer accepted")
	}
}
