// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

func TestIsBareEvidenceSession(t *testing.T) {
	const session = "bare-test"
	const line = `{"type":"evidence_receipt","detail":{"k":1}}`
	cases := []struct {
		name  string
		body  string
		want  bool
		isErr bool
	}{
		{name: "receipt lines only", body: line + "\n\n" + line + "\n", want: true},
		{name: "empty file", body: "", want: false},
		{name: "recorder metadata", body: line + "\n" + `{"type":"session_open","detail":{}}` + "\n", want: false},
		{name: "extra field", body: `{"type":"evidence_receipt","detail":{},"seq":1}` + "\n", want: false},
		{name: "duplicate type key", body: `{"type":"session_open","type":"evidence_receipt","detail":{}}` + "\n", want: false},
		{name: "duplicate detail key", body: `{"type":"evidence_receipt","detail":{},"detail":{}}` + "\n", want: false},
		{name: "null detail", body: `{"type":"evidence_receipt","detail":null}` + "\n", want: false},
		{name: "scalar detail", body: `{"type":"evidence_receipt","detail":"x"}` + "\n", want: false},
		{name: "non-string type", body: `{"type":7,"detail":{}}` + "\n", want: false},
		{name: "malformed JSON", body: `{"type":"evidence_receipt","detail":{}` + "\n", want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			name := filepath.Join(dir, "evidence-"+session+"-0.jsonl")
			if err := os.WriteFile(name, []byte(tc.body), 0o600); err != nil {
				t.Fatal(err)
			}
			got, err := IsBareEvidenceSession(recorder.EvidenceLocation{Root: dir, Dir: dir}, session)
			if (err != nil) != tc.isErr {
				t.Fatalf("err = %v, want error %v", err, tc.isErr)
			}
			if got != tc.want {
				t.Fatalf("IsBareEvidenceSession = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestIsBareEvidenceSessionMissingSession(t *testing.T) {
	dir := t.TempDir()
	got, err := IsBareEvidenceSession(recorder.EvidenceLocation{Root: dir, Dir: dir}, "absent")
	if got {
		t.Fatalf("missing session classified as bare (err %v)", err)
	}
}
