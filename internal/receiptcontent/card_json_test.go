// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package receiptcontent

import (
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/cardtest"
)

func TestCardJSONStructuredReceiptCorpus(t *testing.T) {
	det := testDetector(t)
	for _, tt := range cardtest.TransportCases() {
		t.Run(tt.Name, func(t *testing.T) {
			// Isolate the structured projection. Receipt reconstruction remains an
			// independent artifact policy and can reject fragments that traffic warns on.
			wantClean := tt.Clean || tt.Warn
			// This detector's literal structured view retains ordinary text
			// matching, including a card in a single decimal's fraction.
			if tt.Name == "single decimal telemetry" {
				wantClean = false
			}
			rep, err := Scan(t.Context(), det, &Projection{kind: "test.kind", structured: []byte(tt.Body)})
			if err != nil || rep.Clean() != wantClean {
				t.Fatalf("structured clean=%v want=%v error=%v", rep.Clean(), wantClean, err)
			}
		})
	}
}

func TestCardJSONReceiptFragmentsRetainPolicy(t *testing.T) {
	det := testDetector(t)
	p, err := testProducer.Project([]byte(`{"list":[4111,1111,1111,1111]}`))
	if err != nil {
		t.Fatal(err)
	}
	rep, err := Scan(t.Context(), det, p)
	if err != nil || rep.Clean() || rep.Findings[0].View != ViewFragments {
		t.Fatalf("fragment policy changed: %+v %v", rep, err)
	}
}
