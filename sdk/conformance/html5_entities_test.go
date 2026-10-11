// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package conformance_test

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/normalize"
)

func TestEvidenceProvenanceV5HTML5Table(t *testing.T) {
	data, err := os.ReadFile("testdata/html5/parity-v5.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		Vectors []struct{ Input, Output string }
	}
	if err := json.Unmarshal(data, &corpus); err != nil {
		t.Fatal(err)
	}
	if len(corpus.Vectors) == 0 {
		t.Fatal("empty HTML5 parity corpus")
	}
	recipe := normalize.Recipe{TransformProfileDigest: normalize.EvidenceProvenanceProfileV5Digest, Operations: []normalize.Operation{{Kind: normalize.OperationHTMLEntityDecode}}}
	divergences := make([][3]string, 0)
	for _, vector := range corpus.Vectors {
		got, err := recipe.Apply(vector.Input)
		if err != nil {
			t.Fatal(err)
		}
		if got != vector.Output {
			divergences = append(divergences, [3]string{vector.Input, base64.StdEncoding.EncodeToString([]byte(vector.Output)), base64.StdEncoding.EncodeToString([]byte(got))})
		}
	}
	report, err := json.Marshal(divergences)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("HTML5_DIVERGENCES:%s", report)
	if len(divergences) != 0 {
		t.Fatalf("%d HTML5 divergences across %d cases", len(divergences), len(corpus.Vectors))
	}
	t.Logf("PASS: %d HTML5 cases, zero divergences", len(corpus.Vectors))
}
