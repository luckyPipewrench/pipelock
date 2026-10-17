// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package cardtest

import (
	"encoding/json"
	"testing"
)

func TestCorpusDocuments(t *testing.T) {
	for _, corpus := range []struct {
		name  string
		cases []JSONCase
	}{
		{"JSON", JSONCases()},
		{"union", UnionCases()},
		{"keys", WholeKeyCases()},
		{"transport", TransportCases()},
		{"serialized", StringifiedJSONCases()},
	} {
		t.Run(corpus.name, func(t *testing.T) {
			if len(corpus.cases) == 0 {
				t.Fatal("empty corpus")
			}
			names := make(map[string]bool)
			for _, c := range corpus.cases {
				if c.Name == "" || names[c.Name] {
					t.Fatalf("empty or repeated case name: %q", c.Name)
				}
				names[c.Name] = true
				if !json.Valid([]byte(c.Body)) {
					t.Fatalf("case %q is not JSON", c.Name)
				}
				if c.Clean && c.Warn {
					t.Fatalf("case %q has conflicting verdicts", c.Name)
				}
				if corpus.name == "serialized" {
					var output struct {
						Output string `json:"output"`
					}
					if err := json.Unmarshal([]byte(c.Body), &output); err != nil {
						t.Fatal(err)
					}
					if !json.Valid([]byte(output.Output)) || c.Clean {
						t.Fatalf("case %q lost serialized evidence", c.Name)
					}
				}
			}
		})
	}
	if len(TransportCases()) != len(JSONCases())+len(WholeKeyCases()) {
		t.Fatal("transport corpus lost key cases")
	}
}
