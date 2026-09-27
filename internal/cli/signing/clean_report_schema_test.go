// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package signing

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

const cleanReportSchemaPath = "../../../docs/evidence/clean-report-v1.schema.json"

func validateCleanReportSchema(t *testing.T, raw []byte) error {
	t.Helper()
	f, err := os.Open(filepath.Clean(cleanReportSchemaPath))
	if err != nil {
		t.Fatalf("open clean report schema: %v", err)
	}
	defer func() { _ = f.Close() }()
	doc, err := jsonschema.UnmarshalJSON(f)
	if err != nil {
		t.Fatalf("parse clean report schema: %v", err)
	}
	c := jsonschema.NewCompiler()
	if err := c.AddResource("clean-report-v1.json", doc); err != nil {
		t.Fatalf("add schema resource: %v", err)
	}
	sch, err := c.Compile("clean-report-v1.json")
	if err != nil {
		t.Fatalf("compile clean report schema: %v", err)
	}
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("parse instance: %v", err)
	}
	return sch.Validate(inst)
}

// TestCleanReportSchemaRejectsIncompleteEvidence proves the published schema
// refuses reports missing the chain summary or action fields that the
// generator always writes, so a truncated or hand-built report cannot pass.
func TestCleanReportSchemaRejectsIncompleteEvidence(t *testing.T) {
	t.Parallel()
	const chain = `{"label":"l","receipt_count":1,"final_seq":0,"root_hash":"h","signer_keys":["k"]}`
	const action = `{"action_id":"a","final_decision":"allow","action_type":"read","target":"t","transport":"fetch","timestamp":"2026-01-01T00:00:00Z"}`
	head := `{"schema_version":"pipelock.clean_report.v1","verification_mode":"pinned_provenance",`

	if err := validateCleanReportSchema(t, []byte(head+`"chain":`+chain+`,"actions":[`+action+`]}`)); err != nil {
		t.Fatalf("complete report rejected: %v", err)
	}
	for name, doc := range map[string]string{
		"empty chain":          head + `"chain":{},"actions":[]}`,
		"chain without keys":   head + `"chain":{"label":"l","receipt_count":1,"final_seq":0,"root_hash":"h","signer_keys":[]},"actions":[]}`,
		"zero receipts":        head + `"chain":{"label":"l","receipt_count":0,"final_seq":0,"root_hash":"h","signer_keys":["k"]},"actions":[]}`,
		"empty action":         head + `"chain":` + chain + `,"actions":[{}]}`,
		"action not an object": head + `"chain":` + chain + `,"actions":["x"]}`,
		"action missing id":    head + `"chain":` + chain + `,"actions":[{"final_decision":"allow","action_type":"read","target":"t","transport":"fetch","timestamp":"x"}]}`,
		"unknown chain field":  head + `"chain":{"label":"l","receipt_count":1,"final_seq":0,"root_hash":"h","signer_keys":["k"],"extra":1},"actions":[]}`,
	} {
		if err := validateCleanReportSchema(t, []byte(doc)); err == nil {
			t.Errorf("%s: schema accepted incomplete evidence", name)
		}
	}
}

func TestCleanReportSchemaRejectsInvalidTrustFields(t *testing.T) {
	t.Parallel()
	const body = `"chain":{"label":"l","receipt_count":1,"final_seq":0,"root_hash":"h","signer_keys":["k"]},"actions":[]}`
	for name, doc := range map[string]string{
		"missing schema version":    `{"verification_mode":"pinned_provenance",` + body,
		"unknown schema version":    `{"schema_version":"pipelock.clean_report.v2","verification_mode":"pinned_provenance",` + body,
		"missing verification mode": `{"schema_version":"pipelock.clean_report.v1",` + body,
		"unsupported mode":          `{"schema_version":"pipelock.clean_report.v1","verification_mode":"unknown",` + body,
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateCleanReportSchema(t, []byte(doc)); err == nil {
				t.Fatal("schema accepted invalid trust fields")
			}
		})
	}
}
