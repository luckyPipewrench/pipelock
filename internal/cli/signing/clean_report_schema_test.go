// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package signing

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

const cleanReportSchemaPath = "../../../docs/evidence/clean-report-v1.schema.json"

func validateCleanReportSchema(t *testing.T, raw []byte) error {
	t.Helper()
	var header struct {
		SchemaVersion string `json:"schema_version"`
	}
	if err := json.Unmarshal(raw, &header); err != nil {
		return err
	}
	var path string
	switch header.SchemaVersion {
	case "pipelock.clean_report.v1":
		path = cleanReportSchemaPath
	case "pipelock.clean_report.v2":
		path = "../../../docs/evidence/clean-report-v2.schema.json"
	default:
		return fmt.Errorf("unsupported clean report schema_version %q", header.SchemaVersion)
	}
	return validateCleanReportSchemaAt(t, raw, path)
}

func validateCleanReportSchemaAt(t *testing.T, raw []byte, path string) error {
	t.Helper()
	f, err := os.Open(filepath.Clean(path))
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
		"missing schema version":           `{"verification_mode":"pinned_provenance",` + body,
		"v2 missing extended trust fields": `{"schema_version":"pipelock.clean_report.v2","verification_mode":"pinned_provenance",` + body,
		"missing verification mode":        `{"schema_version":"pipelock.clean_report.v1",` + body,
		"unsupported mode":                 `{"schema_version":"pipelock.clean_report.v1","verification_mode":"unknown",` + body,
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateCleanReportSchema(t, []byte(doc)); err == nil {
				t.Fatal("schema accepted invalid trust fields")
			}
		})
	}
}

func TestCleanReportSchemaVersionBoundary(t *testing.T) {
	t.Parallel()
	const legacy = `{"schema_version":"pipelock.clean_report.v1","verification_mode":"pinned_provenance","chain":{"label":"l","receipt_count":1,"final_seq":0,"root_hash":"h","signer_keys":["k"]},"actions":[]}`
	if err := validateCleanReportSchema(t, []byte(legacy)); err != nil {
		t.Fatalf("original v1 fixture rejected: %v", err)
	}
	var report map[string]any
	if err := json.Unmarshal([]byte(legacy), &report); err != nil {
		t.Fatal(err)
	}
	report["integrity"] = "valid"
	report["end_proof"] = map[string]any{"proven": true, "evidence": []string{"operator_head"}}
	report["scope"] = "receipt_chain"
	report["status"] = "CHAIN VALID"
	encode := func(value map[string]any) []byte {
		t.Helper()
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	if err := validateCleanReportSchema(t, encode(report)); err == nil {
		t.Fatal("v1 accepted extended report fields")
	}
	report["schema_version"] = "pipelock.clean_report.v2"
	if err := validateCleanReportSchema(t, encode(report)); err != nil {
		t.Fatalf("complete v2 fixture rejected: %v", err)
	}
	for _, field := range []string{"integrity", "end_proof", "scope", "status"} {
		t.Run(field, func(t *testing.T) {
			value := report[field]
			delete(report, field)
			if err := validateCleanReportSchema(t, encode(report)); err == nil {
				t.Fatalf("v2 accepted missing %s", field)
			}
			report[field] = value
		})
	}
	for _, status := range []string{"CHAIN VALID", "CHAIN UNPINNED", "CHAIN BROKEN", "VALID PREFIX, END UNPROVEN"} {
		for _, mode := range []string{"pinned_provenance", "unpinned_structural"} {
			for _, proven := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/proven=%t", status, mode, proven), func(t *testing.T) {
					report["status"] = status
					report["verification_mode"] = mode
					report["end_proof"].(map[string]any)["proven"] = proven
					wantValid := status == "CHAIN BROKEN" ||
						status == "CHAIN VALID" && mode == "pinned_provenance" && proven ||
						status == "CHAIN UNPINNED" && mode == "unpinned_structural" && proven ||
						status == "VALID PREFIX, END UNPROVEN" && !proven
					// Validate the published schema directly, without reader checks.
					err := validateCleanReportSchemaAt(t, encode(report), "../../../docs/evidence/clean-report-v2.schema.json")
					if (err == nil) != wantValid {
						t.Fatalf("schema valid = %t, want %t: %v", err == nil, wantValid, err)
					}
				})
			}
		}
	}
	report["status"] = "UNKNOWN"
	if err := validateCleanReportSchema(t, encode(report)); err == nil {
		t.Fatal("v2 accepted unknown status")
	}
	report["schema_version"] = "pipelock.clean_report.v3"
	if err := validateCleanReportSchema(t, encode(report)); err == nil {
		t.Fatal("reader accepted unknown version")
	}
}
