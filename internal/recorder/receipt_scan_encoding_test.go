// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package recorder_test

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// receiptScanEncodingEnvName names the environment value the scanner treats
// as an agent secret for this table. The value is assembled at runtime.
const receiptScanEncodingEnvName = "PIPELOCK_RECEIPT_SCAN_FIXTURE_VALUE"

// signedReceiptShape wraps one caller-controlled value in the same nesting,
// hash, nonce, and signature fields a signed action receipt carries, so the
// encoded secret is scanned alongside the receipt's own hex material.
func signedReceiptShape(fields map[string]string) map[string]any {
	record := map[string]any{
		"version":           1,
		"action_id":         "01a10876-e574-7858-92ca-85180176245e",
		"action_type":       "read",
		"timestamp":         "2026-10-04T19:49:32.149206259Z",
		"principal":         "local",
		"actor":             "anonymous",
		"target":            "http://api.vendor.example/ok?id=20",
		"side_effect_class": "external_read",
		"reversibility":     "full",
		"policy_hash":       strings.Repeat("2f11462af3125d36", 4),
		"verdict":           "block",
		"transport":         "forward",
		"method":            "GET",
		"layer":             "core_dlp",
		"request_id":        "req-5",
		"chain_prev_hash":   strings.Repeat("27edbadedf6ce029", 4),
		"chain_seq":         2,
		"run_nonce":         "3b73fbe93c5e93817cd521630d0c5da8",
	}
	for k, v := range fields {
		record[k] = v
	}
	return map[string]any{
		"version":       1,
		"action_record": record,
		"signature":     "ed25519:" + strings.Repeat("2c228584e64e5259", 8),
		"signer_key":    strings.Repeat("0fb6b3e45f9dd942", 4),
	}
}

func decimalCodes(s, sep string) string {
	parts := make([]string, 0, len(s))
	for _, r := range s {
		parts = append(parts, strconv.Itoa(int(r)))
	}
	return strings.Join(parts, sep)
}

func nestedJSONString(t *testing.T, value string) string {
	t.Helper()
	inner, err := json.Marshal(map[string]string{"inner": value})
	if err != nil {
		t.Fatal(err)
	}
	return string(inner)
}

// TestReceiptScanEncodedSecretMatrix pins the receipt-detail verdict for each
// encoded secret shape on the production text scanner. Every case marked
// reject must be refused by the scanner, the recorder preflight, and a direct
// Record; the clean controls must be accepted by all three.
func TestReceiptScanEncodedSecretMatrix(t *testing.T) {
	envSecret := "rcpt" + "Zq7vK2mX9pL4wR8tN3bY6cH1jD5fG0sA"
	t.Setenv(receiptScanEncodingEnvName, envSecret)
	token := "ghp_" + "aB3dE5gH7jK9mN1pQ3sT5vW7yZ9bC1dF3hJ5"
	seed := strings.Repeat("abandon ", 11) + "about"

	cfg := config.Defaults()
	cfg.SeedPhraseDetection.Enabled = ptrBool(true)
	sc, err := scanner.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sc.Close)

	cases := []struct {
		name       string
		fields     map[string]string
		wantReject bool
	}{
		{name: "clean receipt", fields: nil},
		{name: "clean unrelated fields", fields: map[string]string{"pattern": "core DLP match: GitHub Token (critical)", "rule_id": "allow-list"}},

		// Credential pattern.
		{name: "token literal", fields: map[string]string{"target": "http://api.vendor.example/?t=" + token}, wantReject: true},
		{name: "token base64", fields: map[string]string{"pattern": base64.StdEncoding.EncodeToString([]byte(token))}, wantReject: true},
		{name: "token base64url unpadded", fields: map[string]string{"pattern": base64.RawURLEncoding.EncodeToString([]byte(token))}, wantReject: true},
		{name: "token hex", fields: map[string]string{"pattern": hex.EncodeToString([]byte(token))}, wantReject: true},
		{name: "token url encoded", fields: map[string]string{"target": "http://api.vendor.example/?t=" + strings.Replace(token, "_", "%5F", 1)}, wantReject: true},
		{name: "token double url encoded", fields: map[string]string{"target": "http://api.vendor.example/?t=" + strings.Replace(token, "_", "%255F", 1)}, wantReject: true},
		{name: "token hex in url path", fields: map[string]string{"target": "http://api.vendor.example/" + hex.EncodeToString([]byte(token)) + "/x"}, wantReject: true},
		{name: "token nested json string", fields: map[string]string{"rule_id": nestedJSONString(t, token)}, wantReject: true},
		{name: "token base64 in nested json string", fields: map[string]string{"rule_id": nestedJSONString(t, base64.StdEncoding.EncodeToString([]byte(token)))}, wantReject: true},
		{name: "token base64 of hex", fields: map[string]string{"pattern": base64.StdEncoding.EncodeToString([]byte(hex.EncodeToString([]byte(token))))}, wantReject: true},
		// JSON keys and punctuation separate the two halves; the text scanner
		// does not reassemble credential patterns across fields today.
		{name: "token split across fields", fields: map[string]string{"pattern": token[:14], "rule_id": token[14:]}, wantReject: false},

		// Agent environment secret: whole value, encodings, and partial runs.
		{name: "env literal", fields: map[string]string{"rule_id": envSecret}, wantReject: true},
		{name: "env base64", fields: map[string]string{"rule_id": base64.StdEncoding.EncodeToString([]byte(envSecret))}, wantReject: true},
		{name: "env base64url unpadded", fields: map[string]string{"rule_id": base64.RawURLEncoding.EncodeToString([]byte(envSecret))}, wantReject: true},
		{name: "env hex", fields: map[string]string{"rule_id": hex.EncodeToString([]byte(envSecret))}, wantReject: true},
		{name: "env hex colon separated", fields: map[string]string{"rule_id": colonHex(envSecret)}, wantReject: true},
		{name: "env decimal codes", fields: map[string]string{"rule_id": decimalCodes(envSecret, ",")}, wantReject: true},
		{name: "env partial run", fields: map[string]string{"rule_id": "x" + envSecret[6:30] + "y"}, wantReject: true},
		{name: "env split across fields", fields: map[string]string{"pattern": envSecret[:18], "rule_id": envSecret[18:]}, wantReject: true},
		{name: "env nested json string", fields: map[string]string{"rule_id": nestedJSONString(t, envSecret)}, wantReject: true},
		{name: "env url query escaped", fields: map[string]string{"target": "http://api.vendor.example/?v=" + url.QueryEscape(envSecret)}, wantReject: true},
		{name: "env short fragment", fields: map[string]string{"rule_id": envSecret[4:15]}, wantReject: false},

		// Seed phrase. The phrase sits inside prose, as it would in a free-form
		// field. A phrase that alone fills a JSON string is caught too.
		{name: "seed literal", fields: map[string]string{"rule_id": "note " + seed + " end"}, wantReject: true},
		{name: "seed base64", fields: map[string]string{"pattern": base64.StdEncoding.EncodeToString([]byte(seed))}, wantReject: true},
		{name: "seed hex", fields: map[string]string{"pattern": hex.EncodeToString([]byte(seed))}, wantReject: true},
		{name: "seed url encoded", fields: map[string]string{"target": "http://api.vendor.example/?m=note%20" + strings.ReplaceAll(seed, " ", "%20") + "%20end"}, wantReject: true},
		{name: "seed zero width separated", fields: map[string]string{"rule_id": "note " + strings.ReplaceAll(seed, " ", "\u200b") + " end"}, wantReject: true},
		{name: "seed nested json string", fields: map[string]string{"rule_id": nestedJSONString(t, "note "+seed+" end")}, wantReject: true},
		{name: "seed base64 in url path", fields: map[string]string{"target": "http://api.vendor.example/" + base64.RawURLEncoding.EncodeToString([]byte(seed)) + "/x"}, wantReject: true},
		// Known gap: the JSON quote attaches to the first and last word, so a
		// phrase that is the whole string value is one word short. Pinned so a
		// fix flips this deliberately rather than silently.
		{name: "seed alone in json string", fields: map[string]string{"rule_id": seed}, wantReject: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			detail := signedReceiptShape(tc.fields)
			raw, err := json.Marshal(detail)
			if err != nil {
				t.Fatal(err)
			}
			if got := !sc.ScanTextForDLP(context.Background(), string(raw)).Clean; got != tc.wantReject {
				t.Fatalf("scanner reject = %t, want %t", got, tc.wantReject)
			}
			rec, err := recorder.New(recorder.Config{Enabled: true, Dir: t.TempDir(), Redact: true}, sc.ScanTextForDLP, nil)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = rec.Close() })
			if _, err := rec.PreflightSignedReceiptDetail(json.RawMessage(raw)); (err != nil) != tc.wantReject {
				t.Fatalf("preflight rejected = %t, want %t: %v", err != nil, tc.wantReject, err)
			}
			if err := rec.Record(receiptScanEntry(json.RawMessage(raw))); (err != nil) != tc.wantReject {
				t.Fatalf("record rejected = %t, want %t: %v", err != nil, tc.wantReject, err)
			}
		})
	}
}

func colonHex(s string) string {
	h := hex.EncodeToString([]byte(s))
	parts := make([]string, 0, len(h)/2)
	for i := 0; i < len(h); i += 2 {
		parts = append(parts, h[i:i+2])
	}
	return strings.Join(parts, ":")
}

func ptrBool(b bool) *bool { return &b }
