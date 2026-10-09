// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/receipt"
)

func TestReviewR3SignedRequestShape(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	plan := newWorkload(1, 0, 1)
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		rcpt, signErr := receipt.Sign(receipt.ActionRecord{
			Version: receipt.ActionRecordVersion, ActionID: actionIDFor(0), RunNonce: "run0",
			Timestamp: time.Now().UTC(), ActionType: receipt.ActionRead, Method: method,
			Transport: workloadTransport, Verdict: verdictAllow, Target: sinkTarget(synthSink, "wk="+plan.key(0)),
		}, priv)
		if signErr != nil {
			t.Fatal(signErr)
		}
		if err := receipt.VerifyWithKey(rcpt, hex.EncodeToString(pub)); err != nil {
			t.Fatalf("signed producer control: %v", err)
		}
		raw, err := receipt.Marshal(rcpt)
		if err != nil {
			t.Fatal(err)
		}
		s := &recorderScanner{plan: plan, sinkAddr: synthSink, obs: newRecorderObservation(1), actionSlot: map[string]int{}, controlIDs: map[string]struct{}{}, actionRuns: map[string]string{}}
		err = s.v1Receipt(evidenceEnvelope{Session: "proxy.run.x", Detail: raw})
		if (method == http.MethodGet && err != nil) || (method == http.MethodPost && err == nil) {
			t.Fatalf("authenticated %s receipt attribution: %v", method, err)
		}
	}
}

func TestReviewR3QueryShape(t *testing.T) {
	for _, tc := range []struct {
		name, query              string
		blocked, sanitized, want bool
	}{
		{"allowed", "wk=s1-m000000", false, false, true},
		{"extra", "wk=s1-m000000&extra=value", false, false, false},
		{"extra-token", "wk=s1-m000000&" + workloadTokenParam + "=value", false, true, false},
		{"blocked-original", "wk=s0-m000000&token=" + fakeToken, true, false, true},
		{"blocked-redacted", "wk=s0-m000000&token=[redacted-value]", true, true, true},
		{"origin-redacted", "wk=s0-m000000&token=[redacted-value]", true, false, false},
		{"blocked-missing", "wk=s0-m000000", true, true, false},
		{"blocked-wrong-token", "wk=s0-m000000&" + workloadTokenParam + "=value", true, true, false},
		{"blocked-duplicate", "wk=s0-m000000&" + workloadTokenParam + "=value&" + workloadTokenParam + "=other", true, true, false},
		{"malformed", "wk=s1-m000000&bad=%zz", false, false, false},
		{"foreign-key", "wk=foreign", false, false, false},
		{"malformed-url", "http://[", false, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			seed := uint64(1)
			if tc.blocked {
				seed = 0
			}
			plan := newWorkload(seed, 0, 1)
			target := sinkTarget(synthSink, tc.query)
			if tc.name == "malformed-url" {
				target = tc.query
			}
			if got := plan.matchesTargetQuery(target, 0, tc.sanitized); got != tc.want {
				t.Fatalf("query accepted=%t, want %t", got, tc.want)
			}
		})
	}
	plan := newWorkload(1, 0, 1)
	for _, suffix := range []string{"", "&extra=value"} {
		s := &sink{plan: plan, seen: make([]atomic.Int32, 1)}
		r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, sinkTarget(synthSink, "wk="+plan.key(0)+suffix), nil)
		s.handle(httptest.NewRecorder(), r)
		if (suffix == "" && s.hits()[0] != 1) || (suffix != "" && (s.hits()[0] != 0 || s.unknown.Load() != 1)) {
			t.Fatalf("origin query attribution: hits=%v unknown=%d", s.hits(), s.unknown.Load())
		}
	}
}

func TestReviewR3SummaryProvenance(t *testing.T) {
	for _, name := range []string{"valid", "missing-source", "missing-binary", "missing-config", "malformed-hash", "short-hash"} {
		t.Run(name, func(t *testing.T) {
			r := fakeResult(100, 80, 90, verdictPass, perfMeasured)
			switch name {
			case "missing-source":
				r.Inputs.Harness.SourceSHA256 = ""
			case "missing-binary":
				r.Inputs.Binary.SHA256 = ""
			case "missing-config":
				r.Inputs.Config.CanonicalSHA256 = ""
			case "malformed-hash":
				r.Inputs.Harness.SourceSHA256 = strings.Repeat("z", 64)
			case "short-hash":
				r.Inputs.Harness.SourceSHA256 = "abcd"
			}
			row := summaryRow(2, 1, modeRequired, 1, []result{r})
			if name == "valid" {
				if row[4] != verdictPass || row[7] == "" {
					t.Fatalf("positive population rejected: %v", row)
				}
			} else if row[4] == verdictPass || row[7] != "" {
				t.Fatalf("unknown population qualified: %v", row)
			}
		})
	}
}

func TestReviewR3ReceiptSemantics(t *testing.T) {
	for _, tc := range []struct{ name, kind, field, value string }{
		{"v1-method", recordTypeAction, "method", "POST"},
		{"v1-transport", recordTypeAction, "transport", "fetch"},
		{"v1-action", recordTypeAction, "action_type", "write"},
		{"v1-query", recordTypeAction, "target", sinkTarget(synthSink, "wk=s1-m000000&extra=value")},
		{"v2-transport", recordTypeEvidence, "transport", "mcp_http"},
		{"v2-action", recordTypeEvidence, "action_type", "mcp_tool_call"},
		{"v2-verdict", recordTypeEvidence, "verdict", verdictBlock},
		{"v2-payload-kind", recordTypeEvidence, "payload_kind", "contract_drift"},
		{"v2-query", recordTypeEvidence, "target", sinkTarget(synthSink, "wk=s1-m000000&extra=value")},
		{"native-class", "ael", "class", "write"},
		{"native-direction", "ael", "dir", "out"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			plan := newWorkload(1, 0, 1) // This seed makes the request allowed.
			dir := t.TempDir()
			writeSynthRecorder(t, dir, plan, synthSink, perfectReceipts(plan, modeBest))
			if _, err := scanRecorder(dir, plan, synthSink); err != nil {
				t.Fatalf("producer-shaped positive control: %v", err)
			}
			path := filepath.Join(dir, "evidence-proxy.run.x-0.jsonl")
			if tc.kind == "ael" {
				path = filepath.Join(dir, "ael", "run0", "recorders", "pipelock.jsonl")
			}
			data, err := os.ReadFile(filepath.Clean(path))
			if err != nil {
				t.Fatal(err)
			}
			lines := strings.Split(string(data), "\n")
			changed := false
			for i, line := range lines {
				raw := []byte(line)
				if tc.kind == "ael" {
					payload, _, _ := strings.Cut(line, ".")
					raw, _ = base64.RawURLEncoding.DecodeString(payload)
				}
				if !strings.Contains(string(raw), plan.key(0)) && (tc.kind != "ael" || !strings.Contains(string(raw), actionIDFor(0))) {
					continue
				}
				var value map[string]any
				if err := json.Unmarshal(raw, &value); err != nil {
					t.Fatal(err)
				}
				var fields map[string]any
				if tc.kind == "ael" {
					fields = value["event"].(map[string]any)
				} else {
					if value["type"] != tc.kind {
						continue
					}
					detail := value["detail"].(map[string]any)
					if tc.field == "payload_kind" {
						fields = detail
					} else if tc.kind == recordTypeAction {
						fields = detail["action_record"].(map[string]any)
					} else {
						fields = detail["payload"].(map[string]any)
					}
				}
				fields[tc.field] = tc.value
				raw, err = json.Marshal(value)
				if err != nil {
					t.Fatal(err)
				}
				lines[i] = string(raw)
				if tc.kind == "ael" {
					lines[i] = base64.RawURLEncoding.EncodeToString(raw) + ".c2ln"
				}
				changed = true
				break
			}
			if !changed {
				t.Fatal("mutation matched no workload record")
			}
			writeReviewFile(t, path, strings.Join(lines, "\n"))
			if _, err := scanRecorder(dir, plan, synthSink); err == nil {
				t.Fatal("record for another request shape or decision accepted")
			}
		})
	}
}

func TestReviewR3QuotaHierarchy(t *testing.T) {
	for _, tc := range []struct{ name, parent, child, want string }{
		{"parent-tighter", "100000 100000", "200000 100000", "100000/100000"},
		{"child-tighter", "800000 100000", "200000 100000", "200000/100000"},
		{"parent-fractional", "150000 100000", "200000 100000", "150000/100000"},
		{"different-periods", "300000 200000", "200000 100000", "300000/200000"},
		{"unbounded-child", "200000 100000", "max 100000", "200000/100000"},
		{"invalid-parent", "not-a-quota", "200000 100000", "unavailable:"},
		{"missing-parent", "", "200000 100000", "unavailable:"},
		{"zero-parent-period", "100000 0", "200000 100000", "unavailable:"},
		{"invalid-unbounded-period", "max invalid", "200000 100000", "unavailable:"},
		{"zero-parent-quota", "0 100000", "200000 100000", "unavailable:"},
		{"overflow-parent", "9223372036854775808 100000", "200000 100000", "unavailable:"},
		{"overflow-comparison", "9223372036854775807 9223372036854775807", "9223372036854775807 100000", "9223372036854775807/9223372036854775807"},
		{"all-unbounded", "max 100000", "max 100000", "none visible"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			if err := os.MkdirAll(filepath.Join(root, "parent", "child"), 0o750); err != nil {
				t.Fatal(err)
			}
			if tc.parent != "" {
				writeReviewFile(t, filepath.Join(root, "parent", "cpu.max"), tc.parent+"\n")
			}
			writeReviewFile(t, filepath.Join(root, "parent", "child", "cpu.max"), tc.child+"\n")
			got := cgroupCPUQuotaFrom(root, "/parent/child")
			if !strings.HasPrefix(got, tc.want) {
				t.Fatalf("quota hierarchy: got %q, want prefix %q", got, tc.want)
			}
		})
	}
}

func TestReviewR3QuotaUnavailable(t *testing.T) {
	root := t.TempDir()
	if got := cgroupCPUQuotaFrom(root, "/"); got != "none visible" {
		t.Fatalf("unified root without cpu.max: %q", got)
	}
	if err := os.Mkdir(filepath.Join(root, "child"), 0o750); err != nil {
		t.Fatal(err)
	}
	if got := cgroupCPUQuotaFrom(root, "/child"); !strings.HasPrefix(got, "unavailable:") {
		t.Fatalf("unreadable child hierarchy: %q", got)
	}
	if err := os.Mkdir(filepath.Join(root, "cpu.max"), 0o750); err != nil {
		t.Fatal(err)
	}
	if got := cgroupCPUQuotaFrom(root, "/"); !strings.HasPrefix(got, "unavailable:") {
		t.Fatalf("unreadable root interface: %q", got)
	}
}

func TestReviewR3SampleIdentity(t *testing.T) {
	for _, scenario := range []string{"distinct", "duplicate", "missing"} {
		t.Run(scenario, func(t *testing.T) {
			a, b := fakeResult(100, 80, 90, verdictPass, perfMeasured), fakeResult(100, 80, 90, verdictPass, perfMeasured)
			a.Inputs.Workload.Tag, b.Inputs.Workload.Tag = "s1-rfirst", "s1-rsecond"
			switch scenario {
			case "duplicate":
				b.Inputs.Workload.Tag = a.Inputs.Workload.Tag
			case "missing":
				b.Inputs.Workload.Tag = ""
			}
			row := summaryRow(2, 1, modeRequired, 2, []result{a, b})
			if scenario == "distinct" {
				if row[4] != verdictPass || row[7] != "100.0" {
					t.Fatalf("independent samples rejected: %v", row)
				}
			} else if row[4] == verdictPass || row[7] != "" {
				t.Fatalf("unidentified or repeated run accepted as two samples: %v", row)
			}
		})
	}
}
