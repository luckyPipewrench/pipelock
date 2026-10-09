// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

const fakePrefix = "fake-pipelock-"

var testLockFile = flag.String("lock-file", "", "advisory lock held while the tests run")

// TestMain lets the test binary double as a fake pipelock. A copy of the test
// binary named fake-pipelock-<behavior> answers the pipelock subcommands the
// harness calls, so failure paths (a proxy that fails or hangs at shutdown, a
// failing verifier) are exercised without the real proxy.
func TestMain(m *testing.M) {
	if base := filepath.Base(os.Args[0]); strings.HasPrefix(base, fakePrefix) {
		os.Exit(fakeMain(strings.TrimPrefix(base, fakePrefix), os.Args[1:]))
	}
	// A machine that serializes benchmark runs can pass its lock file here so
	// the tests that start a real proxy wait their turn too:
	//   go test ./scripts/receipt-load -args -lock-file=PATH
	flag.Parse()
	release := func() {}
	if path := *testLockFile; path != "" {
		var err error
		if release, err = holdLock(path); err != nil {
			fmt.Fprintln(os.Stderr, "lock:", err)
			os.Exit(2)
		}
	}
	code := m.Run()
	release()
	os.Exit(code)
}

// newFakePipelock links the test binary under a name that selects a fake
// behavior and returns its path.
func newFakePipelock(t *testing.T, behavior string) string {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), fakePrefix+behavior)
	if err := os.Symlink(self, path); err != nil {
		t.Fatal(err)
	}
	return path
}

func flagValue(args []string, name string) string {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == name {
			return args[i+1]
		}
	}
	return ""
}

const fakeConfig = `fetch_proxy:
  monitoring:
    max_requests_per_minute: 1
forward_proxy:
  enabled: false
ssrf:
  ip_allowlist: []
flight_recorder:
  enabled: false
  require_receipts: false
  receipt_chains: 1
mcp_tool_policy:
  quarantine_dir: /tmp/pipelock-quarantine
`

func fakeMain(behavior string, args []string) int {
	if behavior == "harness" {
		return realMain(args)
	}
	if len(args) == 0 {
		return 2
	}
	switch args[0] {
	case "init":
		out := flagValue(args, "--output")
		keys := filepath.Join(filepath.Dir(out), "keys")
		if behavior == "initfail" {
			fmt.Fprintln(os.Stderr, "fake init failure")
			return 1
		}
		if os.MkdirAll(keys, 0o750) != nil || os.WriteFile(out, []byte(fakeConfig), 0o600) != nil {
			return 1
		}
		fmt.Println("{}")
		return 0
	case "check":
		fmt.Println("Config validation: OK")
		return 0
	case "version":
		fmt.Println("pipelock version fake")
		return 0
	case "verify-receipt":
		if behavior == "verifyfail" {
			fmt.Println("CHAIN_BROKEN")
			return 1
		}
		fmt.Println("GROUP_VALID")
		return 0
	case "run":
		return fakeRun(behavior, flagValue(args, "--listen"))
	}
	return 2
}

// fakeRun is a minimal forward proxy: it blocks the synthetic credential and
// relays everything else, so the harness sees realistic responses.
func fakeRun(behavior, listen string) int {
	transport := &http.Transport{Proxy: nil}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.RawQuery, "token=") {
			w.WriteHeader(http.StatusForbidden)
			_, _ = io.WriteString(w, "blocked: core DLP match: GitHub Token (critical)\n")
			return
		}
		out := r.Clone(r.Context())
		out.RequestURI = ""
		resp, err := transport.RoundTrip(out)
		if err != nil {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		defer func() { _ = resp.Body.Close() }()
		if behavior == "badbody" || (behavior == "warmbadbody" && strings.Contains(r.URL.Query().Get(workloadKeyParam), "-w")) {
			// The origin was reached, but the client's body read fails.
			conn, buf, hijackErr := w.(http.Hijacker).Hijack()
			if hijackErr == nil {
				_, _ = buf.WriteString("HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nab")
				_ = buf.Flush()
				_ = conn.Close()
			}
			return
		}
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	})
	l, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", listen)
	if err != nil {
		return 1
	}
	srv := &http.Server{Handler: handler, ReadHeaderTimeout: time.Second}
	go func() { _ = srv.Serve(l) }()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM)
	for s := range sig {
		_ = s
		switch behavior {
		case "hang":
			continue
		case "shutdownfail":
			return 7
		}
		return 0
	}
	return 0
}

var (
	realOnce     sync.Once
	realPath     string
	errRealBuild error
)

// realPipelock builds the production binary once per test run. Tests that need
// it are skipped under -short.
func realPipelock(t *testing.T) string {
	t.Helper()
	if testing.Short() {
		t.Skip("builds and runs the real proxy")
	}
	realOnce.Do(func() {
		dir, err := os.MkdirTemp("", "receipt-load-bin-")
		if err != nil {
			errRealBuild = err
			return
		}
		realPath = filepath.Join(dir, "pipelock")
		cmd := exec.CommandContext(context.Background(), "go", "build", "-o", realPath, "./cmd/pipelock") //nolint:gosec // fixed arguments
		cmd.Dir = filepath.Join("..", "..")
		if out, err := cmd.CombinedOutput(); err != nil {
			errRealBuild = fmt.Errorf("go build: %w: %s", err, out)
		}
	})
	if errRealBuild != nil {
		t.Fatal(errRealBuild)
	}
	return realPath
}

// synthetic recorder -------------------------------------------------------

type synthReceipt struct {
	kind     receiptKind
	slot     int
	actionID string
	target   string // overrides the derived target when set
}

func actionIDFor(slot int) string { return fmt.Sprintf("action-%04d", slot) }

// perfectReceipts is exactly the receipt set the mode requires for a plan.
func perfectReceipts(plan workload, mode string) []synthReceipt {
	var out []synthReceipt
	for slot := range plan.total() {
		want := expectedFor(mode, plan.blocked(slot))
		for kind := range kindCount {
			for range want[kind] {
				out = append(out, synthReceipt{kind: kind, slot: slot, actionID: actionIDFor(slot)})
			}
		}
	}
	return out
}

func sinkTarget(sinkAddr, rawQuery string) string { return "http://" + sinkAddr + "/ok?" + rawQuery }

func (r synthReceipt) targetFor(plan workload, sinkAddr string) string {
	if r.target != "" {
		return r.target
	}
	query := workloadKeyParam + "=" + plan.key(r.slot)
	if plan.blocked(r.slot) {
		query += "&token=[redacted-value]"
	}
	return sinkTarget(sinkAddr, query)
}

func v1Line(kind receiptKind, actionID, target string) string {
	record := map[string]any{"action_id": actionID, "target": target, "verdict": verdictAllow}
	switch kind {
	case kindV1Intent:
		record["decision_phase"] = "intent"
	case kindV1Outcome:
		record["decision_phase"] = "outcome"
	case kindV1Block:
		record["verdict"] = verdictBlock
	}
	return envelope(recordTypeAction, map[string]any{"action_record": record})
}

var syntheticEventCounter atomic.Uint64

func v2Line(target string) string {
	return envelope(recordTypeEvidence, map[string]any{"event_id": fmt.Sprintf("event-%d", syntheticEventCounter.Add(1)), "payload": map[string]any{"target": target}})
}

func envelope(typ string, detail map[string]any) string {
	raw, _ := json.Marshal(map[string]any{"v": 2, "type": typ, "ts": time.Now().UTC().Format(time.RFC3339Nano), "detail": detail})
	return string(raw)
}

func aelRecord(typ, id string) string {
	payload, _ := json.Marshal(map[string]any{"type": typ, "event": map[string]any{"id": id}})
	return base64.RawURLEncoding.EncodeToString(payload) + ".c2ln"
}

// writeSynthRecorder lays receipts out like the real recorder: evidence-*.jsonl
// for v1 and v2, and ael/<run>/recorders/pipelock.jsonl for native activity.
// Session-control receipts are included so control handling is exercised.
func writeSynthRecorder(t *testing.T, dir string, plan workload, sinkAddr string, receipts []synthReceipt) {
	t.Helper()
	aelDir := filepath.Join(dir, "ael", "run0", "recorders")
	if err := os.MkdirAll(aelDir, 0o750); err != nil {
		t.Fatal(err)
	}
	evidence := []string{v1Line(kindV1Allow, "control-open", "pipelock://session/open")}
	ael := []string{aelRecord("open", ""), aelRecord("activity", "control-open")}
	for _, r := range receipts {
		target := r.targetFor(plan, sinkAddr)
		switch r.kind {
		case kindV2:
			evidence = append(evidence, v2Line(target))
		case kindAEL:
			ael = append(ael, aelRecord("activity", r.actionID))
		default:
			evidence = append(evidence, v1Line(r.kind, r.actionID, target))
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "evidence-proxy.run.x-0.jsonl"), []byte(strings.Join(evidence, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(aelDir, "pipelock.jsonl"), []byte(strings.Join(ael, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

const synthSink = "127.0.0.1:9"

// evaluateSynth writes receipts, scans them, and evaluates integrity for a
// plan whose clients all saw the expected responses and whose sink saw exactly
// the allowed requests.
func evaluateSynth(t *testing.T, mode string, receipts []synthReceipt) integrityReport {
	t.Helper()
	plan := newWorkload(1, 2, 40)
	dir := t.TempDir()
	writeSynthRecorder(t, dir, plan, synthSink, receipts)
	obs, err := scanRecorder(dir, plan, synthSink)
	if err != nil {
		t.Fatal(err)
	}
	outcomes := make([]requestOutcome, plan.total())
	hits := make([]int, plan.total())
	for slot := range outcomes {
		blocked := plan.blocked(slot)
		out := requestOutcome{ran: true, status: http.StatusOK}
		if blocked {
			out.status = http.StatusForbidden
		} else {
			hits[slot] = 1
		}
		if expectsReceiptHeader(mode, blocked) {
			out.receiptHeader = actionIDFor(slot)
		}
		outcomes[slot] = out
	}
	return evaluateIntegrity(integrityInput{mode: mode, plan: plan, obs: obs, outcomes: outcomes, sinkHits: hits})
}
