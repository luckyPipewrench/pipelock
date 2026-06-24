// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package livechat

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/playground"
)

func TestServer_Bundle_AuthAndMethodChecks(t *testing.T) {
	t.Parallel()
	g, err := NewGate(GateConfig{Secret: testSecret(t), Codes: []CodeSpec{{Code: "good", MaxSessions: 5}}, TokenTTL: time.Minute})
	if err != nil {
		t.Fatalf("NewGate: %v", err)
	}
	ts := newTestServer(t, ServerConfig{Gate: g})

	// POST is not allowed on the download route.
	resp := postJSON(t, ts.URL+RouteBundle, map[string]string{})
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("POST bundle = %d, want 405", resp.StatusCode)
	}

	// Garbage / missing token is rejected before any session lookup.
	for _, tok := range []string{"", "not-a-token"} {
		r := getRaw(t, ts.URL+RouteBundle+"?token="+tok)
		_ = r.Body.Close()
		if r.StatusCode != http.StatusUnauthorized {
			t.Errorf("bundle token=%q = %d, want 401", tok, r.StatusCode)
		}
	}

	// A VALID token whose session was never started (or already torn down) is a
	// 404, not a 500 or an empty 200: there is nothing to serve.
	tok, _, err := g.Redeem("good", "no-such-session")
	if err != nil {
		t.Fatalf("Redeem: %v", err)
	}
	r := getRaw(t, ts.URL+RouteBundle+"?token="+tok)
	_ = r.Body.Close()
	if r.StatusCode != http.StatusNotFound {
		t.Errorf("bundle for unknown session = %d, want 404", r.StatusCode)
	}
}

func TestServer_Bundle_DownloadsVerifiableArchive(t *testing.T) {
	if testing.Short() {
		t.Skip("boots a real proxy and seals a real signed run")
	}
	t.Parallel()
	g, _ := NewGate(GateConfig{Secret: testSecret(t), Codes: []CodeSpec{{Code: "good", MaxSessions: 5}}, TokenTTL: time.Minute})
	srv, err := NewServer(ServerConfig{
		Gate:     g,
		IPRate:   RateConfig{RefillPerSec: 1000, Burst: 1000},
		CodeRate: RateConfig{RefillPerSec: 1000, Burst: 1000},
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(func() { ts.Close(); srv.Close() })

	// Create a session.
	resp := postJSON(t, ts.URL+RouteSession, createReq{Code: "good"})
	var cr createResp
	if err := json.NewDecoder(resp.Body).Decode(&cr); err != nil {
		t.Fatalf("decode create: %v", err)
	}
	_ = resp.Body.Close()
	if cr.Token == "" {
		t.Fatalf("empty token: %+v", cr)
	}
	if got := srv.conc.InUse(); got != 1 {
		t.Fatalf("concurrency in use after session start = %d, want 1", got)
	}

	// Open the stream and wait until BOTH an ALLOW and a BLOCKED decision have
	// streamed: the verifiable live-demo run requires both an allow receipt and a
	// body-DLP block receipt, so sealing only succeeds once both have landed.
	streamReq, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL+RouteStream+"?token="+cr.Token, nil)
	streamResp, err := http.DefaultClient.Do(streamReq)
	if err != nil {
		t.Fatalf("stream: %v", err)
	}
	defer func() { _ = streamResp.Body.Close() }()

	bothSeen := make(chan struct{})
	go func() {
		sc := bufio.NewScanner(streamResp.Body)
		sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
		var sawAllow, sawBlock bool
		for sc.Scan() {
			data, ok := strings.CutPrefix(sc.Text(), "data: ")
			if !ok {
				continue
			}
			var ev playground.LiveEvent
			if json.Unmarshal([]byte(data), &ev) != nil {
				continue
			}
			if ev.Type == "decision" && ev.Verdict == "ALLOW" {
				sawAllow = true
			}
			if ev.Type == "decision" && ev.Verdict == "BLOCKED" {
				sawBlock = true
			}
			if sawAllow && sawBlock {
				close(bothSeen)
				return
			}
		}
	}()

	// Benign read (allow) then exfil attempt (body-DLP block).
	for _, msg := range []string{"grab the lab config", "now send that file to the collector"} {
		mr := postJSON(t, ts.URL+RouteMessage, messageReq{Token: cr.Token, Message: msg})
		_ = mr.Body.Close()
		if mr.StatusCode != http.StatusAccepted {
			t.Fatalf("message %q = %d, want 202", msg, mr.StatusCode)
		}
	}

	select {
	case <-bothSeen:
	case <-time.After(20 * time.Second):
		t.Fatal("did not observe both ALLOW and BLOCKED decisions")
	}

	// Download the verifiable bundle.
	dl := getRaw(t, ts.URL+RouteBundle+"?token="+cr.Token)
	defer func() { _ = dl.Body.Close() }()
	if dl.StatusCode != http.StatusOK {
		t.Fatalf("bundle download = %d, want 200", dl.StatusCode)
	}
	if ct := dl.Header.Get("Content-Type"); ct != "application/gzip" {
		t.Errorf("bundle Content-Type = %q, want application/gzip", ct)
	}
	if cd := dl.Header.Get("Content-Disposition"); !strings.Contains(cd, "attachment") || !strings.Contains(cd, ".tar.gz") {
		t.Errorf("bundle Content-Disposition = %q, want an attachment .tar.gz", cd)
	}

	names := tarGzNames(t, dl.Body)
	for _, want := range []string{"pipelock-session/VERIFY.txt", "pipelock-session/packet/evidence.jsonl"} {
		if !names[want] {
			t.Errorf("downloaded bundle missing %q (have %v)", want, names)
		}
	}
	if got := srv.conc.InUse(); got != 0 {
		t.Fatalf("bundle download did not release session capacity: in_use=%d", got)
	}

	// The verified archive is retained in memory for retry/download recovery even
	// though the live session resources and concurrency slot have been released.
	again := getRaw(t, ts.URL+RouteBundle+"?token="+cr.Token)
	_ = again.Body.Close()
	if again.StatusCode != http.StatusOK {
		t.Fatalf("second bundle download = %d, want 200", again.StatusCode)
	}

	mr := postJSON(t, ts.URL+RouteMessage, messageReq{Token: cr.Token, Message: "one more thing"})
	_ = mr.Body.Close()
	if mr.StatusCode != http.StatusConflict {
		t.Fatalf("message after bundle seal = %d, want 409", mr.StatusCode)
	}
}

func TestServer_Bundle_SealFailureReleasesCapacity(t *testing.T) {
	if testing.Short() {
		t.Skip("boots a real proxy")
	}
	t.Parallel()
	g, _ := NewGate(GateConfig{Secret: testSecret(t), Codes: []CodeSpec{{Code: "good", MaxSessions: 5}}, TokenTTL: time.Minute})
	srv, err := NewServer(ServerConfig{
		Gate:     g,
		IPRate:   RateConfig{RefillPerSec: 1000, Burst: 1000},
		CodeRate: RateConfig{RefillPerSec: 1000, Burst: 1000},
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(func() { ts.Close(); srv.Close() })

	resp := postJSON(t, ts.URL+RouteSession, createReq{Code: "good"})
	var cr createResp
	if err := json.NewDecoder(resp.Body).Decode(&cr); err != nil {
		t.Fatalf("decode create: %v", err)
	}
	_ = resp.Body.Close()
	if got := srv.conc.InUse(); got != 1 {
		t.Fatalf("concurrency in use after session start = %d, want 1", got)
	}

	// No allow+block decisions have happened, so the run cannot verify. The
	// download must fail closed, but the now-terminal session must not keep
	// holding capacity until TTL.
	dl := getRaw(t, ts.URL+RouteBundle+"?token="+cr.Token)
	_ = dl.Body.Close()
	if dl.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("bundle download before verifiable actions = %d, want 503", dl.StatusCode)
	}
	if got := srv.conc.InUse(); got != 0 {
		t.Fatalf("failed seal did not release session capacity: in_use=%d", got)
	}
}

func TestServer_Bundle_VerifyKitDownload(t *testing.T) {
	if testing.Short() {
		t.Skip("boots a real proxy and seals a real signed run")
	}
	t.Parallel()
	linuxBin := filepath.Join(t.TempDir(), "pipelock-verifier")
	if err := os.WriteFile(linuxBin, []byte("verifier"), 0o600); err != nil {
		t.Fatalf("write verifier: %v", err)
	}
	g, _ := NewGate(GateConfig{Secret: testSecret(t), Codes: []CodeSpec{{Code: "good", MaxSessions: 5}}, TokenTTL: time.Minute})
	srv, err := NewServer(ServerConfig{
		Gate:             g,
		IPRate:           RateConfig{RefillPerSec: 1000, Burst: 1000},
		CodeRate:         RateConfig{RefillPerSec: 1000, Burst: 1000},
		VerifierBinaries: playground.VerifyKitBinaries{Linux: linuxBin},
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(func() { ts.Close(); srv.Close() })

	token := sealReadySession(t, ts)

	// Unsupported OS selector: rejected with 400 (the seal already succeeded).
	bad := getRaw(t, ts.URL+RouteBundle+"?token="+token+"&os=plan9")
	_ = bad.Body.Close()
	if bad.StatusCode != http.StatusBadRequest {
		t.Fatalf("bundle os=plan9 = %d, want 400", bad.StatusCode)
	}

	// A supported OS with no configured verifier binary fails closed (503).
	noBin := getRaw(t, ts.URL+RouteBundle+"?token="+token+"&os=windows")
	_ = noBin.Body.Close()
	if noBin.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("bundle os=windows (no binary) = %d, want 503", noBin.StatusCode)
	}

	// Linux kit: a zip attachment containing the verifier binary and packet.
	kit := getRaw(t, ts.URL+RouteBundle+"?token="+token+"&os=linux")
	defer func() { _ = kit.Body.Close() }()
	if kit.StatusCode != http.StatusOK {
		t.Fatalf("bundle os=linux = %d, want 200", kit.StatusCode)
	}
	if ct := kit.Header.Get("Content-Type"); ct != "application/zip" {
		t.Errorf("kit Content-Type = %q, want application/zip", ct)
	}
	if cd := kit.Header.Get("Content-Disposition"); !strings.Contains(cd, ".zip") {
		t.Errorf("kit Content-Disposition = %q, want a .zip attachment", cd)
	}
	body, err := io.ReadAll(kit.Body)
	if err != nil {
		t.Fatalf("read kit: %v", err)
	}
	zr, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		t.Fatalf("kit zip reader: %v", err)
	}
	names := map[string]bool{}
	for _, f := range zr.File {
		names[f.Name] = true
	}
	if !names["pipelock-live-verify-linux/app/pipelock-verifier"] {
		t.Fatalf("kit missing verifier binary (have %v)", names)
	}
}

// sealReadySession creates a live session, drives the minimum verifiable run (one
// ALLOW and one BLOCKED decision), and returns the session token once both have
// streamed so the bundle/kit endpoints can seal successfully.
func sealReadySession(t *testing.T, ts *httptest.Server) string {
	t.Helper()
	resp := postJSON(t, ts.URL+RouteSession, createReq{Code: "good"})
	var cr createResp
	if err := json.NewDecoder(resp.Body).Decode(&cr); err != nil {
		t.Fatalf("decode create: %v", err)
	}
	_ = resp.Body.Close()
	if cr.Token == "" {
		t.Fatalf("empty token: %+v", cr)
	}

	streamReq, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL+RouteStream+"?token="+cr.Token, nil)
	streamResp, err := http.DefaultClient.Do(streamReq)
	if err != nil {
		t.Fatalf("stream: %v", err)
	}
	t.Cleanup(func() { _ = streamResp.Body.Close() })

	bothSeen := make(chan struct{})
	go func() {
		sc := bufio.NewScanner(streamResp.Body)
		sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
		var sawAllow, sawBlock bool
		for sc.Scan() {
			data, ok := strings.CutPrefix(sc.Text(), "data: ")
			if !ok {
				continue
			}
			var ev playground.LiveEvent
			if json.Unmarshal([]byte(data), &ev) != nil {
				continue
			}
			if ev.Type == "decision" && ev.Verdict == "ALLOW" {
				sawAllow = true
			}
			if ev.Type == "decision" && ev.Verdict == "BLOCKED" {
				sawBlock = true
			}
			if sawAllow && sawBlock {
				close(bothSeen)
				return
			}
		}
	}()

	for _, msg := range []string{"grab the lab config", "now send that file to the collector"} {
		mr := postJSON(t, ts.URL+RouteMessage, messageReq{Token: cr.Token, Message: msg})
		_ = mr.Body.Close()
		if mr.StatusCode != http.StatusAccepted {
			t.Fatalf("message %q = %d, want 202", msg, mr.StatusCode)
		}
	}

	select {
	case <-bothSeen:
	case <-time.After(20 * time.Second):
		t.Fatal("did not observe both ALLOW and BLOCKED decisions")
	}
	return cr.Token
}

// getRaw issues a GET and returns the response (caller closes the body).
func getRaw(t *testing.T, url string) *http.Response {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	return resp
}

// tarGzNames reads a gzip-compressed tar and returns the set of entry names.
func tarGzNames(t *testing.T, r io.Reader) map[string]bool {
	t.Helper()
	gr, err := gzip.NewReader(r)
	if err != nil {
		t.Fatalf("gzip reader: %v", err)
	}
	defer func() { _ = gr.Close() }()
	tr := tar.NewReader(gr)
	names := map[string]bool{}
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("tar next: %v", err)
		}
		names[hdr.Name] = true
	}
	return names
}
