// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Command receipt-load drives a real Pipelock forward proxy and local sink.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"
)

const fakeToken = "ghp_" + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

type result struct {
	Mode                 string         `json:"mode"`
	Requests             int            `json:"requests"`
	Concurrency          int            `json:"concurrency"`
	Seconds              float64        `json:"seconds"`
	RequestsPerSecond    float64        `json:"requests_per_second"`
	P50MS                float64        `json:"p50_ms"`
	P95MS                float64        `json:"p95_ms"`
	P99MS                float64        `json:"p99_ms"`
	Allowed              int            `json:"allowed"`
	Blocked              int            `json:"blocked"`
	Unexpected           int            `json:"unexpected"`
	Errors               int            `json:"errors"`
	StatusCounts         map[int]int    `json:"status_counts"`
	ResponseSamples      map[int]string `json:"response_samples"`
	SinkRequests         int64          `json:"sink_requests"`
	CPUSeconds           float64        `json:"cpu_seconds"`
	CPUCores             float64        `json:"cpu_cores_average"`
	RSSStartBytes        int64          `json:"rss_start_bytes"`
	RSSEndBytes          int64          `json:"rss_end_bytes"`
	RSSPeakBytes         int64          `json:"rss_peak_bytes"`
	EvidenceBytes        int64          `json:"evidence_bytes"`
	ReceiptEntries       int            `json:"receipt_entries"`
	ReceiptAllowRequests int            `json:"receipt_allow_requests"`
	ReceiptBlockRequests int            `json:"receipt_block_requests"`
	ReceiptMissing       int            `json:"receipt_missing"`
	FlushLagMS           float64        `json:"last_receipt_after_last_response_ms"`
	RecorderFileLagMS    float64        `json:"last_recorder_file_write_after_last_response_ms"`
	VerifyExit           int            `json:"verify_exit"`
	VerifyOutput         string         `json:"verify_output"`
	RecorderFiles        int            `json:"recorder_files"`
}

type procSample struct {
	at    time.Time
	ticks uint64
	rss   int64
}

func main() {
	binary := flag.String("binary", "./pipelock", "pipelock binary")
	out := flag.String("out", "", "unique output directory")
	n := flag.Int("requests", 1000000, "requests per mode")
	concurrency := flag.Int("concurrency", 128, "concurrent clients")
	modes := flag.String("modes", "off,best,required", "comma-separated modes")
	flag.Parse()
	if *out == "" || *n < 1 || *concurrency < 1 {
		log.Fatal("--out, positive --requests, and positive --concurrency are required")
	}
	absBinary, err := filepath.Abs(*binary)
	if err != nil {
		log.Fatal(err)
	}
	if info, statErr := os.Stat(absBinary); statErr != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		log.Fatalf("binary %q is not an executable regular file", absBinary)
	}
	if err := os.MkdirAll(*out, 0o750); err != nil {
		log.Fatal(err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}
	var sinkCount atomic.Int64
	sink := &http.Server{ReadHeaderTimeout: 5 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		sinkCount.Add(1)
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "ok")
	})}
	go func() { _ = sink.Serve(listener) }()
	defer func() { _ = sink.Shutdown(context.Background()) }()
	for _, mode := range strings.Split(*modes, ",") {
		if mode != "off" && mode != "best" && mode != "required" {
			log.Fatalf("invalid mode %q", mode)
		}
		if err := run(ctx, absBinary, *out, mode, *n, *concurrency, listener.Addr().String(), &sinkCount); err != nil {
			log.Fatalf("%s: %v", mode, err)
		}
	}
}

// localCommand builds a command for the validated local test binary. The
// context is attached through exec.CommandContext with a constant name; the
// resolved path and arguments are then set explicitly.
func localCommand(ctx context.Context, binary string, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, "pipelock")
	cmd.Err = nil
	cmd.Path = binary
	cmd.Args = append([]string{binary}, args...)
	return cmd
}

func run(ctx context.Context, binary, out, mode string, n, concurrency int, sinkAddr string, sinkCount *atomic.Int64) error {
	dir := filepath.Join(out, mode)
	if err := os.Mkdir(dir, 0o750); err != nil {
		return err
	}
	for _, sub := range []string{"home", "scan-home"} {
		if err := os.Mkdir(filepath.Join(dir, sub), 0o750); err != nil {
			return err
		}
	}
	configPath := filepath.Join(dir, "pipelock.yaml")
	args := []string{"init", "--output", configPath, "--home", filepath.Join(dir, "home"), "--scan-home", filepath.Join(dir, "scan-home"), "--no-auditor", "--skip-canary", "--json"}
	initOut, err := localCommand(ctx, binary, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("pipelock init: %w: %s", err, initOut)
	}
	if err := os.WriteFile(filepath.Join(dir, "init.json"), initOut, 0o600); err != nil {
		return err
	}
	data, err := os.ReadFile(filepath.Clean(configPath))
	if err != nil {
		return err
	}
	var cfg map[string]any
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return err
	}
	cfg["fetch_proxy"].(map[string]any)["monitoring"].(map[string]any)["max_requests_per_minute"] = 10000000
	cfg["forward_proxy"].(map[string]any)["enabled"] = true
	cfg["ssrf"].(map[string]any)["ip_allowlist"] = []string{"127.0.0.1/32"}
	fr := cfg["flight_recorder"].(map[string]any)
	fr["enabled"] = mode != "off"
	fr["require_receipts"] = mode == "required"
	data, err = yaml.Marshal(cfg)
	if err != nil {
		return err
	}
	if err := os.WriteFile(configPath, data, 0o600); err != nil {
		return err
	}
	checkOut, err := localCommand(ctx, binary, "check", "--config", configPath).CombinedOutput()
	if err != nil {
		return fmt.Errorf("pipelock check: %w: %s", err, checkOut)
	}
	if err := os.WriteFile(filepath.Join(dir, "check.txt"), checkOut, 0o600); err != nil {
		return err
	}
	port, err := freePort(ctx)
	if err != nil {
		return err
	}
	proxyAddr := fmt.Sprintf("127.0.0.1:%d", port)
	proxyLog, err := os.OpenFile(filepath.Clean(filepath.Join(dir, "proxy.log")), os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer func() { _ = proxyLog.Close() }()
	cmd := localCommand(context.WithoutCancel(ctx), binary, "run", "--config", configPath, "--home", filepath.Join(dir, "home"), "--listen", proxyAddr)
	cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
	cmd.WaitDelay = 30 * time.Second
	cmd.Stdout, cmd.Stderr = proxyLog, proxyLog
	if err := cmd.Start(); err != nil {
		return err
	}
	stopped := false
	defer func() {
		if !stopped {
			_ = cmd.Process.Signal(syscall.SIGTERM)
			_ = cmd.Wait()
		}
	}()
	if err := awaitProxy(ctx, proxyAddr); err != nil {
		return err
	}
	log.Printf("%s: proxy ready; %d requests at concurrency %d", mode, n, concurrency)
	samplesFile, err := os.OpenFile(filepath.Clean(filepath.Join(dir, "samples.csv")), os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer func() { _ = samplesFile.Close() }()
	_, _ = io.WriteString(samplesFile, "unix_ns,cpu_ticks,rss_bytes,evidence_bytes\n")
	startSample, err := readProc(cmd.Process.Pid)
	if err != nil {
		return err
	}
	stopSamples := make(chan struct{})
	sampleDone := make(chan struct{})
	var peakRSS atomic.Int64
	var lastSample procSample
	go func() {
		defer close(sampleDone)
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				s, readErr := readProc(cmd.Process.Pid)
				if readErr == nil {
					lastSample = s
					for old := peakRSS.Load(); s.rss > old && !peakRSS.CompareAndSwap(old, s.rss); old = peakRSS.Load() {
					}
					_, _ = fmt.Fprintf(samplesFile, "%d,%d,%d,%d\n", s.at.UnixNano(), s.ticks, s.rss, evidenceBytes(filepath.Join(dir, "recorder")))
				}
			case <-stopSamples:
				return
			}
		}
	}()
	proxyURL, _ := url.Parse("http://" + proxyAddr)
	transport := &http.Transport{Proxy: http.ProxyURL(proxyURL), MaxIdleConns: concurrency * 2, MaxIdleConnsPerHost: concurrency * 2, MaxConnsPerHost: concurrency * 2, IdleConnTimeout: time.Minute}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 30 * time.Second}
	latency := make([]int64, n)
	status := make([]int, n)
	bodies := make([]string, 3)
	jobs := make(chan int, concurrency)
	var wg sync.WaitGroup
	start := time.Now()
	for range concurrency {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				target := fmt.Sprintf("http://%s/ok?id=%d", sinkAddr, i)
				if i%20 == 0 {
					target += "&token=" + fakeToken
				}
				req, reqErr := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
				if reqErr != nil {
					status[i] = -1
					continue
				}
				before := time.Now()
				resp, doErr := client.Do(req)
				latency[i] = time.Since(before).Nanoseconds()
				if doErr != nil {
					status[i] = -1
					continue
				}
				if i < len(bodies) {
					body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
					bodies[i] = string(body)
				} else {
					_, _ = io.Copy(io.Discard, resp.Body)
				}
				_ = resp.Body.Close()
				status[i] = resp.StatusCode
			}
		}()
	}
	sinkBefore := sinkCount.Load()
	for i := range n {
		jobs <- i
	}
	close(jobs)
	wg.Wait()
	end := time.Now()
	close(stopSamples)
	<-sampleDone
	endSample, _ := readProc(cmd.Process.Pid)
	if endSample.at.IsZero() {
		endSample = lastSample
	}
	if endSample.rss > peakRSS.Load() {
		peakRSS.Store(endSample.rss)
	}
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		return err
	}
	if err := cmd.Wait(); err != nil {
		return fmt.Errorf("proxy did not shut down cleanly: %w", err)
	}
	stopped = true
	r := result{Mode: mode, Requests: n, Concurrency: concurrency, Seconds: end.Sub(start).Seconds(), SinkRequests: sinkCount.Load() - sinkBefore, RSSStartBytes: startSample.rss, RSSEndBytes: endSample.rss, RSSPeakBytes: peakRSS.Load()}
	r.StatusCounts = make(map[int]int)
	r.ResponseSamples = make(map[int]string)
	for i, body := range bodies {
		r.ResponseSamples[i] = body
	}
	r.RequestsPerSecond = float64(n) / r.Seconds
	for i, code := range status {
		r.StatusCounts[code]++
		switch {
		case code == -1:
			r.Errors++
		case i%20 == 0 && code == http.StatusForbidden:
			r.Blocked++
		case i%20 != 0 && code == http.StatusOK:
			r.Allowed++
		default:
			r.Unexpected++
		}
	}
	sort.Slice(latency, func(i, j int) bool { return latency[i] < latency[j] })
	r.P50MS, r.P95MS, r.P99MS = quantile(latency, 0.50), quantile(latency, 0.95), quantile(latency, 0.99)
	if ticks, tickErr := clockTicks(ctx); tickErr == nil && endSample.ticks >= startSample.ticks {
		r.CPUSeconds = float64(endSample.ticks-startSample.ticks) / ticks
		r.CPUCores = r.CPUSeconds / r.Seconds
	}
	if mode != "off" {
		if err := scanReceipts(filepath.Join(dir, "recorder"), n, &r, end); err != nil {
			return err
		}
		pubKey := filepath.Join(dir, "keys", "flight-recorder-signing.key.pub")
		verify, verifyErr := localCommand(ctx, binary, "verify-receipt", "--chain", filepath.Join(dir, "recorder"), "--whole-recorder", "--require-seal", "--key", pubKey).CombinedOutput()
		r.VerifyOutput = string(verify)
		if verifyErr != nil {
			var exitErr *exec.ExitError
			if errors.As(verifyErr, &exitErr) {
				r.VerifyExit = exitErr.ExitCode()
			} else {
				r.VerifyExit = -1
			}
		}
		if err := os.WriteFile(filepath.Join(dir, "verify.txt"), verify, 0o600); err != nil {
			return err
		}
	}
	r.EvidenceBytes = evidenceBytes(filepath.Join(dir, "recorder"))
	jsonResult, _ := json.MarshalIndent(r, "", "  ")
	if err := os.WriteFile(filepath.Join(dir, "result.json"), append(jsonResult, '\n'), 0o600); err != nil {
		return err
	}
	log.Printf("%s: %.0f req/s, allow=%d block=%d unexpected=%d errors=%d receipt missing=%d verify=%d", mode, r.RequestsPerSecond, r.Allowed, r.Blocked, r.Unexpected, r.Errors, r.ReceiptMissing, r.VerifyExit)
	if r.Unexpected != 0 || r.Errors != 0 || !strings.Contains(r.ResponseSamples[0], "GitHub Token") || (mode != "off" && (r.ReceiptMissing != 0 || r.VerifyExit != 0)) {
		return fmt.Errorf("finding: inspect %s", filepath.Join(dir, "result.json"))
	}
	return nil
}

func freePort(ctx context.Context) (int, error) {
	l, err := (&net.ListenConfig{}).Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	port := l.Addr().(*net.TCPAddr).Port
	return port, l.Close()
}

func awaitProxy(ctx context.Context, addr string) error {
	deadline := time.NewTimer(10 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		conn, err := (&net.Dialer{Timeout: 100 * time.Millisecond}).DialContext(ctx, "tcp", addr)
		if err == nil {
			_ = conn.Close()
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return fmt.Errorf("proxy did not listen on %s", addr)
		case <-ticker.C:
		}
	}
}

func readProc(pid int) (procSample, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return procSample{}, err
	}
	end := strings.LastIndexByte(string(data), ')')
	if end < 0 {
		return procSample{}, fmt.Errorf("invalid proc stat")
	}
	fields := strings.Fields(string(data[end+1:]))
	if len(fields) < 22 {
		return procSample{}, fmt.Errorf("short proc stat")
	}
	u, err := strconv.ParseUint(fields[11], 10, 64)
	if err != nil {
		return procSample{}, err
	}
	s, err := strconv.ParseUint(fields[12], 10, 64)
	if err != nil {
		return procSample{}, err
	}
	rssPages, err := strconv.ParseInt(fields[21], 10, 64)
	if err != nil {
		return procSample{}, err
	}
	return procSample{at: time.Now(), ticks: u + s, rss: rssPages * int64(os.Getpagesize())}, nil
}

func clockTicks(ctx context.Context) (float64, error) {
	out, err := exec.CommandContext(ctx, "getconf", "CLK_TCK").Output()
	if err != nil {
		return 0, err
	}
	return strconv.ParseFloat(strings.TrimSpace(string(out)), 64)
}

func quantile(sorted []int64, p float64) float64 {
	index := int(float64(len(sorted)-1) * p)
	return float64(sorted[index]) / 1e6
}

func evidenceBytes(dir string) int64 {
	var total int64
	_ = filepath.WalkDir(dir, func(_ string, entry os.DirEntry, err error) error {
		if err == nil && !entry.IsDir() {
			if info, statErr := entry.Info(); statErr == nil {
				total += info.Size()
			}
		}
		return nil
	})
	return total
}

func scanReceipts(dir string, n int, r *result, end time.Time) error {
	seen := make([]uint8, n)
	var latest time.Time
	var lastReceipt time.Time
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	err = filepath.WalkDir(dir, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil || entry.IsDir() || !strings.HasPrefix(filepath.Base(path), "evidence-") || !strings.HasSuffix(path, ".jsonl") {
			return walkErr
		}
		r.RecorderFiles++
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		f, err := root.Open(rel)
		if err != nil {
			return err
		}
		defer func() { _ = f.Close() }()
		scanner := bufio.NewScanner(f)
		scanner.Buffer(make([]byte, 64*1024), 8*1024*1024)
		lineNumber := 0
		for scanner.Scan() {
			lineNumber++
			var record struct {
				Type   string          `json:"type"`
				TS     time.Time       `json:"ts"`
				Detail json.RawMessage `json:"detail"`
			}
			if err := json.Unmarshal(scanner.Bytes(), &record); err != nil {
				return fmt.Errorf("%s:%d envelope: %w", path, lineNumber, err)
			}
			if record.Type != "action_receipt" {
				continue
			}
			var detail struct {
				ActionRecord struct {
					Target  string `json:"target"`
					Verdict string `json:"verdict"`
				} `json:"action_record"`
			}
			if err := json.Unmarshal(record.Detail, &detail); err != nil {
				return fmt.Errorf("%s:%d action detail: %w", path, lineNumber, err)
			}
			if detail.ActionRecord.Target == "" {
				continue
			}
			r.ReceiptEntries++
			u, err := url.Parse(detail.ActionRecord.Target)
			if err != nil {
				continue
			}
			i, err := strconv.Atoi(u.Query().Get("id"))
			if err != nil || i < 0 || i >= n {
				continue
			}
			if record.TS.After(lastReceipt) {
				lastReceipt = record.TS
			}
			if detail.ActionRecord.Verdict == "allow" {
				seen[i] |= 1
			}
			if detail.ActionRecord.Verdict == "block" {
				seen[i] |= 2
			}
		}
		if err := scanner.Err(); err != nil {
			return err
		}
		if info, err := os.Stat(path); err == nil && info.ModTime().After(latest) {
			latest = info.ModTime()
		}
		return nil
	})
	if err != nil {
		return err
	}
	for i, bits := range seen {
		if i%20 == 0 {
			if bits&2 != 0 {
				r.ReceiptBlockRequests++
			} else {
				r.ReceiptMissing++
			}
		} else if bits&1 != 0 {
			r.ReceiptAllowRequests++
		} else {
			r.ReceiptMissing++
		}
	}
	if latest.After(end) {
		r.RecorderFileLagMS = float64(latest.Sub(end).Nanoseconds()) / 1e6
	}
	if lastReceipt.After(end) {
		r.FlushLagMS = float64(lastReceipt.Sub(end).Nanoseconds()) / 1e6
	}
	return nil
}
