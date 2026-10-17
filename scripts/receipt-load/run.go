// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/ael"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

const (
	clientTimeout  = 30 * time.Second
	maxVersionText = 512
)

type options struct {
	binary          string
	out             string
	rules           string
	requests        int
	warmup          int
	concurrency     int
	chains          int
	seed            uint64
	window          time.Duration
	shutdownTimeout time.Duration
	verifyTimeout   time.Duration
	restartAfter    int
	restartBefore   *recorderObservation
}

// runMode runs one recorder mode end to end and always writes result.json once
// its run directory exists, including when setup, shutdown, or verification
// fails. The result starts out failed on both verdicts, so a path that forgets
// to evaluate something cannot report a pass.
func runMode(ctx context.Context, opt options, mode string) (*result, error) {
	name := mode
	if opt.chains > 1 {
		name = fmt.Sprintf("chains-%d-%s", opt.chains, mode)
	}
	dirs := newRunDirs(filepath.Join(opt.out, name))
	if err := dirs.create(); err != nil {
		return nil, err
	}
	plan := newWorkload(opt.seed, opt.warmup, opt.requests)
	nonce := make([]byte, 16)
	_, _ = rand.Read(nonce)
	plan.runNonce = hex.EncodeToString(nonce)
	res := &result{
		SchemaVersion: resultSchemaVersion, Mode: mode, ReceiptChains: opt.chains,
		Requests: opt.requests, WarmupRequests: opt.warmup, Concurrency: opt.concurrency,
		Performance: performanceReport{Verdict: perfInvalid, Reasons: []string{"measurement did not complete"}},
		Integrity:   integrityReport{Verdict: verdictFail, Reasons: []string{"integrity was not evaluated"}},
	}
	res.Inputs.Workload = workloadReport{
		Seed: plan.seed, Tag: plan.tag(), KeyParam: workloadKeyParam,
		BlockEvery: blockEvery, BlockOffset: plan.blockOffset, WindowSeconds: opt.window.Seconds(),
	}
	err := execute(ctx, opt, mode, dirs, plan, res)
	if err != nil {
		res.Integrity.fail("run failed: " + err.Error())
		res.Performance.invalidate("run failed: " + err.Error())
	}
	if writeErr := writeResult(dirs.root, res); writeErr != nil {
		return res, errors.Join(err, writeErr)
	}
	logSummary(mode, res)
	return res, err
}

func logSummary(mode string, res *result) {
	p, i := res.Performance, res.Integrity
	logf("%q: performance=%q integrity=%q %.0f req/s (window min/median %.0f/%.0f) p99 %.2f ms; missing=%d errors=%d unexpected=%d body_read_errors=%d",
		mode, p.Verdict, i.Verdict, p.RequestsPerSecond, p.Windows.MinRPS, p.Windows.MedianRPS, p.Latency.P99MS, i.ReceiptMissing, p.Errors, p.Unexpected, p.BodyReadErrors)
	for _, reason := range p.Reasons {
		logf("%q: performance: %q", mode, reason)
	}
	for _, reason := range i.Reasons {
		logf("%q: integrity: %q", mode, reason)
	}
}

// execute performs the run and fills res. Any error it returns is recorded by
// runMode as a failure of both verdicts.
func execute(ctx context.Context, opt options, mode string, dirs runDirs, plan workload, res *result) error {
	childEnv, envRep := buildChildEnv(os.Environ(), dirs)
	res.Inputs.Env = envRep
	res.Inputs.Host = describeHost(childEnv, opt.out)
	sourceHash, err := harnessSourceSHA256()
	if err != nil {
		return fmt.Errorf("hashing harness source: %w", err)
	}
	res.Inputs.Harness = harnessReport{ContractVersion: harnessContractVersion, SourceSHA256: sourceHash, GoVersion: runtime.Version()}
	pinned, binarySum, err := pinBinary(opt.binary, dirs)
	if err != nil {
		return fmt.Errorf("pinning binary: %w", err)
	}
	opt.binary = pinned
	res.Inputs.Binary = binaryReport{SHA256: binarySum, Version: versionText(ctx, opt.binary, dirs, childEnv)}
	if res.Inputs.Rules, err = prepareRules(opt.rules, dirs); err != nil {
		return err
	}
	configPath, err := prepareConfig(ctx, opt, mode, dirs, childEnv, res)
	if err != nil {
		return err
	}

	sink, err := startSink(ctx, plan)
	if err != nil {
		return err
	}
	defer sink.close()
	port, err := freePort(ctx)
	if err != nil {
		return err
	}
	proxyAddr := fmt.Sprintf("127.0.0.1:%d", port)
	proxy, err := startProxy(ctx, opt.binary, dirs, childEnv, configPath, proxyAddr)
	if err != nil {
		return err
	}
	defer func() { proxy.cleanup() }()
	if err := awaitProxy(ctx, proxyAddr, proxy); err != nil {
		return err
	}
	logf("%s: proxy ready; warmup %d then %d requests at concurrency %d", mode, opt.warmup, opt.requests, opt.concurrency)

	samples, err := startSampler(proxy.cmd.Process.Pid, dirs)
	if err != nil {
		return err
	}
	defer func() { samples.close() }()

	proxyURL, err := url.Parse("http://" + proxyAddr)
	if err != nil {
		return err
	}
	transport := &http.Transport{
		Proxy: http.ProxyURL(proxyURL), MaxIdleConns: opt.concurrency * 2, MaxIdleConnsPerHost: opt.concurrency * 2,
		MaxConnsPerHost: opt.concurrency * 2, IdleConnTimeout: time.Minute,
	}
	defer transport.CloseIdleConnections()
	params := loadParams{client: &http.Client{Transport: transport, Timeout: clientTimeout}, plan: plan, sinkAddr: sink.addr(), concurrency: opt.concurrency}

	// Warmup shares the proxy process and its connections with the measured
	// phase; only the measured phase feeds the performance numbers.
	warm := runPhase(ctx, params, phaseWarmup, opt.warmup)
	startSample, startErr := readProc(proxy.cmd.Process.Pid)

	evidenceAtStart := evidenceBytes(dirs.recorder)
	var cpuBeforeRestart uint64
	var restartPeak int64
	measured, err := measuredPhases(opt, func(offset, count int) phaseResult {
		return runPhaseRange(ctx, params, phaseMeasure, offset, count)
	}, func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		rep := &restartReport{AfterRequests: opt.restartAfter, ShutdownBudgetSeconds: opt.shutdownTimeout.Seconds()}
		res.Restart = rep
		pre, preErr := readProc(proxy.cmd.Process.Pid)
		_, restartPeak = samples.finish()
		restartPeak = max(restartPeak, pre.rss)
		if preErr != nil || pre.ticks < startSample.ticks {
			startErr = errors.New("pre-restart process measurement unavailable or invalid")
		} else {
			cpuBeforeRestart = pre.ticks - startSample.ticks
		}
		started := time.Now()
		rep.Shutdown = proxy.stop(opt.shutdownTimeout)
		rep.StopSeconds = time.Since(started).Seconds()
		if !rep.Shutdown.Clean || rep.StopSeconds > rep.ShutdownBudgetSeconds {
			return fmt.Errorf("restart stop failed within %s budget: %s (elapsed %.6fs)", opt.shutdownTimeout, rep.Shutdown.Error, rep.StopSeconds)
		}
		if mode != modeOff {
			opt.restartBefore, err = scanRecorder(dirs.recorder, plan, sink.addr())
			if err != nil {
				return fmt.Errorf("scan before restart: %w", err)
			}
			verifyCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), verificationTimeout(opt))
			rep.Verify = verifyRecorder(verifyCtx, opt.binary, dirs, childEnv, opt.restartBefore)
			cancel()
			if err := os.Rename(filepath.Join(dirs.root, "verify.txt"), filepath.Join(dirs.root, "verify-before-restart.txt")); err != nil {
				return fmt.Errorf("preserve pre-restart verification: %w", err)
			}
			if rep.Verify.Exit != 0 {
				return fmt.Errorf("verification before restart exited %d", rep.Verify.Exit)
			}
			opt.restartBefore = &recorderObservation{opens: opt.restartBefore.opens, closes: opt.restartBefore.closes}
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		transport.CloseIdleConnections()
		proxy.cleanup()
		// Both generations append to the same log and use the same pinned inputs.
		next, err := launchProxy(ctx, proxyLaunch{binary: opt.binary, dirs: dirs, env: childEnv, configPath: configPath, addr: proxyAddr, appendLog: true})
		if err != nil {
			return fmt.Errorf("restart proxy: %w", err)
		}
		proxy = next
		if err := awaitProxy(ctx, proxyAddr, proxy); err != nil {
			return fmt.Errorf("restart readiness: %w", err)
		}
		samples.close()
		nextSamples, err := sampleProxy(proxy.cmd.Process.Pid, dirs, true)
		if err != nil {
			return fmt.Errorf("restart sampler: %w", err)
		}
		samples = nextSamples
		post, postErr := readProc(proxy.cmd.Process.Pid)
		if postErr != nil {
			startErr = postErr
		}
		startSample.ticks = post.ticks
		rep.Ready = true
		return nil
	})
	if err != nil {
		return err
	}
	end := time.Now()
	endSample, endErr := readProc(proxy.cmd.Process.Pid)
	lastSample, peakRSS := samples.finish()
	if endErr != nil {
		endSample = lastSample
	}
	peakRSS = max(peakRSS, startSample.rss)
	peakRSS = max(peakRSS, restartPeak)
	if endSample.rss > peakRSS {
		peakRSS = endSample.rss
	}

	shutdown := proxy.stop(opt.shutdownTimeout)

	perf := summarizeMeasured(plan, measured, opt.window, measured.samples)
	if warm.interrupted {
		perf.invalidate("warmup was interrupted")
	}
	for _, out := range warm.outcomes {
		if !out.ran || out.transportErr || out.bodyReadErr || out.bodyMismatch {
			perf.invalidate("warmup did not complete with expected responses")
			break
		}
	}
	perf.RSSStartBytes, perf.RSSEndBytes, perf.RSSPeakBytes = startSample.rss, endSample.rss, peakRSS
	perf.EvidenceAtStart = evidenceAtStart
	if startErr != nil || endErr != nil {
		perf.invalidate("process measurement unavailable or invalid")
	}
	if ticks, tickErr := clockTicks(context.WithoutCancel(ctx)); tickErr == nil && ticks > 0 && !math.IsNaN(ticks) && !math.IsInf(ticks, 0) && startErr == nil && endErr == nil && endSample.ticks >= startSample.ticks && perf.Seconds > 0 {
		perf.CPUSeconds = float64(cpuBeforeRestart+endSample.ticks-startSample.ticks) / ticks
		perf.CPUCores = perf.CPUSeconds / perf.Seconds
	} else {
		perf.invalidate("CPU measurement unavailable or invalid")
	}

	integrity := finishIntegrity(context.WithoutCancel(ctx), opt, mode, dirs, childEnv, plan, sink, warm, measured, end, shutdown, &perf)

	if lines, logErr := bundleLogLines(filepath.Join(dirs.root, "proxy.log")); logErr != nil {
		integrity.fail("reading proxy.log failed: " + logErr.Error())
	} else {
		res.Inputs.Rules.ProxyLogLines = lines
		if res.Inputs.Rules.Mode == rulesEmpty && len(lines) > 0 {
			integrity.fail("proxy reported rule bundle activity under --rules empty: " + lines[0])
		}
	}
	if ctx.Err() != nil {
		integrity.fail("run interrupted")
		perf.invalidate("run interrupted")
	}
	perf.EvidenceBytes = evidenceBytes(dirs.recorder)
	res.Performance, res.Integrity = perf, integrity
	return nil
}

// versionText records the proxy's own version output, which pins what the
// build reports about itself next to the binary hash.
func versionText(ctx context.Context, binary string, dirs runDirs, env []string) string {
	out, err := localCommand(ctx, binary, dirs.cwd, env, "version").CombinedOutput()
	text := strings.TrimSpace(string(out))
	if len(text) > maxVersionText {
		text = text[:maxVersionText]
	}
	if err != nil {
		return "unavailable: " + err.Error()
	}
	return text
}

// prepareConfig generates the base config with the proxy's own init, forces
// the load-test settings onto it, validates it, and records the effective
// config and its hashes. Every one of these commands runs with the pinned
// environment so none can read a host profile.
func prepareConfig(ctx context.Context, opt options, mode string, dirs runDirs, env []string, res *result) (string, error) {
	configPath := filepath.Join(dirs.root, "pipelock.yaml")
	args := []string{"init", "--output", configPath, "--home", dirs.home, "--scan-home", dirs.scanHome, "--no-auditor", "--skip-canary", "--json"}
	initOut, err := localCommand(ctx, opt.binary, dirs.cwd, env, args...).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("pipelock init: %w: %s", err, initOut)
	}
	if err := os.WriteFile(filepath.Join(dirs.root, "init.json"), initOut, 0o600); err != nil {
		return "", err
	}
	base, err := os.ReadFile(filepath.Clean(configPath))
	if err != nil {
		return "", err
	}
	effective, err := applyConfig(base, configParams{mode: mode, chains: opt.chains, dirs: dirs})
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(configPath, effective, 0o600); err != nil {
		return "", err
	}
	if res.Inputs.Config, err = describeConfig(configPath, effective, dirs.root); err != nil {
		return "", err
	}
	checkOut, err := localCommand(ctx, opt.binary, dirs.cwd, env, "check", "--config", configPath).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("pipelock check: %w: %s", err, checkOut)
	}
	return configPath, os.WriteFile(filepath.Join(dirs.root, "check.txt"), checkOut, 0o600)
}

// proxyProc is the Pipelock child. Its exit is observed once, by a goroutine
// that owns Wait, so a crash during the run is visible and shutdown never
// blocks on a process that already ended.
type proxyProc struct {
	cmd     *exec.Cmd
	exited  chan struct{}
	exitErr error
	log     *os.File
	stopped bool
}

func startProxy(ctx context.Context, binary string, dirs runDirs, env []string, configPath, addr string) (*proxyProc, error) {
	return launchProxy(ctx, proxyLaunch{binary: binary, dirs: dirs, env: env, configPath: configPath, addr: addr})
}

type proxyLaunch struct {
	binary, configPath, addr string
	dirs                     runDirs
	env                      []string
	appendLog                bool
}

func launchProxy(ctx context.Context, opt proxyLaunch) (*proxyProc, error) {
	flags := os.O_CREATE | os.O_WRONLY | os.O_EXCL
	if opt.appendLog {
		flags = os.O_WRONLY | os.O_APPEND
	}
	logFile, err := os.OpenFile(filepath.Clean(filepath.Join(opt.dirs.root, "proxy.log")), flags, 0o600)
	if err != nil {
		return nil, err
	}
	cmd := localCommand(context.WithoutCancel(ctx), opt.binary, opt.dirs.cwd, opt.env, "run", "--config", opt.configPath, "--home", opt.dirs.home, "--listen", opt.addr)
	cmd.Stdout, cmd.Stderr = logFile, logFile
	if err := cmd.Start(); err != nil {
		_ = logFile.Close()
		return nil, err
	}
	p := &proxyProc{cmd: cmd, exited: make(chan struct{}), log: logFile}
	go func() {
		p.exitErr = cmd.Wait()
		close(p.exited)
	}()
	return p, nil
}

// stop asks the proxy to shut down and reports whether it did so cleanly. A
// proxy that ignores SIGTERM is killed after the timeout rather than waited on
// forever.
func (p *proxyProc) stop(timeout time.Duration) shutdownReport {
	if err := p.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		p.killAndWait(timeout)
		return shutdownReport{Error: fmt.Sprintf("proxy termination signal failed: %v (reaped: %t)", err, p.stopped)}
	}
	if p.waitForExit(timeout) {
		if p.exitErr != nil {
			return shutdownReport{Error: "proxy did not shut down cleanly: " + p.exitErr.Error()}
		}
		return shutdownReport{Clean: true}
	}
	p.killAndWait(timeout)
	return shutdownReport{Error: fmt.Sprintf("proxy ignored SIGTERM for %s and was killed (reaped: %t)", timeout, p.stopped)}
}

// waitForExit marks the process stopped only after observing its exit.
func (p *proxyProc) waitForExit(timeout time.Duration) bool {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-p.exited:
		p.stopped = true
		return true
	case <-timer.C:
		return false
	}
}

func (p *proxyProc) killAndWait(timeout time.Duration) {
	_ = p.cmd.Process.Kill()
	p.waitForExit(timeout)
}

// cleanup retries termination when shutdown could not observe an exit.
func (p *proxyProc) cleanup() {
	if !p.stopped {
		p.killAndWait(5 * time.Second)
	}
	_ = p.log.Close()
}

// sampler records the proxy's CPU ticks, RSS, and evidence size once a second.
type sampler struct {
	stop chan struct{}
	done chan struct{}
	file *os.File
	last procSample
	peak atomic.Int64
}

func startSampler(pid int, dirs runDirs) (*sampler, error) {
	return sampleProxy(pid, dirs, false)
}

func sampleProxy(pid int, dirs runDirs, appendLog bool) (*sampler, error) {
	flags := os.O_CREATE | os.O_WRONLY | os.O_EXCL
	if appendLog {
		flags = os.O_WRONLY | os.O_APPEND
	}
	file, err := os.OpenFile(filepath.Clean(filepath.Join(dirs.root, "samples.csv")), flags, 0o600)
	if err != nil {
		return nil, err
	}
	if !appendLog {
		_, _ = io.WriteString(file, "unix_ns,cpu_ticks,rss_bytes,evidence_bytes\n")
	}
	s := &sampler{stop: make(chan struct{}), done: make(chan struct{}), file: file}
	go func() {
		defer close(s.done)
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				sample, err := readProc(pid)
				if err != nil {
					continue
				}
				s.last = sample
				for old := s.peak.Load(); sample.rss > old && !s.peak.CompareAndSwap(old, sample.rss); old = s.peak.Load() {
				}
				_, _ = fmt.Fprintf(file, "%d,%d,%d,%d\n", sample.at.UnixNano(), sample.ticks, sample.rss, evidenceBytes(dirs.recorder))
			case <-s.stop:
				return
			}
		}
	}()
	return s, nil
}

// finish stops sampling and returns the last sample and peak RSS seen.
func (s *sampler) finish() (procSample, int64) {
	s.shutdown()
	return s.last, s.peak.Load()
}

func (s *sampler) shutdown() {
	select {
	case <-s.stop:
	default:
		close(s.stop)
	}
	<-s.done
}

func (s *sampler) close() {
	s.shutdown()
	_ = s.file.Close()
}

// finishIntegrity reads the recorder after the proxy has exited, so every
// receipt the proxy will ever write is on disk, then evaluates integrity and
// folds in the shutdown and offline verification results.
func finishIntegrity(ctx context.Context, opt options, mode string, dirs runDirs, env []string, plan workload, sink *sink, warm, measured phaseResult, end time.Time, shutdown shutdownReport, perf *performanceReport) integrityReport {
	var obs *recorderObservation
	var scanErr error
	if _, statErr := os.Stat(dirs.recorder); statErr == nil {
		obs, scanErr = scanRecorder(dirs.recorder, plan, sink.addr())
	} else if mode != modeOff {
		scanErr = fmt.Errorf("recorder directory missing: %w", statErr)
	}
	outcomes := append(append(make([]requestOutcome, 0, plan.total()), warm.outcomes...), measured.outcomes...)
	rep := evaluateIntegrity(integrityInput{
		mode: mode, plan: plan, obs: obs, outcomes: outcomes,
		sinkHits: sink.hits(), sinkUnknown: sink.unknown.Load(),
	})
	if len(sink.unknownSamples()) > 0 {
		rep.OrphanSamples = append(rep.OrphanSamples, sink.unknownSamples()...)
	}
	if scanErr != nil {
		rep.fail("reading the recorder failed: " + scanErr.Error())
	}
	if obs != nil {
		if obs.latestFileMod.After(end) {
			perf.RecorderFileLagMS = float64(obs.latestFileMod.Sub(end).Nanoseconds()) / 1e6
		}
		if obs.lastReceipt.After(end) {
			perf.FlushLagMS = float64(obs.lastReceipt.Sub(end).Nanoseconds()) / 1e6
		}
	}
	rep.Shutdown = shutdown
	if !shutdown.Clean {
		rep.fail("shutdown: " + shutdown.Error)
	}
	if mode != modeOff {
		verifyCtx, cancel := context.WithTimeout(ctx, verificationTimeout(opt))
		rep.Verify = verifyRecorder(verifyCtx, opt.binary, dirs, env, obs)
		cancel()
		if rep.Verify.Exit != 0 {
			rep.fail(fmt.Sprintf("verify-receipt exited %d", rep.Verify.Exit))
		}
	}
	if opt.restartAfter > 0 && mode != modeOff {
		if err := checkRestartContinuity(dirs, opt.restartBefore, obs, opt.chains); err != nil {
			rep.fail("restart continuity: " + err.Error())
		}
	}

	return rep
}

func verifyRecorder(ctx context.Context, binary string, dirs runDirs, env []string, obs *recorderObservation) verifyReport {
	pubKey := filepath.Join(dirs.keys, "flight-recorder-signing.key.pub")
	out, err := localCommand(ctx, binary, dirs.cwd, env, "verify-receipt", "--chain", dirs.recorder, "--whole-recorder", "--require-seal", "--key", pubKey).CombinedOutput()
	rep := verifyReport{Ran: true, Output: string(out)}
	if ctx.Err() != nil {
		rep.Output += "\nverification: " + ctx.Err().Error()
		err = ctx.Err()
	}
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			rep.Exit = exitErr.ExitCode()
		} else {
			rep.Exit = -1
		}
	}
	if rep.Exit == 0 {
		if err := verifyNativeAEL(dirs, obs); err != nil {
			rep.Exit = -1
			rep.Output += "\nnative AEL: " + err.Error()
		}
	}
	if werr := os.WriteFile(filepath.Join(dirs.root, "verify.txt"), []byte(rep.Output), 0o600); werr != nil && rep.Exit == 0 {
		rep.Exit = -1
		rep.Output += "\nwriting verify.txt: " + werr.Error()
	}
	return rep
}

// verifyNativeAEL joins the shipped native verifier to the signed v1 run claims.
// Directory names alone cannot establish ownership or the trusted signing key.
func verifyNativeAEL(dirs runDirs, obs *recorderObservation) error {
	if obs == nil || len(obs.nativeRuns) == 0 {
		return errors.New("no signed native AEL run claims")
	}
	key, err := signing.LoadPublicKey(filepath.Join(dirs.keys, "flight-recorder-signing.key.pub"))
	if err != nil {
		return err
	}
	trusted := hex.EncodeToString(key)
	entries, err := os.ReadDir(filepath.Join(dirs.recorder, "ael"))
	if err != nil {
		return err
	}
	if len(entries) != len(obs.nativeRuns) {
		return errors.New("native AEL inventory differs from signed run claims")
	}
	for _, entry := range entries {
		if _, ok := obs.nativeRuns[entry.Name()]; !ok {
			return errors.New("unclaimed native AEL run")
		}
	}
	for run, signer := range obs.nativeRuns {
		if signer != trusted {
			return errors.New("native AEL signer differs from pinned key")
		}
		if _, err := ael.VerifyRun(dirs.recorder, run, trusted); err != nil {
			return err
		}
	}
	return nil
}

// pinBinary copies and hashes the executable that every child command uses.
func pinBinary(source string, dirs runDirs) (string, string, error) {
	resolved, err := filepath.EvalSymlinks(source)
	if err != nil {
		return "", "", err
	}
	root, err := os.OpenRoot(filepath.Dir(resolved))
	if err != nil {
		return "", "", err
	}
	defer func() { _ = root.Close() }()
	binDir := filepath.Join(dirs.root, "bin")
	if err := os.Mkdir(binDir, 0o750); err != nil {
		return "", "", err
	}
	target := filepath.Join(binDir, filepath.Base(source))
	digest, err := copyHashed(root, filepath.Base(resolved), target)
	if err != nil {
		return "", "", err
	}
	if err := os.Chmod(target, 0o700); err != nil { // #nosec G302 -- private pinned executable needs owner execute permission

		return "", "", err
	}
	return target, digest.SHA256, nil
}
