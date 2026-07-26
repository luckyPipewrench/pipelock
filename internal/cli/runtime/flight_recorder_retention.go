// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

const defaultFlightRecorderRetentionInterval = 24 * time.Hour

// expireFunc performs one expiry pass. It is a parameter rather than a
// package-level variable so tests substitute it per call: a mutable package
// seam is shared state, and these tests run in parallel.
type expireFunc func(*recorder.Recorder) (int, error)

func defaultExpire(rec *recorder.Recorder) (int, error) {
	return rec.ExpireOldFiles()
}

func runFlightRecorderExpiryOnce(rec *recorder.Recorder, logW io.Writer, expire expireFunc) {
	if rec == nil {
		return
	}
	if expire == nil {
		expire = defaultExpire
	}
	removed, err := expire(rec)
	if err != nil {
		if logW != nil {
			_, _ = fmt.Fprintf(logW, "pipelock: recorder retention expiry failed: %v\n", err)
		}
		return
	}
	if removed > 0 && logW != nil {
		_, _ = fmt.Fprintf(logW, "pipelock: recorder retention expired %d old raw escrow sidecar(s)\n", removed)
	}
}

func startFlightRecorderRetention(
	ctx context.Context,
	wg *sync.WaitGroup,
	rec *recorder.Recorder,
	logW io.Writer,
	interval time.Duration,
	expire expireFunc,
) {
	if wg == nil || rec == nil {
		return
	}
	if interval <= 0 {
		interval = defaultFlightRecorderRetentionInterval
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				runFlightRecorderExpiryOnce(rec, logW, expire)
			case <-ctx.Done():
				return
			}
		}
	}()
}

func flightRecorderEvidenceWarning(dir string, retentionDays int) string {
	health, err := recorder.EvidenceDirectoryHealthForDir(dir, retentionDays)
	if err != nil {
		return fmt.Sprintf("evidence file-count health unavailable: %v", err)
	}
	if !health.NearSessionFileLimit {
		return ""
	}
	return health.FileCountVerdict()
}

func printFlightRecorderEvidenceWarning(logW io.Writer, dir string, retentionDays int) {
	if logW == nil || dir == "" {
		return
	}
	if warning := flightRecorderEvidenceWarning(dir, retentionDays); warning != "" {
		_, _ = fmt.Fprintf(logW, "  Recorder: WARNING - %s\n", warning)
	}
}
