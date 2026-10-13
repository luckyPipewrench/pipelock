// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	"github.com/luckyPipewrench/pipelock/internal/verification"
)

// startupProgress has no timer: only observed evidence work can send an
// extension. systemd.service(5) requires the first message before the startup
// budget expires and subsequent messages within the extension interval. Once
// that interval passes without an event, this ceremony loses eligibility.
type startupProgress struct {
	mu      sync.Mutex
	last    time.Time
	expired bool
	stderr  io.Writer
}

func (p *startupProgress) reportAt(event verification.Progress, now time.Time) error {
	if event.Bytes <= 0 && event.Records == 0 {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.expired {
		return nil
	}
	if now.Sub(p.last) >= cliutil.ServiceStartTimeout {
		p.expired = true
		return nil
	}
	p.last = now
	if _, err := sdNotify(fmt.Sprintf("EXTEND_TIMEOUT_USEC=%d", cliutil.ServiceStartTimeout/time.Microsecond)); err != nil {
		_, _ = fmt.Fprintf(p.stderr, "pipelock: systemd notification failed: %v\n", err)
		return err
	}
	return nil
}

func startupVerificationOptions(opts ServerOpts) verification.Options {
	p := &startupProgress{last: time.Now(), stderr: opts.Stderr}
	options := opts.StartupVerification
	prior := options.Progress
	options.Progress = func(event verification.Progress) error {
		if prior != nil {
			if err := prior(event); err != nil {
				return err
			}
		}
		return p.reportAt(event, time.Now())
	}
	return options
}
