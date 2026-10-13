// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"fmt"
	"io"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	"github.com/luckyPipewrench/pipelock/internal/verification"
)

// sd_watchdog_enabled(3) recommends notifying every half of the advertised
// timeout. Apply that cadence to sd_notify(3)'s EXTEND_TIMEOUT_USEC interval,
// leaving the other half for scheduling and delivery before systemd expires it.
const startupProgressInterval = cliutil.ServiceStartTimeout / 2

// Progress events only update observed work. A single sender owns notification
// writes, outside the progress mutex. Neither its timer nor a send grants trust
// to evidence or creates progress; a full-budget gap permanently expires it.
type startupProgress struct {
	mu                      sync.Mutex
	last                    time.Time
	sentAt                  time.Time
	observed, sent, expired bool
	stderr                  io.Writer
	wake                    chan struct{}
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
	p.last, p.observed = now, true
	if p.wake != nil && (!p.sent || now.Sub(p.sentAt) >= startupProgressInterval) {
		select {
		case p.wake <- struct{}{}:
		default:
		}
	}
	return nil
}

func (p *startupProgress) sendAt(now time.Time) {
	p.mu.Lock()
	if now.Sub(p.last) >= cliutil.ServiceStartTimeout {
		p.expired = true
	}
	if p.expired || !p.observed || now.Sub(p.last) >= startupProgressInterval || p.sent && now.Sub(p.sentAt) < startupProgressInterval {
		p.mu.Unlock()
		return
	}
	p.sent, p.sentAt, p.observed = true, now, false
	p.mu.Unlock()
	if _, err := sdNotify(fmt.Sprintf("EXTEND_TIMEOUT_USEC=%d", cliutil.ServiceStartTimeout/time.Microsecond)); err != nil {
		p.mu.Lock()
		p.expired = true
		p.mu.Unlock()
		_, _ = fmt.Fprintf(p.stderr, "pipelock: systemd notification failed; startup extensions disabled: %v\n", err)
	}
}

func startupVerificationOptions(opts ServerOpts) (verification.Options, func()) {
	options := opts.StartupVerification
	if runtime.GOOS != "linux" || os.Getenv("NOTIFY_SOCKET") == "" {
		return options, func() {}
	}
	p := &startupProgress{last: time.Now(), stderr: opts.Stderr, wake: make(chan struct{}, 1)}
	prior := options.Progress
	options.Progress = func(event verification.Progress) error {
		if prior != nil {
			if err := prior(event); err != nil {
				return err
			}
		}
		return p.reportAt(event, time.Now())
	}
	stop, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		p.run(stop)
	}()
	return options, func() { close(stop); <-done }
}

// run owns the timer and socket writes until its caller stops and joins it.
func (p *startupProgress) run(stop <-chan struct{}) {
	select {
	case <-p.wake:
		p.sendAt(time.Now())
	case <-stop:
		p.sendAt(time.Now())
		return
	}
	ticker := time.NewTicker(startupProgressInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			p.sendAt(time.Now())
		case <-p.wake:
			p.sendAt(time.Now())
		case <-stop:
			return
		}
	}
}
