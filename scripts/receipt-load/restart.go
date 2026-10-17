// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/receipt"
)

type restartReport struct {
	AfterRequests         int            `json:"after_requests"`
	ShutdownBudgetSeconds float64        `json:"shutdown_budget_seconds"`
	StopSeconds           float64        `json:"stop_seconds"`
	Shutdown              shutdownReport `json:"shutdown"`
	Ready                 bool           `json:"ready"`
	Verify                verifyReport   `json:"verify_before_restart"`
}

func verificationTimeout(opt options) time.Duration {
	if opt.verifyTimeout > 0 {
		return opt.verifyTimeout
	}
	return time.Minute
}

// measuredPhases drains the first phase before stopping the proxy. Downtime is
// excluded from throughput; request indices and completion windows span both
// load phases. No second warmup is issued against the successor.
func measuredPhases(opt options, run func(offset, count int) phaseResult, restart func() error) (phaseResult, error) {
	if opt.restartAfter == 0 {
		return run(0, opt.requests), nil
	}
	first := run(0, opt.restartAfter)
	if first.interrupted {
		return first, errors.New("measured phase interrupted before restart")
	}
	if err := restart(); err != nil {
		return first, err
	}
	second := run(opt.restartAfter, opt.requests-opt.restartAfter)
	for i := range second.outcomes {
		second.outcomes[i].doneAtNS += first.elapsed.Nanoseconds()
	}
	for index, body := range second.samples {
		first.samples[opt.restartAfter+index] = body
	}
	first.outcomes = append(first.outcomes, second.outcomes...)
	first.elapsed += second.elapsed
	first.interrupted = second.interrupted
	return first, nil
}

// checkRestartContinuity adds the expected topology to the existing offline
// verification. Independently valid but unlinked runs are not restart proof.
// SessionOpen, ChainLink and ReceiptGroupBinding are the product contracts.
func checkRestartContinuity(dirs runDirs, before, after *recorderObservation, chains int) error {
	if before == nil || after == nil || len(before.opens) != chains || len(after.opens) != 2*chains {
		return errors.New("expected exactly two generations of receipt sessions")
	}
	var previousGroup string
	for session, open := range before.opens {
		if after.opens[session] == nil || !before.closes[session] || !after.closes[session] {
			return errors.New("predecessor session is missing or lacks a published close")
		}
		if chains > 1 {
			if open.GroupBinding == nil || (previousGroup != "" && previousGroup != open.GroupBinding.GroupID) {
				return errors.New("predecessor sessions do not form one receipt group")
			}
			previousGroup = open.GroupBinding.GroupID
		}
	}
	var nextGroup string
	for session, open := range after.opens {
		if !after.closes[session] {
			return errors.New("successor session lacks a published close")
		}
		if before.opens[session] != nil {
			continue
		}
		if chains > 1 {
			binding := open.GroupBinding
			if binding == nil || binding.PreviousGroupID != previousGroup || binding.GroupID == previousGroup || (nextGroup != "" && nextGroup != binding.GroupID) {
				return errors.New("successor receipt group does not link to the pre-restart group")
			}
			nextGroup = binding.GroupID
			continue
		}
		base, ok := receipt.RunSessionBase(session)
		if !ok {
			return errors.New("successor is not a recorder run session")
		}
		// The external verifier already authenticates both complete chains.
		// LinksOnly reuses the product's tail and signature checks without
		// rewalking the entire receipt history a second time.
		report, err := receipt.VerifyBase(dirs.recorder, base, receipt.BaseVerifyOptions{LinksOnly: true})
		if err != nil {
			return fmt.Errorf("verify restart link: %w", err)
		}
		if !report.Healthy() {
			return fmt.Errorf("restart link verification failed: %v", report.Findings)
		}
		linked := false
		for _, chain := range report.Chains {
			if chain.Session == session && chain.Link != nil && before.opens[chain.Link.PredecessorSession] != nil {
				linked = true
			}
		}
		if !linked {
			return errors.New("successor receipt chain does not link to the pre-restart session")
		}
	}
	return nil
}
