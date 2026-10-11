// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package signing

import (
	"errors"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	"github.com/luckyPipewrench/pipelock/internal/evidence/endproof"
)

type chainCLIReport struct {
	endproof.Report
	Path               string `json:"path"`
	Valid              bool   `json:"valid"`
	RootHash           string `json:"root_hash"`
	FinalSeq           uint64 `json:"final_seq"`
	ReceiptCount       uint64 `json:"receipt_count"`
	SignaturesVerified bool   `json:"signatures_verified"`
	Unpinned           bool   `json:"unpinned"`
}

func newChainCLIReport(r chainCLIReport, keys []string, scope string, proof []string) chainCLIReport {
	r.Report = endproof.New(r.Valid, scope, proof...)
	r.SignaturesVerified = r.Valid && len(keys) > 0
	r.Unpinned = len(keys) == 0
	if r.Valid && r.EndProof.Proven && r.Unpinned {
		r.Status = "CHAIN UNPINNED"
	}
	return r
}

func collectChainReport(opts verifyReceiptOptions, report chainCLIReport) {
	if opts.Reports != nil {
		*opts.Reports = append(*opts.Reports, report)
	}
}

func isPrefixError(err error) bool {
	var code *cliutil.ExitError
	return errors.As(err, &code) && code.Code == endproof.ExitPrefix
}

func preferChainError(first, second error) error {
	if first != nil && !isPrefixError(first) {
		return first
	}
	if second != nil {
		return second
	}
	return first
}

func aggregateChainReports(reports []chainCLIReport, err error, directory, whole bool) any {
	valid := err == nil || isPrefixError(err)
	proven := len(reports) > 0
	for _, r := range reports {
		valid = valid && r.Valid
		proven = proven && r.EndProof.Proven
	}
	var evidence []string
	for _, r := range reports {
		evidence = append(evidence, r.EndProof.Evidence...)
	}
	if !proven {
		evidence = nil
	}
	scope := "receipt_chain"
	if directory {
		scope = "chain_set"
	}
	if whole {
		scope = "whole_recorder"
	}
	if len(reports) == 1 {
		scope = reports[0].Scope
	}
	report := endproof.New(valid, scope, evidence...)
	if err != nil && cliutil.ExitCodeOf(err) == cliutil.ExitConfig {
		report.Status = "USAGE ERROR"
	} else if valid && proven {
		for _, r := range reports {
			if r.Unpinned {
				report.Status = "CHAIN UNPINNED"
				break
			}
		}
	}
	return struct {
		endproof.Report
		Valid  bool             `json:"valid"`
		Chains []chainCLIReport `json:"chains"`
		Error  string           `json:"error,omitempty"`
	}{report, valid, reports, chainErrorText(err)}
}

func chainErrorText(err error) string {
	if err != nil {
		return err.Error()
	}
	return ""
}
