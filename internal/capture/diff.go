// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package capture

// reportVersion is the current DiffReport schema version.
const reportVersion = 1

// Change type constants used in DiffEntry.ChangeType.
const (
	changeTypeNewBlock     = "new_block"
	changeTypeNewAllow     = "new_allow"
	changeTypeUnchanged    = "unchanged"
	changeTypeEvidenceOnly = "evidence_only"
	changeTypeSummaryOnly  = "summary_only"
)

// ReplayedRecord pairs a capture summary with the result of replaying it
// against a candidate configuration.
type ReplayedRecord struct {
	Summary CaptureSummary
	Result  ReplayResult
}

// DiffReport is the output of ComputeDiff. It summarises how a candidate
// configuration differs from the original across all replayed records.
type DiffReport struct {
	ReportVersion       int         `json:"report_version"`
	OriginalConfigHash  string      `json:"original_config_hash"`
	CandidateConfigHash string      `json:"candidate_config_hash"`
	TotalRecords        int         `json:"total_records"`
	Replayed            int         `json:"replayed"`
	NewBlocks           int         `json:"new_blocks"`
	NewAllows           int         `json:"new_allows"`
	Unchanged           int         `json:"unchanged"`
	EvidenceOnly        int         `json:"evidence_only"`
	SummaryOnly         int         `json:"summary_only"`
	Dropped             int         `json:"dropped"`
	Skipped             int         `json:"skipped"`
	Changes             []DiffEntry `json:"changes"`
	AllRecords          []DiffEntry `json:"all_records,omitempty"`
}

// DiffEntry describes a single record in a DiffReport.
type DiffEntry struct {
	Summary           CaptureSummary `json:"summary"`
	OriginalAction    string         `json:"original_action"`
	CandidateAction   string         `json:"candidate_action,omitempty"`
	Changed           bool           `json:"changed"`
	EvidenceOnly      bool           `json:"evidence_only"`
	SummaryOnly       bool           `json:"summary_only"`
	ChangeType        string         `json:"change_type"`
	CandidateFindings []Finding      `json:"candidate_findings,omitempty"`
}

// ComputeDiff classifies each replayed record and returns a DiffReport.
// dropped is the number of records that could not be replayed (e.g. buffer
// overflows during capture). skipped is the number of entries that failed to
// unmarshal during loading. originalHash and candidateHash are the
// hex-encoded SHA-256 digests of the respective configs.
func ComputeDiff(records []ReplayedRecord, dropped, skipped int, originalHash, candidateHash string) *DiffReport {
	report := &DiffReport{
		ReportVersion:       reportVersion,
		OriginalConfigHash:  originalHash,
		CandidateConfigHash: candidateHash,
		TotalRecords:        len(records),
		Dropped:             dropped,
		Skipped:             skipped,
	}

	for _, r := range records {
		entry := DiffEntry{
			Summary:           r.Summary,
			OriginalAction:    r.Result.OriginalAction,
			CandidateAction:   r.Result.CandidateAction,
			Changed:           r.Result.Changed,
			EvidenceOnly:      r.Result.EvidenceOnly,
			SummaryOnly:       r.Result.SummaryOnly,
			CandidateFindings: r.Result.CandidateFindings,
		}

		switch {
		case r.Result.EvidenceOnly:
			entry.ChangeType = changeTypeEvidenceOnly
			report.EvidenceOnly++

		case r.Result.SummaryOnly:
			entry.ChangeType = changeTypeSummaryOnly
			report.SummaryOnly++

		case r.Result.Changed && isBlockAction(r.Result.CandidateAction) && !isBlockAction(r.Result.OriginalAction):
			// Candidate would block something the original allowed.
			entry.ChangeType = changeTypeNewBlock
			report.NewBlocks++
			report.Replayed++
			report.Changes = append(report.Changes, entry)

		case r.Result.Changed:
			// Any other change (original blocked, candidate allows; or action type change).
			entry.ChangeType = changeTypeNewAllow
			report.NewAllows++
			report.Replayed++
			report.Changes = append(report.Changes, entry)

		default:
			entry.ChangeType = changeTypeUnchanged
			report.Unchanged++
			report.Replayed++
		}

		report.AllRecords = append(report.AllRecords, entry)
	}

	return report
}

// isBlockAction returns true when action represents a blocking outcome.
// Both "block" and "fail_closed" are treated as blocking actions because
// fail_closed is the fail-safe outcome for parse errors and timeouts.
func isBlockAction(action string) bool {
	return action == "block" || action == "fail_closed"
}
