//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package dashboard

import (
	"github.com/luckyPipewrench/pipelock/internal/evidenceview"
)

// Type aliases so that handler.go, readmodel.go, templates, and tests
// that reference dashboard.TrustedKey etc. keep compiling after the
// pure evidence-rendering logic moved to internal/evidenceview.

type TrustedKey = evidenceview.TrustedKey

type Line = evidenceview.Line

type Scorecard = evidenceview.Scorecard

type SessionSummary = evidenceview.SessionSummary

type SessionEvidence = evidenceview.SessionEvidence

type TimelineItem = evidenceview.TimelineItem

type SummaryPip = evidenceview.SummaryPip

// Const re-exports: scorecard state constants.
const (
	StateVerify  = evidenceview.StateVerify
	StateWarn    = evidenceview.StateWarn
	StateFail    = evidenceview.StateFail
	StateLimited = evidenceview.StateLimited
)

// Const re-exports: read/timeline limits.
const (
	dashboardReceiptReadLimit = evidenceview.DashboardReceiptReadLimit
	dashboardTimelineLimit    = evidenceview.DashboardTimelineLimit
)

// Const re-export: redacted destination placeholder.
const redactedDestination = evidenceview.RedactedDestination

// Package-level func vars so existing lowercase call sites resolve
// unchanged. The signatures match because dashboard.TrustedKey is an
// alias of evidenceview.TrustedKey, so the map types are identical.
var (
	cloneTrustedKeys = evidenceview.CloneTrustedKeys
	sessionSummary   = evidenceview.SessionSummaryOf
	sessionEvidence  = evidenceview.SessionEvidenceOf
	redactRaw        = evidenceview.RedactRaw
)
