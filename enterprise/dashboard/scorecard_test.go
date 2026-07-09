//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

// Scorecard tests moved to internal/evidenceview/scorecard_ported_test.go as
// part of the evidence-view extraction. The enterprise package consumes
// evidenceview via type aliases in aliases.go; the regression tests exercise
// the shared logic in its new home.
package dashboard
