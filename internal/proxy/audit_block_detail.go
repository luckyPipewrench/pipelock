// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// auditDetailFromResult bridges scanner.Result classification onto the
// string-typed audit.BlockDetail without forcing the audit package to depend
// on scanner. The bridge lives in proxy because proxy already imports both
// packages, and every audit.LogBlockedDetail call site for a scanner.Result
// goes through here so the mapping has a single source of truth.
//
// Empty Class strings on a ClassThreat result are intentional: the audit
// package treats an empty Class identically to BlockClassThreat (preserves
// the pre-existing LogBlocked behavior).
func auditDetailFromResult(r scanner.Result) audit.BlockDetail {
	d := audit.BlockDetail{DNSErrorKind: string(r.DNSErrorKind)}
	switch r.Class {
	case scanner.ClassProtective:
		d.Class = audit.BlockClassProtective
	case scanner.ClassConfigMismatch:
		d.Class = audit.BlockClassConfigMismatch
	case scanner.ClassInfrastructureError:
		d.Class = audit.BlockClassInfrastructureError
	case scanner.ClassStructuralExemption:
		d.Class = audit.BlockClassStructuralExemption
	}
	return d
}
