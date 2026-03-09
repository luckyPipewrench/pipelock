//go:build enterprise

// Package testinit activates enterprise edition hooks for package-level tests.
// Import with blank identifier in build-tagged test files:
//
//	//go:build enterprise
//	package foo
//	import _ "github.com/luckyPipewrench/pipelock/enterprise/testinit"
package testinit

import (
	"github.com/luckyPipewrench/pipelock/enterprise"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/edition"
)

func init() {
	edition.NewEditionFunc = enterprise.NewEdition
	config.ValidateAgentsFunc = enterprise.ValidateAgents
	config.EnforceLicenseGateFunc = enterprise.EnforceLicenseGate
	config.MergeAgentProfileFunc = enterprise.MergeAgentProfile
}
