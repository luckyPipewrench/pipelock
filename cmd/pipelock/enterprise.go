//go:build enterprise

package main

import (
	"github.com/luckyPipewrench/pipelock/enterprise"
	_ "github.com/luckyPipewrench/pipelock/enterprise/cli"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/edition"
)

func init() {
	edition.NewEditionFunc = enterprise.NewEdition
	config.ValidateAgentsFunc = enterprise.ValidateAgents
	config.EnforceLicenseGateFunc = enterprise.EnforceLicenseGate
	config.MergeAgentProfileFunc = enterprise.MergeAgentProfile
}
