package mcp

import (
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/hitl"
	"github.com/luckyPipewrench/pipelock/internal/killswitch"
	"github.com/luckyPipewrench/pipelock/internal/mcp/tools"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
	"github.com/luckyPipewrench/pipelock/internal/session"
)

// testOpts returns an MCPProxyOpts with only the scanner set.
// Most test callers need only the scanner; callers that need additional
// fields can copy the result and set them directly.
func testOpts(sc *scanner.Scanner) MCPProxyOpts {
	return MCPProxyOpts{Scanner: sc}
}

// testOptsFunc is a functional option for building MCPProxyOpts in tests.
type testOptsFunc func(*MCPProxyOpts)

// buildTestOpts constructs an MCPProxyOpts from a scanner and variadic options.
// This keeps test call sites short while allowing selective field overrides:
//
//	opts := buildTestOpts(sc, withRec(rec), withAdaptive(cfg))
func buildTestOpts(sc *scanner.Scanner, fns ...testOptsFunc) MCPProxyOpts {
	o := MCPProxyOpts{Scanner: sc}
	for _, fn := range fns {
		fn(&o)
	}
	return o
}

func withApprover(a *hitl.Approver) testOptsFunc {
	return func(o *MCPProxyOpts) { o.Approver = a }
}

func withToolCfg(tc *tools.ToolScanConfig) testOptsFunc {
	return func(o *MCPProxyOpts) { o.ToolCfg = tc }
}

func withKillSwitch(ks *killswitch.Controller) testOptsFunc {
	return func(o *MCPProxyOpts) { o.KillSwitch = ks }
}

func withRec(rec session.Recorder) testOptsFunc {
	return func(o *MCPProxyOpts) { o.Rec = rec }
}

func withAdaptive(cfg *config.AdaptiveEnforcement) testOptsFunc {
	return func(o *MCPProxyOpts) { o.AdaptiveCfg = cfg }
}
