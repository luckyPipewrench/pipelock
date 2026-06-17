// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package playground

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/proxy"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
)

// Live event types streamed to the viewer.
const (
	LiveEventStatus   = "status"
	LiveEventChat     = "chat"
	LiveEventAgent    = "agent"
	LiveEventDecision = "decision"
	LiveEventVerified = "verified"
	LiveEventError    = "error"
	LiveEventDone     = "done"
)

// Live session states surfaced in the status event.
const (
	LiveStateContained = "contained"
	LiveStateDev       = "dev"
)

// ErrContainmentUnavailable is returned when a session requires containment but
// it cannot be established or verified. The session is refused (fail-closed):
// the live agent is never run uncontained while presenting as a live session.
var ErrContainmentUnavailable = fmt.Errorf("playground: containment required but not established")

// ErrSessionClosed is returned by Send after the session has been finalized.
// Once Finalize seals and verifies the run, no further receipt-producing action
// may be admitted, or it would fall outside the sealed evidence packet.
var ErrSessionClosed = fmt.Errorf("playground: live session is closed")

// ContainmentVerifier proves the live agent's environment is kernel-contained
// before a public session starts. Verify returns nil only when containment is
// established AND enforced. The server wires this to the real host-containment
// check; tests inject a stub.
type ContainmentVerifier interface {
	Verify(ctx context.Context) error
}

// LiveEvent is one item in the live decision stream. It is JSON-serialized as an
// SSE data payload. Fields are sparse: only those relevant to Type are set.
type LiveEvent struct {
	Type string `json:"type"`

	// status
	State string `json:"state,omitempty"`
	RunID string `json:"run_id,omitempty"`

	// chat
	Role string `json:"role,omitempty"`
	Text string `json:"text,omitempty"`

	// agent
	Kind  string `json:"kind,omitempty"`
	Act   string `json:"act,omitempty"`
	Title string `json:"title,omitempty"`
	Note  string `json:"note,omitempty"`
	Line  string `json:"line,omitempty"`

	// decision
	Verdict  string   `json:"verdict,omitempty"`
	Color    string   `json:"color,omitempty"`
	Layer    string   `json:"layer,omitempty"`
	Pattern  string   `json:"pattern,omitempty"`
	Target   string   `json:"target,omitempty"`
	Signer   string   `json:"signer,omitempty"`
	Key      string   `json:"key,omitempty"`
	Seq      uint64   `json:"seq,omitempty"`
	Envelope []string `json:"envelope,omitempty"`

	// verified
	Checks []string `json:"checks,omitempty"`

	// error
	Message string `json:"message,omitempty"`
}

// LiveSessionConfig configures a live chat session.
type LiveSessionConfig struct {
	// RunNonce uniquely identifies the run.
	RunNonce string
	// RequireContainment, when true, refuses to start unless Containment.Verify
	// succeeds. Public exposure MUST set this true.
	RequireContainment bool
	// Containment proves kernel containment. Required (non-nil) when
	// RequireContainment is true; ignored otherwise.
	Containment ContainmentVerifier
	// OrchestratorKeyPath loads the published demo signing key (so the run is
	// verifiable against the published key). Empty => ephemeral per-run key.
	OrchestratorKeyPath string
	// Agent overrides the LiveAgent. Nil => the deterministic IntentAgent.
	Agent LiveAgent
	// ToyAgentBin / WebToolBin are needed only for a contained run's
	// host-containment witness probe; unused in dev (uncontained) sessions.
	ToyAgentBin string
	WebToolBin  string
	// EventBuffer sizes the event channel. Defaults to 256.
	EventBuffer int
	// HTTPTimeout bounds each agent request through the proxy. Defaults to 10s.
	HTTPTimeout time.Duration
}

// LiveSession drives a deterministic agent through a real contained Pipelock
// proxy from visitor chat input, streaming each signed decision as it happens.
type LiveSession struct {
	lr        *LiveRun
	agent     LiveAgent
	client    *http.Client
	contained bool

	sendMu sync.Mutex // serializes Send so the event stream is ordered
	done   bool       // set by Finalize under sendMu; rejects later sends

	mu     sync.Mutex
	closed bool
	events chan LiveEvent
}

// StartLiveSession boots a live chat session. It fails closed on containment:
// if RequireContainment is set and containment cannot be proven, it refuses
// before starting any agent or proxy that would present as live.
func StartLiveSession(ctx context.Context, cfg LiveSessionConfig) (*LiveSession, error) {
	if cfg.RequireContainment {
		if cfg.Containment == nil {
			return nil, ErrContainmentUnavailable
		}
		if err := cfg.Containment.Verify(ctx); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrContainmentUnavailable, err)
		}
	}

	buf := cfg.EventBuffer
	if buf <= 0 {
		buf = 256
	}
	s := &LiveSession{
		contained: cfg.RequireContainment,
		events:    make(chan LiveEvent, buf),
	}

	lr, err := StartLiveRun(ctx, LiveRunOpts{
		Contained:           cfg.RequireContainment,
		ScenarioID:          LiveDemoScenarioID,
		RunNonce:            cfg.RunNonce,
		OrchestratorKeyPath: cfg.OrchestratorKeyPath,
		ToyAgentBin:         cfg.ToyAgentBin,
		WebToolBin:          cfg.WebToolBin,
		OnReceipt:           s.onReceipt,
	})
	if err != nil {
		return nil, fmt.Errorf("start live run: %w", err)
	}
	s.lr = lr

	proxyURL, err := url.Parse("http://" + lr.proxyLn.Addr().String())
	if err != nil {
		lr.Close()
		return nil, fmt.Errorf("parse proxy url: %w", err)
	}
	timeout := cfg.HTTPTimeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	s.client = &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
		Timeout:   timeout,
	}

	if cfg.Agent != nil {
		s.agent = cfg.Agent
	} else {
		s.agent = NewIntentAgent(lr.liveSafeURL(), lr.liveExfilURL(), lr.canaryValue)
	}

	state := LiveStateDev
	if s.contained {
		state = LiveStateContained
	}
	s.push(LiveEvent{Type: LiveEventStatus, State: state, RunID: cfg.RunNonce})

	return s, nil
}

// Events returns the read side of the live event stream. The channel is closed
// by Close.
func (s *LiveSession) Events() <-chan LiveEvent {
	return s.events
}

// Send processes one visitor message: it echoes the message, plans the agent's
// reply, then executes each planned action through the proxy. Signed decisions
// arrive asynchronously on the event stream via onReceipt. Send is serialized so
// the stream stays ordered. The message must already be size-validated by the
// caller (the server enforces the input cap).
func (s *LiveSession) Send(ctx context.Context, msg string) error {
	s.sendMu.Lock()
	defer s.sendMu.Unlock()

	// Once finalized, the run is sealed; admitting another action would produce
	// receipts outside the verified packet. Refuse fail-closed.
	if s.done {
		return ErrSessionClosed
	}

	s.push(LiveEvent{Type: LiveEventChat, Role: "user", Text: msg})

	turn := s.agent.Plan(msg)
	s.push(LiveEvent{Type: LiveEventChat, Role: "agent", Text: turn.Reply})

	for _, act := range turn.Actions {
		s.push(LiveEvent{
			Type:  LiveEventAgent,
			Kind:  act.Kind,
			Act:   act.Act,
			Title: act.Title,
			Note:  act.Note,
			Line:  act.Method + " " + act.URL,
		})
		// Executing the request triggers the proxy decision -> emitter ->
		// onReceipt -> a decision event, in this same goroutine, so it lands on
		// the stream right after the agent action above.
		s.execute(ctx, act)
	}
	return nil
}

// execute issues one planned action through the proxy. A blocked request returns
// a 4xx (not a transport error); both allow and block paths produce a signed
// receipt, which is what the stream surfaces. Transport errors (e.g. context
// cancellation) are swallowed: the decision, if any, already streamed.
func (s *LiveSession) execute(ctx context.Context, act AgentAction) {
	var body io.Reader
	if len(act.Body) > 0 {
		body = bytes.NewReader(act.Body)
	}
	req, err := http.NewRequestWithContext(ctx, act.Method, act.URL, body)
	if err != nil {
		return
	}
	// Declare the lab agent identity so the proxy records the receipt actor as
	// the synthetic lab agent (not "anonymous"), matching the toy agent's
	// webtool and the lab's public-safe field allowlist.
	req.Header.Set(proxy.AgentHeader, liveRunActor)
	if len(act.Body) > 0 {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
}

// Finalize seals and offline-verifies the run, streaming a verified event with
// the check names, then returns the report. Call after the visitor's session is
// done (or on timeout) and before Close.
func (s *LiveSession) Finalize(runDir string) (VerifyReport, error) {
	s.sendMu.Lock()
	defer s.sendMu.Unlock()

	// Mark terminal before sealing: any send that was waiting on this lock will
	// observe done and refuse, so no action lands outside the sealed packet.
	s.done = true

	rep, err := s.lr.AssembleAndVerify(runDir)
	if err != nil {
		s.push(LiveEvent{Type: LiveEventError, Message: "verification failed"})
		return VerifyReport{}, err
	}
	names := make([]string, 0, len(rep.Checks))
	for _, c := range rep.Checks {
		names = append(names, c.Name)
	}
	s.push(LiveEvent{Type: LiveEventVerified, Checks: names})
	return rep, nil
}

// Close shuts down the run and closes the event stream. Safe to call multiple
// times. After Close, onReceipt becomes a no-op so no producer touches the
// closed channel.
func (s *LiveSession) Close() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	close(s.events)
	s.mu.Unlock()

	if s.lr != nil {
		s.lr.Close()
	}
}

// onReceipt maps a signed receipt to a decision event. Wired into the emitter,
// it fires under the chain mutex; it must not block (push is non-blocking).
func (s *LiveSession) onReceipt(rcpt *receipt.Receipt) {
	if rcpt == nil {
		return
	}
	verdict := receipt.NormalizeVerdict(rcpt.ActionRecord.Verdict)
	color := bundleColorAllow
	label := "ALLOW"
	if verdict == "block" {
		color = bundleColorBlock
		label = "BLOCKED"
	}
	signer := rcpt.SignerKey
	short := signer
	if len(short) > 16 {
		short = short[:16] + "…"
	}
	s.push(LiveEvent{
		Type:     LiveEventDecision,
		Verdict:  label,
		Color:    color,
		Layer:    rcpt.ActionRecord.Layer,
		Pattern:  rcpt.ActionRecord.Pattern,
		Target:   rcpt.ActionRecord.Target,
		Signer:   "pipelock",
		Key:      short,
		Seq:      rcpt.ActionRecord.ChainSeq,
		Envelope: receiptEnvelopeLines(*rcpt),
	})
}

// push sends an event without blocking. If the buffer is full or the session is
// closed, the event is dropped — the durable evidence bundle remains the source
// of truth, so a dropped UI frame is never a correctness loss. Dropping (rather
// than blocking) honors the emitter's non-blocking observer contract.
func (s *LiveSession) push(ev LiveEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	select {
	case s.events <- ev:
	default:
	}
}

// liveSafeURL / liveExfilURL reconstruct the lab target URLs with their
// ephemeral ports, mirroring RunSteps. Defined on LiveRun so live_session.go can
// build the agent without duplicating port logic.
func (lr *LiveRun) liveSafeURL() string {
	return fmt.Sprintf("http://%s:%s/", liveRunSafeHost, portFromAddr(lr.safeLn.Addr()))
}

func (lr *LiveRun) liveExfilURL() string {
	return fmt.Sprintf("http://%s:%s/", liveRunExfilHost, portFromAddr(lr.collectorLn.Addr()))
}
