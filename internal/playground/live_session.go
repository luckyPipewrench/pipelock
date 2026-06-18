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
	"strings"
	"sync"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/playground/llmagent"
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

// Chat roles in the live stream.
const (
	liveRoleUser  = "user"
	liveRoleAgent = "agent"
)

// ErrContainmentUnavailable is returned when a session requires containment but
// it cannot be established or verified. The session is refused (fail-closed):
// the live agent is never run uncontained while presenting as a live session.
var ErrContainmentUnavailable = fmt.Errorf("playground: containment required but not established")

// ErrSessionClosed is returned by Send after the session has been finalized.
// Once Finalize seals and verifies the run, no further receipt-producing action
// may be admitted, or it would fall outside the sealed evidence packet.
var ErrSessionClosed = fmt.Errorf("playground: live session is closed")

// ErrReceiptInvariant is returned (and fails the turn closed) when a model-backed
// agent narrates an HTTP action that received a proxy response but produced no
// matching signed receipt. That means the action egressed unmediated, the proxy
// wiring is wrong, or a proxy path went unobserved -- any of which breaks the
// "every mediated action is attested" guarantee the live demo makes.
var ErrReceiptInvariant = fmt.Errorf("playground: agent action produced no signed receipt")

// ErrAgentReplyDLP is returned when the agent's browser-bound reply is flagged
// by DLP. The raw reply is not streamed. In the model-backed path the subprocess
// is also closed, because it may already have recorded that raw reply in bounded
// history before the parent process could redact it for the visitor.
var ErrAgentReplyDLP = fmt.Errorf("playground: agent reply contained a secret")

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
	// Ignored when LLMAgent is set (the model-backed subprocess drives instead).
	Agent LiveAgent
	// LLMAgent, when non-nil, drives each turn with a real model-backed agent run
	// as a proxy-only subprocess (cmd/pipelock-playground-llm-agent) instead of the
	// in-process deterministic IntentAgent. The subprocess egresses ONLY through the
	// live run's proxy, so its model calls and tool calls are all mediated and
	// produce signed receipts; the session enforces that invariant per turn.
	LLMAgent *LLMAgentConfig
	// ToyAgentBin / WebToolBin are needed only for a contained run's
	// host-containment witness probe; unused in dev (uncontained) sessions.
	ToyAgentBin string
	WebToolBin  string
	// EventBuffer sizes the event channel. Defaults to 256.
	EventBuffer int
	// HTTPTimeout bounds each agent request through the proxy. Defaults to 10s.
	// Applies only to the in-process IntentAgent path; the subprocess agent uses
	// LLMAgentConfig.Timeout.
	HTTPTimeout time.Duration
}

// LLMAgentConfig configures the model-backed subprocess agent for a live session.
type LLMAgentConfig struct {
	// Bin is the path to the cmd/pipelock-playground-llm-agent binary.
	Bin string
	// ModelBaseURL is the chat-completions API base URL (e.g. https://provider.example/v1).
	ModelBaseURL string
	// Model is the model name passed to the API.
	Model string
	// SecretFile is the path to a file holding the model API key (never argv).
	SecretFile string
	// MaxSteps bounds the model<->tool loop per turn (0 = wrapper default).
	MaxSteps int
	// Timeout bounds each model/tool request (0 = wrapper default).
	Timeout time.Duration
	// ModelHostOverride maps the model host to these IPs in the lab proxy's DNS so
	// the agent's model calls resolve to a test server. Empty => real DNS (the
	// model host is reached for real, the only allowlisted real-egress destination).
	ModelHostOverride []string
}

// LiveSession drives a deterministic agent through a real contained Pipelock
// proxy from visitor chat input, streaming each signed decision as it happens.
type LiveSession struct {
	lr        *LiveRun
	agent     LiveAgent
	runner    modelTurnRunner // non-nil => model-backed subprocess drives turns
	client    *http.Client
	contained bool

	sendMu sync.Mutex // serializes Send so the event stream is ordered
	done   bool       // set by Finalize under sendMu; rejects later sends

	// recMu guards the per-turn receipt accounting used by the model-driver path's
	// receipt invariant. onReceipt records method+target keys while a turn is active.
	recMu        sync.Mutex
	turnActive   bool
	turnReceipts []string
	receiptSig   chan struct{} // per-turn: signaled when a receipt is recorded
	// receiptSettle bounds how long sendViaModel waits for in-flight receipts to
	// settle before declaring a receipt-invariant violation. 0 => defaultReceiptSettle.
	receiptSettle time.Duration

	mu     sync.Mutex
	closed bool
	events chan LiveEvent
}

// defaultReceiptSettle is the backstop wait for in-flight receipt emission. A
// turn's allow receipt is emitted on the proxy goroutine just AFTER the response
// is streamed to the subprocess, so the narration can momentarily outrace the
// bookkeeping. This is a fail-safe ceiling, not the gate: the wait early-exits the
// instant the tally covers the narrated actions, and a genuinely missing receipt
// still fails closed once it elapses.
const defaultReceiptSettle = 3 * time.Second

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

	runOpts := LiveRunOpts{
		Contained:           cfg.RequireContainment,
		ScenarioID:          LiveDemoScenarioID,
		RunNonce:            cfg.RunNonce,
		OrchestratorKeyPath: cfg.OrchestratorKeyPath,
		ToyAgentBin:         cfg.ToyAgentBin,
		WebToolBin:          cfg.WebToolBin,
		OnReceipt:           s.onReceipt,
	}
	if cfg.LLMAgent != nil {
		// The agent's model calls egress through the lab proxy, so the model host
		// must be reachable: allowlist it (the one real-egress destination). Tool
		// calls to the .test hosts stay loopback.
		runOpts.ModelBaseURL = cfg.LLMAgent.ModelBaseURL
		runOpts.ModelHostOverride = cfg.LLMAgent.ModelHostOverride
	}
	lr, err := StartLiveRun(ctx, runOpts)
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

	if cfg.LLMAgent != nil {
		runner, rErr := newSubprocessTurnRunner(ctx, subprocessRunnerOpts{
			Bin:          cfg.LLMAgent.Bin,
			ProxyURL:     "http://" + lr.proxyLn.Addr().String(),
			ModelBaseURL: cfg.LLMAgent.ModelBaseURL,
			Model:        cfg.LLMAgent.Model,
			SecretFile:   cfg.LLMAgent.SecretFile,
			SafeURL:      lr.liveSafeURL(),
			ExfilURL:     lr.liveExfilURL(),
			Canary:       lr.canaryValue,
			Actor:        liveRunActor,
			MaxSteps:     cfg.LLMAgent.MaxSteps,
			Timeout:      cfg.LLMAgent.Timeout,
		})
		if rErr != nil {
			lr.Close()
			return nil, fmt.Errorf("start model agent: %w", rErr)
		}
		s.runner = runner
	} else if cfg.Agent != nil {
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

	s.push(LiveEvent{Type: LiveEventChat, Role: liveRoleUser, Text: msg})

	if s.runner != nil {
		return s.sendViaModel(ctx, msg)
	}

	turn := s.agent.Plan(msg)
	reply, blocked := s.scanAgentReply(ctx, LiveEvent{Type: LiveEventChat, Role: liveRoleAgent, Text: turn.Reply})
	s.push(reply)
	if blocked {
		s.done = true
		s.push(LiveEvent{Type: LiveEventError, Message: agentReplyDLPMessage})
		return ErrAgentReplyDLP
	}

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

// redactedReplyNotice replaces a model reply the DLP flags. The model holds only
// the secret handle, so a non-clean reply means a regression or some other secret
// reached the model's output; fail closed and never stream the raw text.
const redactedReplyNotice = "[Pipelock redacted this reply: it contained a secret]"

const agentReplyDLPMessage = "agent reply contained a secret; session stopped"

// scanAgentReply runs the agent's outbound chat reply through DLP before it
// reaches the visitor. The browser chat is an untrusted egress surface: a reply
// that carries a secret is a leak regardless of the collector. This is defense in
// depth on top of the secret handle. A flagged reply is redacted and reported to
// the caller so the session can fail closed before any dirty model history is
// reused. Quiet scan: this is our own output, not adversarial input, so it skips
// warn-telemetry.
func (s *LiveSession) scanAgentReply(ctx context.Context, ev LiveEvent) (LiveEvent, bool) {
	if s.lr == nil || s.lr.sc == nil || strings.TrimSpace(ev.Text) == "" {
		return ev, false
	}
	if res := s.lr.sc.ScanTextForDLPQuiet(ctx, ev.Text); !res.Clean {
		ev.Text = redactedReplyNotice
		return ev, true
	}
	return ev, false
}

// sendViaModel drives one turn through the model-backed subprocess. It opens a
// receipt-accounting window, streams the agent's narration to the live stream
// (decision events arrive concurrently via onReceipt as the subprocess's proxy
// traffic is mediated), then enforces the receipt invariant: every narrated HTTP
// action that received a proxy response must be backed by a signed receipt with
// the same method+destination key for this turn. A violation fails the turn
// closed. Called with sendMu held.
func (s *LiveSession) sendViaModel(ctx context.Context, msg string) error {
	s.beginReceiptTurn()
	var proxied []string
	replyBlocked := false
	turnCtx, cancelTurn := context.WithCancel(ctx)
	defer cancelTurn()
	runErr := s.runner.RunTurn(turnCtx, msg, func(ev llmagent.Event) {
		out, push, target := mapModelEvent(ev)
		if target != "" {
			proxied = append(proxied, target)
		}
		if push {
			if out.Type == LiveEventChat && out.Role == liveRoleAgent {
				var blocked bool
				out, blocked = s.scanAgentReply(ctx, out)
				if blocked {
					replyBlocked = true
					cancelTurn()
				}
			}
			s.push(out)
		}
	})
	if replyBlocked {
		s.endReceiptTurn()
		s.done = true
		if s.runner != nil {
			_ = s.runner.Close()
		}
		s.push(LiveEvent{Type: LiveEventError, Message: agentReplyDLPMessage})
		return ErrAgentReplyDLP
	}
	if runErr != nil {
		s.endReceiptTurn()
		s.push(LiveEvent{Type: LiveEventError, Message: "agent turn failed"})
		return fmt.Errorf("model agent turn: %w", runErr)
	}

	// Wait (bounded) for in-flight receipts to settle: a turn's allow receipt is
	// emitted on the proxy goroutine just AFTER the response is streamed back, so
	// the narration can momentarily outrace the tally. The wait early-exits the
	// instant the tally covers the narrated actions; it does not weaken the
	// invariant (a genuinely missing receipt still fails once the deadline elapses).
	s.waitReceiptsSettle(ctx, proxied)
	receipts := s.endReceiptTurn()

	// Receipt invariant: each action the agent narrated as proxy-responded must
	// carry at LEAST as many signed receipts this turn as narrated actions with the
	// same method+destination key. A shortfall means an action egressed unmediated or a proxy
	// path went unobserved -- fail closed. Counting (not set-membership) catches a
	// dropped receipt even when an earlier matching action was mediated.
	receiptCount := tallyValues(receipts)
	proxiedCount := tallyValues(proxied)
	for action, want := range proxiedCount {
		if receiptCount[action] < want {
			s.push(LiveEvent{Type: LiveEventError, Message: "unverified agent action blocked"})
			return fmt.Errorf("%w: %s", ErrReceiptInvariant, action)
		}
	}
	return nil
}

// tallyValues counts occurrences of each comparison key in xs.
func tallyValues(xs []string) map[string]int {
	out := make(map[string]int, len(xs))
	for _, x := range xs {
		out[x]++
	}
	return out
}

// receiptsCover reports whether the recorded receipts cover every narrated
// proxied action (at least as many receipts per method+destination key as
// actions).
func receiptsCover(proxied, receipts []string) bool {
	have := tallyValues(receipts)
	for action, want := range tallyValues(proxied) {
		if have[action] < want {
			return false
		}
	}
	return true
}

// waitReceiptsSettle blocks until the per-turn receipt tally covers the narrated
// proxied actions, the settle deadline elapses, or ctx ends. It is signaled by
// onReceipt as each receipt lands, so it returns promptly in the common case.
func (s *LiveSession) waitReceiptsSettle(ctx context.Context, proxied []string) {
	if len(proxied) == 0 {
		return
	}
	settle := s.receiptSettle
	if settle <= 0 {
		settle = defaultReceiptSettle
	}
	timer := time.NewTimer(settle)
	defer timer.Stop()
	for {
		receipts, sig := s.receiptSnapshot()
		if receiptsCover(proxied, receipts) {
			return
		}
		select {
		case <-sig:
		case <-timer.C:
			return
		case <-ctx.Done():
			return
		}
	}
}

// receiptSnapshot returns a copy of the turn's recorded targets plus the current
// signal channel, both read under recMu.
func (s *LiveSession) receiptSnapshot() ([]string, chan struct{}) {
	s.recMu.Lock()
	defer s.recMu.Unlock()
	out := make([]string, len(s.turnReceipts))
	copy(out, s.turnReceipts)
	return out, s.receiptSig
}

// beginReceiptTurn opens the per-turn receipt-accounting window. onReceipt records
// each receipt's method+target key until endReceiptTurn closes it.
func (s *LiveSession) beginReceiptTurn() {
	s.recMu.Lock()
	s.turnActive = true
	s.turnReceipts = nil
	s.receiptSig = make(chan struct{}, 1)
	s.recMu.Unlock()
}

// endReceiptTurn closes the window and returns the targets recorded during the
// turn. Callers should waitReceiptsSettle first: an allow receipt can be emitted
// just after the proxy streams the response to the subprocess, so the tally may
// still be filling in for an instant after RunTurn returns.
func (s *LiveSession) endReceiptTurn() []string {
	s.recMu.Lock()
	defer s.recMu.Unlock()
	s.turnActive = false
	out := s.turnReceipts
	s.turnReceipts = nil
	s.receiptSig = nil
	return out
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

	if s.runner != nil {
		_ = s.runner.Close()
	}
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
	// Record the method+target key for the model-driver receipt invariant, if a
	// turn is open, and signal any settle-wait that the tally advanced.
	s.recMu.Lock()
	if s.turnActive {
		s.turnReceipts = append(s.turnReceipts, actionReceiptKey(rcpt.ActionRecord.Method, rcpt.ActionRecord.Target))
		if s.receiptSig != nil {
			select {
			case s.receiptSig <- struct{}{}:
			default:
			}
		}
	}
	s.recMu.Unlock()

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
