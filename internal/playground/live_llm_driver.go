// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package playground

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/playground/llmagent"
)

// modelTurnRunner runs one visitor message as a single agent turn and streams the
// agent's narration back via onEvent, in order, until the turn completes. It is
// the seam between the live session and the model-backed agent subprocess: the
// real implementation (subprocessTurnRunner) drives the proxy-only
// cmd/pipelock-playground-llm-agent wrapper; tests inject a fake.
//
// The runner performs the agent's network I/O itself (model + tool calls,
// mediated by the Pipelock proxy). The session never executes those actions; it
// only maps the narration onto its event stream and enforces the receipt
// invariant after the turn.
type modelTurnRunner interface {
	// RunTurn writes msg to the agent and invokes onEvent for each narration event
	// the agent emits, returning when the turn is complete (the wrapper's turn_done
	// marker) or on error. It must not invoke onEvent after returning.
	RunTurn(ctx context.Context, msg string, onEvent func(llmagent.Event)) error
	// Close shuts down the underlying agent (closes stdin, reaps the subprocess).
	Close() error
}

// maxModelEventLine bounds one narration line read from the agent subprocess. A
// reply can carry model text, so this is larger than the wrapper's input cap.
const maxModelEventLine = 1 << 20 // 1 MiB

// mapModelEvent maps one agent narration event to a live-stream event. It returns
// the mapped event and push=true when the event should be streamed, plus a
// proxiedAction key when the event represents a tool action that received a
// proxy response (Status>0) and therefore MUST be backed by a signed receipt
// (the session counts these per method+destination against the turn's receipts).
//
// Decision events (allow/block) arrive separately via onReceipt, so a successful
// tool result is not re-pushed here (the decision renders the outcome); only its
// target is recorded for the receipt invariant. A tool result with no proxy
// response (Status 0: bad args, unbuildable request, transport error, or a
// refused direct dial) gets no decision event, so its outcome is surfaced here.
func mapModelEvent(ev llmagent.Event) (out LiveEvent, push bool, proxiedAction string) {
	switch ev.Kind {
	case llmagent.EventReply:
		if strings.TrimSpace(ev.Text) == "" {
			return LiveEvent{}, false, ""
		}
		return LiveEvent{Type: LiveEventChat, Role: liveRoleAgent, Text: ev.Text}, true, ""
	case llmagent.EventToolCall:
		return LiveEvent{
			Type:  LiveEventAgent,
			Kind:  agentKindBenign,
			Act:   ev.Tool,
			Title: "calling " + ev.Tool,
		}, true, ""
	case llmagent.EventToolResult:
		if ev.Status > 0 {
			// The proxy returned a response: the decision event (from onReceipt)
			// renders allow/block. Record the action for the receipt invariant and
			// do not double-push.
			return LiveEvent{}, false, actionReceiptKey(ev.Method, ev.URL)
		}
		// No proxy response: no decision event will arrive, so surface the outcome.
		note := ev.Note
		if note == "" {
			note = "no response"
		}
		return LiveEvent{
			Type:  LiveEventAgent,
			Act:   ev.Tool,
			Title: ev.Tool,
			Note:  note,
			Line:  strings.TrimSpace(ev.Method + " " + ev.URL),
		}, true, ""
	case llmagent.EventError:
		return LiveEvent{Type: LiveEventError, Message: ev.Text}, true, ""
	default:
		return LiveEvent{}, false, ""
	}
}

// actionReceiptKey is the comparison key for model-narrated HTTP actions and
// signed receipt records. It deliberately uses method + host:port rather than
// only host:port, so a model-call POST receipt cannot cover a narrated GET, and a
// safe read cannot cover a narrated write to the same destination.
func actionReceiptKey(method, target string) string {
	target = targetHostPort(target)
	method = strings.ToUpper(strings.TrimSpace(method))
	if method == "" {
		return target
	}
	return method + " " + target
}

// targetHostPort extracts the host:port from a tool action URL or a receipt
// target. Tool URLs and forward-proxy receipt targets are absolute URLs, so the
// host:port matches across both sides of the receipt invariant. A non-URL target
// (e.g. a CONNECT synthetic "host:port") is returned unchanged.
func targetHostPort(raw string) string {
	if raw == "" {
		return ""
	}
	if u, err := url.Parse(raw); err == nil && u.Host != "" {
		return u.Host
	}
	return raw
}

// subprocessRunnerOpts configures a subprocessTurnRunner. ProxyURL is mandatory:
// the agent egresses ONLY through it, and the wrapper itself refuses to run
// without it (fail-closed). The model API key is passed by file path
// (SecretFile), never on argv.
type subprocessRunnerOpts struct {
	Bin          string
	ProxyURL     string
	ModelBaseURL string
	Model        string
	SecretFile   string
	SafeURL      string
	ExfilURL     string
	Canary       string
	Actor        string
	MaxSteps     int
	Timeout      time.Duration
}

// subprocessTurnRunner drives the cmd/pipelock-playground-llm-agent wrapper as a
// long-lived subprocess: one turn per visitor message over a persistent
// stdin/stdout pipe. The subprocess runs with a minimal, controlled environment
// (NEVER the operator's env, which may hold real secrets) and is forced through
// the Pipelock proxy by --proxy-url plus a proxy-only transport guard inside the
// wrapper. Host kernel containment, where the host provides it, is attested
// separately (HostContainmentWitness); this runner provides the transport-only
// guarantee.
type subprocessTurnRunner struct {
	cmd    *exec.Cmd
	cancel context.CancelFunc
	stdin  io.WriteCloser
	stdout io.ReadCloser
	enc    *json.Encoder
	sc     *bufio.Scanner

	mu     sync.Mutex
	closed bool
}

// newSubprocessTurnRunner spawns the agent wrapper subprocess and prepares its
// stdin/stdout pipes. The caller owns Close. ctx bounds the subprocess lifetime:
// when it is cancelled (the session context expires) the process is killed.
func newSubprocessTurnRunner(ctx context.Context, opts subprocessRunnerOpts) (*subprocessTurnRunner, error) {
	if opts.Bin == "" {
		return nil, fmt.Errorf("playground: model agent binary path is required")
	}
	if opts.ProxyURL == "" {
		// The wrapper would itself refuse, but fail closed here too so a misconfigured
		// session never spawns an unmediated agent.
		return nil, fmt.Errorf("playground: model agent requires a proxy URL (refusing to run uncontained)")
	}

	args := []string{
		"--proxy-url", opts.ProxyURL,
		"--model-base-url", opts.ModelBaseURL,
		"--model", opts.Model,
		"--secret-file", opts.SecretFile,
		"--agent", actorOrDefault(opts.Actor),
	}
	if opts.SafeURL != "" {
		args = append(args, "--safe-url", opts.SafeURL)
	}
	if opts.ExfilURL != "" {
		args = append(args, "--exfil-url", opts.ExfilURL)
	}
	if opts.MaxSteps > 0 {
		args = append(args, "--max-steps", fmt.Sprintf("%d", opts.MaxSteps))
	}
	if opts.Timeout > 0 {
		args = append(args, "--timeout", opts.Timeout.String())
	}

	procCtx, cancel := context.WithCancel(ctx)
	cmd := exec.CommandContext(procCtx, opts.Bin, args...)
	// Minimal, controlled environment. The agent holds ONLY the synthetic canary
	// plus the demo plumbing -- never the operator's real environment. --proxy-url
	// is authoritative; HTTP_PROXY/HTTPS_PROXY are belt-and-suspenders and NO_PROXY
	// is cleared so nothing is exempted from the proxy.
	cmd.Env = []string{
		"PATH=/usr/local/bin:/usr/bin:/bin",
		"NO_PROXY=",
		"HTTP_PROXY=" + opts.ProxyURL,
		"HTTPS_PROXY=" + opts.ProxyURL,
		envPlaygroundCanary + "=" + opts.Canary,
		"PLAYGROUND_AGENT_ID=" + actorOrDefault(opts.Actor),
	}
	cmd.Stderr = os.Stderr

	stdin, err := cmd.StdinPipe()
	if err != nil {
		cancel()
		return nil, fmt.Errorf("playground: model agent stdin: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		_ = stdin.Close()
		return nil, fmt.Errorf("playground: model agent stdout: %w", err)
	}
	if err := cmd.Start(); err != nil {
		cancel()
		_ = stdin.Close()
		_ = stdout.Close()
		return nil, fmt.Errorf("playground: model agent start: %w", err)
	}

	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 0, 4096), maxModelEventLine)
	return &subprocessTurnRunner{
		cmd:    cmd,
		cancel: cancel,
		stdin:  stdin,
		stdout: stdout,
		enc:    json.NewEncoder(stdin),
		sc:     sc,
	}, nil
}

// envPlaygroundCanary is the env var the wrapper reads for the synthetic canary.
// It mirrors cmd/pipelock-playground-llm-agent's envCanary. Split to avoid a
// shared exported constant for an internal protocol detail.
const envPlaygroundCanary = "PIPELOCK_PLAYGROUND_CANARY"

func actorOrDefault(actor string) string {
	if actor == "" {
		return liveRunActor
	}
	return actor
}

// RunTurn writes one message to the subprocess and streams its narration events
// to onEvent until the wrapper emits turn_done. A turn_done marker ends the turn
// (and is not forwarded). EOF or a malformed line before turn_done fails the turn
// closed: the session treats that as an unobservable turn.
func (r *subprocessTurnRunner) RunTurn(ctx context.Context, msg string, onEvent func(llmagent.Event)) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return fmt.Errorf("playground: model agent runner is closed")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			if r.cancel != nil {
				r.cancel()
			}
		case <-done:
		}
	}()
	defer close(done)

	req := struct {
		Message string `json:"message"`
	}{Message: msg}
	if err := r.enc.Encode(req); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		return fmt.Errorf("playground: write message to model agent: %w", err)
	}

	for r.sc.Scan() {
		if err := ctx.Err(); err != nil {
			return err
		}
		var ev llmagent.Event
		if err := json.Unmarshal(r.sc.Bytes(), &ev); err != nil {
			return fmt.Errorf("playground: parse model agent event: %w", err)
		}
		if ev.Kind == llmagent.EventTurnDone {
			return nil
		}
		onEvent(ev)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := r.sc.Err(); err != nil {
		return fmt.Errorf("playground: read model agent: %w", err)
	}
	// Stdout closed before a turn_done marker: the turn never completed.
	return fmt.Errorf("playground: model agent ended before turn completed")
}

// Close shuts the subprocess down: closing stdin ends its read loop, then it is
// reaped. Safe to call multiple times.
func (r *subprocessTurnRunner) Close() error {
	if r.cancel != nil {
		r.cancel()
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil
	}
	r.closed = true
	_ = r.stdin.Close()
	_ = r.stdout.Close()
	if r.cmd != nil && r.cmd.Process != nil {
		// Best-effort wait; the context cancel kills it if it does not exit.
		_ = r.cmd.Wait()
	}
	return nil
}
