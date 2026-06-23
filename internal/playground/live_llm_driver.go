// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package playground

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
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

// keyFD is the child file descriptor the model key pipe is inherited on. The
// first ExtraFiles entry lands at fd 3 (after stdin/stdout/stderr = 0/1/2).
const keyFD = 3

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
			return LiveEvent{}, false, modelEventReceiptKey(ev)
		}
		// No proxy response: no decision event will arrive, so surface the outcome.
		// For shell/filesystem tools the actionable detail is the command or path
		// (ev.Detail); for would-be HTTP actions it is the method+URL. Show whichever
		// is present so the agent column reports WHAT it did, not just the tool name.
		note := ev.Note
		if note == "" {
			note = "no response"
		}
		line := strings.TrimSpace(ev.Method + " " + ev.URL)
		if ev.Detail != "" {
			line = ev.Detail
		}
		return LiveEvent{
			Type:  LiveEventAgent,
			Act:   ev.Tool,
			Title: ev.Tool,
			Note:  note,
			Line:  line,
		}, true, ""
	case llmagent.EventThinking:
		// Model round trip in flight: surface the exact "thinking" state so the
		// viewer does not have to infer it from event silence.
		return LiveEvent{Type: LiveEventAgentState, State: agentStateThinking}, true, ""
	case llmagent.EventTurnEnd:
		// Precise terminal state for the turn, with a human-readable reason so the
		// agent column shows "hit action limit" vs "done" instead of inferring it.
		return LiveEvent{Type: LiveEventAgentState, State: agentStateEnded, Note: turnEndNote(ev.Reason)}, true, ""
	case llmagent.EventError:
		if ev.Code == llmagent.ErrorCodeModelProviderPaused {
			return LiveEvent{Type: LiveEventError, Message: ModelProviderPausedMessage}, true, ""
		}
		return LiveEvent{Type: LiveEventError, Message: ev.Text}, true, ""
	default:
		return LiveEvent{}, false, ""
	}
}

// turnEndNote maps an agent turn-end reason to short viewer text. Unknown reasons
// fall through to a neutral "turn ended" so a new reason never renders blank.
func turnEndNote(reason string) string {
	switch reason {
	case "tool_call_limit", "step_limit":
		return "hit action limit"
	case "complete":
		return "done"
	default:
		return "turn ended"
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

// modelEventReceiptKey maps a model-narrated HTTP tool result to the proxy
// decision the live demo can actually receipt. Plain HTTP is forwarded as the
// original method; HTTPS is mediated as an opaque CONNECT tunnel, so the receipt
// invariant must compare against CONNECT host:port rather than an unobservable
// inner GET/POST.
func modelEventReceiptKey(ev llmagent.Event) string {
	if target, ok := httpsConnectTarget(ev.URL); ok {
		return actionReceiptKey(http.MethodConnect, target)
	}
	return actionReceiptKey(ev.Method, ev.URL)
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

func httpsConnectTarget(raw string) (string, bool) {
	u, err := url.Parse(raw)
	if err != nil || !strings.EqualFold(u.Scheme, "https") || u.Host == "" {
		return "", false
	}
	if u.Port() != "" {
		return u.Host, true
	}
	return net.JoinHostPort(u.Hostname(), "443"), true
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
	// SecretFile is the path to the model API key file. Used only when ModelKey is
	// empty (the legacy path: the subprocess reads the file itself).
	SecretFile string
	// ModelKey, when non-empty, is the model API key value. The runner passes it to
	// the subprocess over an inherited pipe FD (--secret-fd) instead of a file path,
	// so the key never sits on a filesystem the agent's read_file tool can open. The
	// key file can then be made root-only at deploy time. Preferred over SecretFile.
	ModelKey string
	SafeURL  string
	// ScratchDir is the agent's working directory + HOME (seeded with a
	// ~/.aws/credentials file holding the dead secret). The caller owns its
	// lifecycle (creation and teardown).
	ScratchDir string
	// AllowExec enables the run_command shell tool in the wrapper. The caller sets
	// it true ONLY when the host kernel-contains the agent's egress.
	AllowExec bool
	// AWSAccessKeyID / AWSSecretAccessKey are the dead, AWS-shaped secret planted
	// in env and in the seeded credentials file for the agent to discover.
	AWSAccessKeyID     string
	AWSSecretAccessKey string
	// Contained launches the agent subprocess as AgentUser (the kernel-owner-match
	// user) and chowns the scratch tree to it, so the agent's direct egress --
	// including run_command children -- is dropped by the host owner-match rules.
	// It requires root; when set without root the runner fails closed rather than
	// launching an uncontained agent. AllowExec must only be true when Contained is.
	Contained bool
	AgentUser string
	Actor     string
	MaxSteps  int
	Timeout   time.Duration
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

	// Seed the dead secret where a real agent would find it: a normal AWS
	// credentials file under the scratch HOME. The agent has NO knowledge it is
	// special; it discovers it by reading its own environment/filesystem.
	if opts.ScratchDir != "" {
		if err := seedAWSCredentials(opts.ScratchDir, opts.AWSAccessKeyID, opts.AWSSecretAccessKey); err != nil {
			return nil, fmt.Errorf("playground: seed agent credentials: %w", err)
		}
	}

	// Prefer passing the model key over an inherited pipe FD: the key never lands
	// on a file the agent's read_file tool can open. Fall back to --secret-file
	// only when the parent could not read the key value.
	useKeyFD := opts.ModelKey != ""
	args := []string{
		"--proxy-url", opts.ProxyURL,
		"--model-base-url", opts.ModelBaseURL,
		"--model", opts.Model,
		"--agent", actorOrDefault(opts.Actor),
	}
	if useKeyFD {
		// ExtraFiles[0] is inherited as fd 3 in the child (after stdin/out/err).
		args = append(args, "--secret-fd", strconv.Itoa(keyFD))
	} else {
		args = append(args, "--secret-file", opts.SecretFile)
	}
	if opts.SafeURL != "" {
		args = append(args, "--safe-url", opts.SafeURL)
	}
	if opts.ScratchDir != "" {
		args = append(args, "--scratch-dir", opts.ScratchDir)
	}
	if opts.AllowExec {
		args = append(args, "--allow-exec")
	}
	if opts.MaxSteps > 0 {
		args = append(args, "--max-steps", fmt.Sprintf("%d", opts.MaxSteps))
	}
	if opts.Timeout > 0 {
		args = append(args, "--timeout", opts.Timeout.String())
	}

	procCtx, cancel := context.WithCancel(ctx)
	cmd := exec.CommandContext(procCtx, opts.Bin, args...)
	// Minimal, controlled environment. The agent holds ONLY the dead synthetic
	// secret plus the demo plumbing -- never the operator's real environment.
	// --proxy-url is authoritative; HTTP_PROXY/HTTPS_PROXY are belt-and-suspenders
	// and NO_PROXY is cleared so nothing is exempted from the proxy. HOME points at
	// the scratch dir so ~/.aws resolves to the seeded credentials. The agent is
	// told nothing about the secret; PIPELOCK_PLAYGROUND_SECRET_ENV only tells the
	// wrapper which env vars hold the dead value for egress TAGGING (UI provenance).
	cmd.Env = []string{
		"PATH=/usr/local/bin:/usr/bin:/bin",
		"NO_PROXY=",
		"HTTP_PROXY=" + opts.ProxyURL,
		"HTTPS_PROXY=" + opts.ProxyURL,
		"PLAYGROUND_AGENT_ID=" + actorOrDefault(opts.Actor),
		"AWS_ACCESS_KEY_ID=" + opts.AWSAccessKeyID,
		"AWS_SECRET_ACCESS_KEY=" + opts.AWSSecretAccessKey,
		"PIPELOCK_PLAYGROUND_SECRET_ENV=AWS_ACCESS_KEY_ID,AWS_SECRET_ACCESS_KEY",
	}
	if opts.ScratchDir != "" {
		cmd.Env = append(cmd.Env, "HOME="+opts.ScratchDir)
	}
	cmd.Stderr = os.Stderr

	// Contained launch: run the subprocess as the owner-match agent user and hand
	// it the scratch tree, BEFORE Start (SysProcAttr must be set first). Fail
	// closed: if containment cannot be established (not root, unknown user), do
	// NOT fall back to an uncontained launch in a session that claims containment.
	if opts.Contained {
		if err := applyAgentContainment(cmd, opts.ScratchDir, opts.AgentUser); err != nil {
			cancel()
			return nil, fmt.Errorf("playground: contain model agent: %w", err)
		}
	}

	// Attach the model-key pipe read end as the child's fd 3 BEFORE Start. The key
	// value is written to the write end AFTER Start (below). keyW is closed by the
	// deferred guard on any error path, and set to nil after a clean write so the
	// guard is a no-op on success.
	var keyW *os.File
	defer func() {
		if keyW != nil {
			_ = keyW.Close()
		}
	}()
	if useKeyFD {
		keyR, kw, perr := os.Pipe()
		if perr != nil {
			cancel()
			return nil, fmt.Errorf("playground: model key pipe: %w", perr)
		}
		cmd.ExtraFiles = []*os.File{keyR} // inherited as fd 3 in the child
		keyW = kw
		defer func() { _ = keyR.Close() }() // parent's read-end copy; child has its own
	}

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

	if useKeyFD {
		// Hand the key to the child over the pipe, then close so it reads EOF.
		if _, werr := io.WriteString(keyW, opts.ModelKey); werr != nil {
			cancel()
			_ = stdin.Close()
			_ = stdout.Close()
			return nil, fmt.Errorf("playground: write model key to agent: %w", werr)
		}
		_ = keyW.Close()
		keyW = nil
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

// seedAWSCredentials writes a normal-looking AWS credentials file under
// scratchDir/.aws so the agent (whose HOME is scratchDir) discovers the dead
// secret the way a real agent would. Perms are locked down (0o750 dir, 0o600
// file). The value is dead by construction; the realism is the point.
func seedAWSCredentials(scratchDir, accessKeyID, secretAccessKey string) error {
	awsDir := filepath.Join(filepath.Clean(scratchDir), ".aws")
	if err := os.MkdirAll(awsDir, 0o750); err != nil {
		return fmt.Errorf("create .aws dir: %w", err)
	}
	creds := fmt.Sprintf("[default]\naws_access_key_id = %s\naws_secret_access_key = %s\n", accessKeyID, secretAccessKey)
	if err := os.WriteFile(filepath.Join(awsDir, "credentials"), []byte(creds), 0o600); err != nil {
		return fmt.Errorf("write credentials file: %w", err)
	}
	return nil
}

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

	var turnErr error
	for r.sc.Scan() {
		if err := ctx.Err(); err != nil {
			return err
		}
		var ev llmagent.Event
		if err := json.Unmarshal(r.sc.Bytes(), &ev); err != nil {
			return fmt.Errorf("playground: parse model agent event: %w", err)
		}
		if ev.Kind == llmagent.EventTurnDone {
			return turnErr
		}
		if ev.Kind == llmagent.EventError && ev.Code == llmagent.ErrorCodeModelProviderPaused {
			turnErr = ErrModelProviderPaused
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
