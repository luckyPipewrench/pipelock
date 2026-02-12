// Package hitl provides human-in-the-loop terminal approval for pipelock.
// When the response scanning action is "ask", detected threats are presented
// to the terminal operator who decides whether to allow, block, or strip.
package hitl

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

// Decision represents the operator's choice for a threat.
type Decision int

// Decision constants for operator responses.
const (
	DecisionBlock Decision = iota // default (fail-closed)
	DecisionAllow
	DecisionStrip
)

// Request contains threat context for the operator prompt.
type Request struct {
	Agent    string
	URL      string
	Preview  string
	Reason   string
	Patterns []string
}

// internal request wraps a Request with a response channel.
type request struct {
	req      *Request
	response chan Decision
}

// Approver handles human-in-the-loop terminal prompts.
// If stdin is not a terminal, all requests auto-block (fail-closed).
type Approver struct {
	timeout            time.Duration
	input              io.Reader
	output             io.Writer
	queue              chan request
	ctx                context.Context
	cancel             context.CancelFunc
	wg                 sync.WaitGroup
	isTerminal         bool
	lastPromptTimedOut bool // true if previous prompt hit timeout (stale input possible)
}

// Option configures an Approver.
type Option func(*Approver)

// WithInput sets the input reader (default: os.Stdin).
func WithInput(r io.Reader) Option {
	return func(a *Approver) { a.input = r }
}

// WithOutput sets the output writer (default: os.Stderr).
func WithOutput(w io.Writer) Option {
	return func(a *Approver) { a.output = w }
}

// WithTerminal overrides terminal detection (for testing).
func WithTerminal(isTerminal bool) Option {
	return func(a *Approver) { a.isTerminal = isTerminal }
}

// New creates an Approver that prompts on the terminal with the given timeout.
// If stdin is not a terminal (pipe, /dev/null), all requests auto-block.
// Call Close() to shut down the background worker.
func New(timeoutSeconds int, opts ...Option) *Approver {
	timeout := 30 * time.Second
	if timeoutSeconds > 0 {
		timeout = time.Duration(timeoutSeconds) * time.Second
	}

	ctx, cancel := context.WithCancel(context.Background())

	a := &Approver{
		timeout:    timeout,
		input:      os.Stdin,
		output:     os.Stderr,
		queue:      make(chan request, 64),
		ctx:        ctx,
		cancel:     cancel,
		isTerminal: isStdinTerminal(),
	}

	for _, opt := range opts {
		opt(a)
	}

	a.wg.Add(1)
	go a.worker()

	return a
}

// Ask submits a threat for operator approval. Blocks until the operator
// responds or the timeout expires. Returns DecisionBlock if stdin is not
// a terminal, on timeout, or on any error (fail-closed).
func (a *Approver) Ask(req *Request) Decision {
	if !a.isTerminal {
		return DecisionBlock
	}

	r := request{
		req:      req,
		response: make(chan Decision, 1),
	}

	select {
	case a.queue <- r:
	case <-a.ctx.Done():
		return DecisionBlock
	}

	select {
	case d := <-r.response:
		return d
	case <-a.ctx.Done():
		return DecisionBlock
	}
}

// IsTerminal reports whether the approver detected a terminal on stdin.
func (a *Approver) IsTerminal() bool {
	return a.isTerminal
}

// Close shuts down the worker goroutine and waits for it to exit.
func (a *Approver) Close() {
	a.cancel()
	a.wg.Wait()
}

// worker processes approval requests sequentially.
// A single reader goroutine owns the bufio.Reader to prevent concurrent access.
func (a *Approver) worker() {
	defer a.wg.Done()

	lines := make(chan string, 1)
	go a.readLines(lines)

	for {
		select {
		case r := <-a.queue:
			d := a.prompt(lines, r.req)
			select {
			case r.response <- d:
			case <-a.ctx.Done():
				return
			}
		case <-a.ctx.Done():
			return
		}
	}
}

// readLines reads from input sequentially. Only this goroutine touches
// the bufio.Reader, eliminating data races when prompts time out.
func (a *Approver) readLines(lines chan<- string) {
	reader := bufio.NewReader(a.input)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			select {
			case lines <- "":
			case <-a.ctx.Done():
			}
			return
		}
		select {
		case lines <- strings.TrimSpace(strings.ToLower(line)):
		case <-a.ctx.Done():
			return
		}
	}
}

// drainStaleLines discards any buffered lines from the channel that were
// left over from previous prompts (e.g., timeout or extra input).
func (a *Approver) drainStaleLines(lines <-chan string) {
	for {
		select {
		case <-lines:
		default:
			return
		}
	}
}

// prompt displays the threat details and reads the operator's decision.
func (a *Approver) prompt(lines <-chan string, req *Request) Decision {
	// Drain stale input only if the previous prompt timed out, because
	// a timeout leaves the operator's late response sitting in the channel.
	if a.lastPromptTimedOut {
		a.drainStaleLines(lines)
		a.lastPromptTimedOut = false
	}
	_, _ = fmt.Fprintf(a.output, "\n=== PIPELOCK: THREAT DETECTED ===\n")
	if req.Agent != "" {
		_, _ = fmt.Fprintf(a.output, "Agent:    %s\n", req.Agent)
	}
	_, _ = fmt.Fprintf(a.output, "URL:      %s\n", truncate(req.URL, 80))
	_, _ = fmt.Fprintf(a.output, "Reason:   %s\n", req.Reason)
	if len(req.Patterns) > 0 {
		_, _ = fmt.Fprintf(a.output, "Patterns: %s\n", strings.Join(req.Patterns, ", "))
	}
	if req.Preview != "" {
		_, _ = fmt.Fprintf(a.output, "Preview:  %s\n", truncate(req.Preview, 200))
	}
	_, _ = fmt.Fprintf(a.output, "\nAllow (y), Block (N), or Strip (s)? [%ds timeout] ", int(a.timeout.Seconds()))

	select {
	case input := <-lines:
		switch input {
		case "y", "yes":
			_, _ = fmt.Fprintln(a.output, "-> Allowed.")
			return DecisionAllow
		case "s", "strip":
			_, _ = fmt.Fprintln(a.output, "-> Stripped.")
			return DecisionStrip
		default:
			_, _ = fmt.Fprintln(a.output, "-> Blocked.")
			return DecisionBlock
		}
	case <-time.After(a.timeout):
		_, _ = fmt.Fprintln(a.output, "\nTimeout — blocked.")
		a.lastPromptTimedOut = true
		return DecisionBlock
	case <-a.ctx.Done():
		return DecisionBlock
	}
}

// truncate returns s truncated to max runes with "..." suffix.
// Uses rune slicing to avoid splitting multi-byte UTF-8 characters.
func truncate(s string, maxLen int) string {
	runes := []rune(s)
	if len(runes) <= maxLen {
		return s
	}
	return string(runes[:maxLen]) + "..."
}

// isStdinTerminal checks if os.Stdin is a terminal device.
func isStdinTerminal() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}
