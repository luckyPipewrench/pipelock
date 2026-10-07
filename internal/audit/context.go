// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/luckyPipewrench/pipelock/internal/envelope"
)

// LogContext carries common fields shared across all audit log events.
// Use the typed constructors (NewHTTPLogContext, NewMCPLogContext,
// NewConnectLogContext) to enforce required fields per transport.
//
// URL, Target, and Resource are mutually exclusive identifiers:
//   - URL: actual HTTP/HTTPS URLs (fetch, forward-proxy, response scan)
//   - Target: CONNECT tunnel host:port destinations
//   - Resource: MCP tool names, config file paths, listen addresses
type LogContext struct {
	method          string
	url             string // actual HTTP URL
	target          string // CONNECT host:port
	resource        string // MCP tool, config path, listen address
	clientIP        string
	requestID       string
	agent           string
	agentAuth       string
	dowSubjectKey   string
	dowSubjectTrust string
	correlation     CorrelationID // emitted events only; see correlation.go
}

func (c LogContext) Method() string    { return c.method }
func (c LogContext) URL() string       { return c.url }
func (c LogContext) Target() string    { return c.target }
func (c LogContext) Resource() string  { return c.resource }
func (c LogContext) ClientIP() string  { return c.clientIP }
func (c LogContext) RequestID() string { return c.requestID }
func (c LogContext) Agent() string     { return c.agent }

// AgentAuth reports the provenance grade of the agent label, using the
// envelope.ActorAuth vocabulary ("bound", "config-default", "matched",
// "self-declared"). An empty value means the grade is unknown and MUST be
// treated as untrusted by every consumer.
func (c LogContext) AgentAuth() string { return c.agentAuth }

// agentAuthOrUnknown returns the recorded grade, or the fail-closed unknown
// grade when the context never carried one.
func (c LogContext) agentAuthOrUnknown() string {
	if c.agentAuth == "" {
		return string(envelope.ActorAuthUnknown)
	}
	return c.agentAuth
}

// WithActorAuth records how the agent label was established. It mirrors
// WithDoWAttribution: the grade travels with the context so downstream
// emitters can tell an infrastructure-bound identity from a caller-supplied
// one. A caller that omits it gets the fail-closed unknown treatment.
func (c LogContext) WithActorAuth(auth string) LogContext {
	c.agentAuth = auth
	return c
}

// WithDoWAttribution adds denial-of-wallet subject metadata to a copy of the
// context. The raw subject key stays process-local and is HMAC-redacted by the
// logger before any local or external audit emission.
func (c LogContext) WithDoWAttribution(subjectKey, subjectTrust string) LogContext {
	c.dowSubjectKey = subjectKey
	c.dowSubjectTrust = subjectTrust
	return c
}

var (
	errLogContextMissingClientIP  = errors.New("audit log context: client IP required")
	errLogContextMissingRequestID = errors.New("audit log context: request ID required")
	errLogContextMissingURL       = errors.New("audit log context: url required")
	errLogContextMissingTarget    = errors.New("audit log context: target required")
	errLogContextMissingResource  = errors.New("audit log context: resource required")
	errLogContextIdentifierClash  = errors.New("audit log context: url, target, and resource are mutually exclusive")
)

// LogContextOpts bundles the parameters newLogContext consumes so the
// internal constructor stays under the >6-params options-struct rule
// (project CLAUDE.md). External callers should keep using the typed
// NewHTTPLogContext / NewMCPLogContext / NewConnectLogContext / etc.
// helpers; LogContextOpts is internal plumbing.
type LogContextOpts struct {
	Method    string
	URL       string
	Target    string
	Resource  string
	ClientIP  string
	RequestID string
	Agent     string
}

func newLogContext(o LogContextOpts) (LogContext, error) {
	identifierCount := 0
	if o.URL != "" {
		identifierCount++
	}
	if o.Target != "" {
		identifierCount++
	}
	if o.Resource != "" {
		identifierCount++
	}
	if identifierCount > 1 {
		return LogContext{}, errLogContextIdentifierClash
	}
	if o.Target != "" && o.Method != http.MethodConnect {
		return LogContext{}, fmt.Errorf("audit log context: target contexts require %q method", http.MethodConnect)
	}
	return LogContext{
		method:    o.Method,
		url:       o.URL,
		target:    o.Target,
		resource:  o.Resource,
		clientIP:  o.ClientIP,
		requestID: o.RequestID,
		agent:     o.Agent,
	}, nil
}

// NewHTTPLogContext creates a LogContext for URL-based proxy requests
// (fetch, forward-proxy, WebSocket, response scan). ClientIP and RequestID are
// required to prevent accidental omission on URL-bearing transport paths.
func NewHTTPLogContext(method, url, clientIP, requestID, agent string) (LogContext, error) {
	if url == "" {
		return LogContext{}, errLogContextMissingURL
	}
	if clientIP == "" {
		return LogContext{}, errLogContextMissingClientIP
	}
	if requestID == "" {
		return LogContext{}, errLogContextMissingRequestID
	}
	return newLogContext(LogContextOpts{Method: method, URL: url, ClientIP: clientIP, RequestID: requestID, Agent: agent})
}

// NewMCPLogContext creates a LogContext for MCP proxy requests. HTTP-specific
// fields (ClientIP, RequestID) are omitted by design since MCP stdio has no
// HTTP transport layer.
func NewMCPLogContext(method, resource, agent string) (LogContext, error) {
	if resource == "" {
		return LogContext{}, errLogContextMissingResource
	}
	return newLogContext(LogContextOpts{Method: method, Resource: resource, Agent: agent})
}

// NewConnectLogContext creates a LogContext for CONNECT tunnel operations.
func NewConnectLogContext(target, clientIP, requestID, agent string) (LogContext, error) {
	if target == "" {
		return LogContext{}, errLogContextMissingTarget
	}
	if clientIP == "" {
		return LogContext{}, errLogContextMissingClientIP
	}
	if requestID == "" {
		return LogContext{}, errLogContextMissingRequestID
	}
	return newLogContext(LogContextOpts{Method: http.MethodConnect, Target: target, ClientIP: clientIP, RequestID: requestID, Agent: agent})
}

// NewResourceLogContext creates a LogContext for operational events scoped to a
// local resource such as a config path or listen address.
func NewResourceLogContext(method, resource string) LogContext {
	ctx, _ := newLogContext(LogContextOpts{Method: method, Resource: resource})
	return ctx
}

// NewRequestLogContext creates a LogContext scoped only to a request ID.
func NewRequestLogContext(requestID string) LogContext {
	ctx, _ := newLogContext(LogContextOpts{RequestID: requestID})
	return ctx
}

// NewMethodLogContext creates a LogContext scoped only to an operation name.
func NewMethodLogContext(method string) LogContext {
	ctx, _ := newLogContext(LogContextOpts{Method: method})
	return ctx
}
