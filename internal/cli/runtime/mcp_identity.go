// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/mcp"
	"github.com/luckyPipewrench/pipelock/internal/mcp/identity"
	"github.com/luckyPipewrench/pipelock/internal/mcp/localservice"
)

// localServiceVerifier is the one verifier of the process. It caches
// executable digests across connections, so every surface shares it.
var localServiceVerifier = sync.OnceValue(localservice.NewVerifier)

// verifiedDialContext wraps an upstream dial function so every new connection
// is verified against the resolution's pin before any byte is sent on it. A
// resolution without a pin is returned unchanged.
//
// Verification runs per dialed connection. The transport reuses pooled
// keep-alive connections, and a reused connection is one already verified
// when it was dialed, so reuse does not widen what was verified. Keep-alives
// stay enabled for that reason; a service that is replaced closes its
// connections, and the next dial is verified again.
//
// The HTTP and WebSocket clients collapse a dial failure to a generic upstream
// error, so a refusal is also written to logW (when set): the operator needs the
// failing registration field, and the text is Pipelock's own, never upstream bytes.
func verifiedDialContext(inner localservice.DialContextFunc, res identity.Resolution, logW io.Writer) localservice.DialContextFunc {
	if res.Pin == nil {
		return inner
	}
	pin := *res.Pin
	name := res.Name
	verifier := localServiceVerifier()
	// Dials run concurrently (pooled POSTs, the SSE GET stream, reconnects), so
	// refusals are serialized onto logW.
	if logW != nil {
		logW = &safeWriter{w: logW}
	}
	return localservice.VerifyingDialContext(inner, func(ctx context.Context, conn net.Conn) error {
		if _, err := verifier.VerifyConnContext(ctx, conn, pin); err != nil {
			err = fmt.Errorf("verified local service %s: %w", name, err)
			if logW != nil {
				_, _ = fmt.Fprintf(logW, "pipelock: refused upstream connection: %v\n", err)
			}
			return err
		}
		return nil
	})
}

// launchBinding is the acknowledgment binding of a launch: the
// verified-local-session digest for a registered verified local service and the
// transport-v2 digest for everything else.
func launchBinding(res identity.Resolution, t identity.Transport, in mcpBindingInputs) (string, error) {
	if res.BindingMode == config.MCPAckBindingModeVerifiedLocalSession {
		return identity.SessionBinding(res, t)
	}
	return mcpServerBinding(in), nil
}

// listenerIdentityHeadersFn binds every operator/client-selected header on a
// verified listener request. The live identity resolver still governs reload
// revocation; only the binding is specialized to the request's headers.
func listenerIdentityHeadersFn(res identity.Resolution, t identity.Transport, current func() mcp.ServerIdentity) func(http.Header) mcp.ServerIdentity {
	if res.BindingMode != config.MCPAckBindingModeVerifiedLocalSession {
		return nil
	}
	return func(headers http.Header) mcp.ServerIdentity {
		id := current()
		if id.Refusal != "" {
			return id
		}
		requestTransport := t
		requestTransport.Headers = nil
		for name, values := range headers {
			for _, value := range values {
				requestTransport.Headers = append(requestTransport.Headers, identity.Header{Name: name, Value: value})
			}
		}
		binding, err := identity.SessionBinding(res, requestTransport)
		if err != nil {
			return mcp.ServerIdentity{Refusal: fmt.Sprintf("verified local service %s binding refused: %v", res.Name, err)}
		}
		id.Binding = binding
		return id
	}
}

// resolveLaunchIdentity resolves the identity of a launch and prints the
// startup line, so every launch, named or not, shows which identity and binding
// its acknowledgments use.
func resolveLaunchIdentity(cfg *config.Config, explicitName string, t identity.Transport, stderr io.Writer) (identity.Resolution, error) {
	res, err := identity.Resolve(cfg, explicitName, t)
	if err != nil {
		return identity.Resolution{}, err
	}
	_, _ = fmt.Fprintln(stderr, identity.StartupLine(res))
	return res, nil
}

// carrierHeader is one header resolved from a --header-carrier mapping, with the
// name of the environment variable it came from.
type carrierHeader struct {
	Header  string
	Carrier string
	Value   string
}

// resolveHeaderCarrierEntries resolves --header-carrier mappings and keeps the
// carrier variable name each value came from.
func resolveHeaderCarrierEntries(mappings []string) ([]carrierHeader, error) {
	entries := make([]carrierHeader, 0, len(mappings))
	for _, mapping := range mappings {
		header, carrier, err := parseCarrierMapping("--header-carrier", mapping)
		if err != nil {
			return nil, err
		}
		value, ok := os.LookupEnv(carrier)
		if !ok {
			return nil, fmt.Errorf("--header-carrier %q: required carrier %s is unset", mapping, carrier)
		}
		entries = append(entries, carrierHeader{Header: header, Carrier: carrier, Value: value})
	}
	return entries, nil
}

// identityHeaders returns the effective upstream headers in sending order, each
// with the source it came from (file, flag or carrier and the carrier
// variable name). The values are validated by the same parser the transport
// uses. They are never logged.
func identityHeaders(fileLines, flagLines []string, carriers []carrierHeader) ([]identity.Header, error) {
	headers := make([]identity.Header, 0, len(fileLines)+len(flagLines)+len(carriers))
	add := func(line, source, carrier string) error {
		parsed, err := parseHeaderFlags([]string{line})
		if err != nil {
			return err
		}
		for name, values := range parsed {
			for _, value := range values {
				headers = append(headers, identity.Header{Name: name, Value: value, Source: source, Carrier: carrier})
			}
		}
		return nil
	}
	for _, line := range fileLines {
		if err := add(line, identity.HeaderSourceFile, ""); err != nil {
			return nil, err
		}
	}
	for _, line := range flagLines {
		if err := add(line, identity.HeaderSourceFlag, ""); err != nil {
			return nil, err
		}
	}
	for _, c := range carriers {
		if err := add(c.Header+": "+c.Value, identity.HeaderSourceCarrier, c.Carrier); err != nil {
			return nil, err
		}
	}
	return headers, nil
}

// upstreamTransportKind maps an upstream URL scheme to a transport kind.
func upstreamTransportKind(isWS bool) string {
	if isWS {
		return identity.KindWS
	}
	return identity.KindHTTP
}

// runListenerIdentity is the identity of the `pipelock run` MCP listener. The
// resolution made at startup is pinned for the life of the listener. Every
// request re-resolves against the current configuration snapshot; when that
// resolution differs from the pinned one the listener stops serving, because a
// listener that kept serving would be running under a registration the
// operator has since changed.
type runListenerIdentity struct {
	explicitName string
	pinned       identity.Resolution
	binding      string
	transport    identity.Transport
	current      atomic.Pointer[runListenerResolution]
}

type runListenerResolution struct {
	cfg *config.Config
	res identity.Resolution
	err error
}

func newRunListenerIdentity(explicitName string, pinned identity.Resolution, binding string, t identity.Transport) *runListenerIdentity {
	return &runListenerIdentity{explicitName: explicitName, pinned: pinned, binding: binding, transport: t}
}

// resolveFor resolves the listener against cfg, cached by the config pointer so
// a request does not re-resolve an unchanged snapshot.
func (r *runListenerIdentity) resolveFor(cfg *config.Config) runListenerResolution {
	if cached := r.current.Load(); cached != nil && cached.cfg == cfg {
		return *cached
	}
	res, err := identity.Resolve(cfg, r.explicitName, r.transport)
	fresh := &runListenerResolution{cfg: cfg, res: res, err: err}
	r.current.Store(fresh)
	return *fresh
}

// changed reports whether the registration this listener started under no
// longer resolves to the same identity.
func (r *runListenerIdentity) changed(cfg *config.Config) bool {
	got := r.resolveFor(cfg)
	return got.err != nil || !got.res.SameAs(r.pinned)
}

// armingName is the name that may arm response trust, taint, suppression and
// core-observe. It is empty once the registration changed, so a stale identity
// arms nothing.
func (r *runListenerIdentity) armingName(cfg *config.Config) string {
	if r.changed(cfg) {
		return ""
	}
	return r.pinned.ArmingName
}

// identityFn returns the per-request identity stamped onto the listener's
// options.
func (r *runListenerIdentity) identityFn(currentConfig func() *config.Config) func() mcp.ServerIdentity {
	return func() mcp.ServerIdentity {
		if r.changed(currentConfig()) {
			return mcp.ServerIdentity{
				Refusal: fmt.Sprintf("verified local service %s registration changed; restart pipelock run", displayName(r.pinned.Name)),
			}
		}
		return mcp.ServerIdentity{
			Name:        r.pinned.Name,
			PolicyName:  r.pinned.ArmingName,
			Binding:     r.binding,
			BindingMode: r.pinned.BindingMode,
			Revision:    r.pinned.Revision,
		}
	}
}

func displayName(name string) string {
	if strings.TrimSpace(name) == "" {
		return "(unnamed)"
	}
	return name
}

// listenerTransport is the transport of the `pipelock run` MCP listener: an
// HTTP upstream with no per-launch headers.
func listenerTransport(upstream string) identity.Transport {
	return identity.Transport{Kind: identity.KindHTTP, UpstreamURL: upstream}
}

// requireNoSessionHeader refuses a listener whose upstream is registered with a
// per-session header, which `pipelock run` cannot carry.
func requireNoSessionHeader(cfg *config.Config, t identity.Transport) error {
	if i, ok := identity.DeclaresSessionHeader(cfg, t); ok {
		return fmt.Errorf("mcp_identities[%d] declares a session_header, which pipelock run cannot carry per session; launch this server with pipelock mcp proxy instead", i)
	}
	return nil
}
