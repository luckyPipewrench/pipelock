// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package identity resolves which registered MCP server identity a launch
// is, and builds the acknowledgment binding for a verified local service.
//
// One resolver serves every entry point (pipelock mcp proxy and the MCP
// listener started by pipelock run), so the same upstream resolves to the same
// identity wherever it is launched.
package identity

import (
	"fmt"
	"net/http"
	"net/url"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/mcp"
	"github.com/luckyPipewrench/pipelock/internal/mcp/localservice"
	"github.com/luckyPipewrench/pipelock/internal/mcp/tools"
)

// Transport kinds a launch can have.
const (
	KindHTTP       = "http"
	KindWS         = "ws"
	KindSubprocess = "subprocess"
)

// Where an effective upstream header came from.
const (
	HeaderSourceFile    = "file"
	HeaderSourceFlag    = "flag"
	HeaderSourceCarrier = "carrier"
)

// How a resolution got its name.
const (
	SourceExplicit             = "explicit"
	SourceUnnamed              = "unnamed"
	SourceVerifiedLocalService = "verified-local-service"
)

// BindingDomain is the ServerBindingDigest kind of a verified-local-session
// binding.
const BindingDomain = "verified-local-session-v1"

const unnamedServer = "(unnamed)"

// Header is one effective upstream header of a launch.
type Header struct {
	// Name is the canonical header name.
	Name  string
	Value string
	// Source is HeaderSourceFile, HeaderSourceFlag or HeaderSourceCarrier.
	Source string
	// Carrier is the environment variable that supplied the value when Source
	// is HeaderSourceCarrier.
	Carrier string
}

// Transport is everything about a launch that identity resolution and the
// acknowledgment binding depend on.
type Transport struct {
	// Kind is KindHTTP, KindWS or KindSubprocess.
	Kind        string
	UpstreamURL string
	// Headers are the effective upstream headers from every source, in the order
	// they are sent.
	Headers []Header
	// Command is the subprocess command line (KindSubprocess).
	Command []string
	// ChildEnv is the resolved child-environment override list.
	ChildEnv []string
}

// Resolution is the identity of one launch.
type Resolution struct {
	// Name is the server name used for audit, receipts, adaptive state and
	// acknowledgment lookup. Empty for an unnamed launch.
	Name string
	// ArmingName is the name that arms name-keyed policy: response trust, taint
	// trust, the response-action override, suppress and core-observe targets. It
	// equals Name for a verified identity, and for a launch that supplied its own
	// name. It is empty only for an unnamed launch. It is a separate field so a
	// name that was never proven can be recorded without ever arming policy.
	ArmingName string
	// Source is SourceExplicit, SourceUnnamed or SourceVerifiedLocalService.
	Source string
	// Revision is the registered entry's revision; empty unless verified.
	Revision string
	// BindingMode is the acknowledgment binding mode of the launch.
	BindingMode string
	// Pin is what the connection owner is compared with; nil unless verified.
	Pin *localservice.Pin
	// Entry is the matched registry entry; nil unless verified.
	Entry *config.MCPIdentity
}

// Resolve resolves the identity of a launch from the registry, an optional
// explicit name (--server-name or --mcp-server-name) and the transport.
//
// A launch whose upstream matches a registered verified local service is named
// by that entry. A launch that claims a registered name without matching it is
// refused rather than treated as an unregistered server of the same name. Any
// other launch keeps the name it supplied, if any.
func Resolve(cfg *config.Config, explicitName string, t Transport) (Resolution, error) {
	return resolve(cfg, explicitName, t, runtime.GOOS == "linux")
}

// resolve is Resolve with the platform capability injected, so the refusal on a
// platform that cannot verify a connection owner is testable everywhere.
func resolve(cfg *config.Config, explicitName string, t Transport, canVerify bool) (Resolution, error) {
	if explicitName != "" {
		if err := config.ValidateMCPServerName(explicitName, "MCP server name"); err != nil {
			return Resolution{}, err
		}
	}
	var identities []config.MCPIdentity
	if cfg != nil {
		identities = cfg.MCPIdentities
	}

	matched, portless := matchingIdentities(identities, t)
	if portless && len(matched) > 0 {
		return Resolution{}, fmt.Errorf("mcp_identities[%d] requires an explicit port in the upstream URL", matched[0])
	}
	switch len(matched) {
	case 0:
		if explicitName != "" {
			if _, i, ok := config.FindMCPIdentity(identities, explicitName); ok {
				return Resolution{}, fmt.Errorf("identity %s is registered as a verified local service; this launch's upstream does not match mcp_identities[%d].verified_local_service", explicitName, i)
			}
		}
		return Legacy(explicitName), nil
	case 1:
	default:
		return Resolution{}, fmt.Errorf("this launch's upstream matches more than one mcp_identities entry (%s); each upstream must match exactly one", indexList(matched))
	}

	i := matched[0]
	entry := identities[i]
	v := entry.VerifiedLocalService
	if explicitName != "" && explicitName != entry.Name {
		return Resolution{}, fmt.Errorf("server name %q conflicts with mcp_identities[%d], which names this upstream %q", explicitName, i, entry.Name)
	}
	if v.SessionHeader != nil {
		if err := checkSessionHeader(i, v.SessionHeader, t.Headers); err != nil {
			return Resolution{}, err
		}
	}
	if !canVerify {
		return Resolution{}, fmt.Errorf("verified local service requires Linux; this platform cannot verify mcp_identities[%d]", i)
	}
	pin, err := buildPin(i, v)
	if err != nil {
		return Resolution{}, err
	}
	return Resolution{
		Name:        entry.Name,
		ArmingName:  entry.Name,
		Source:      SourceVerifiedLocalService,
		Revision:    entry.Revision(),
		BindingMode: config.MCPAckBindingModeVerifiedLocalSession,
		Pin:         pin,
		Entry:       &entry,
	}, nil
}

// Legacy is the resolution of a launch that matched no registered identity: the
// name it supplied, if any, with transport-v2 acknowledgment binding and no
// connection-owner verification. Its name arms policy exactly as before the
// registry existed.
func Legacy(name string) Resolution {
	r := Resolution{
		Name:        name,
		ArmingName:  name,
		Source:      SourceExplicit,
		BindingMode: config.MCPAckBindingModeTransportV2,
	}
	if name == "" {
		r.Source = SourceUnnamed
	}
	return r
}

// SameAs reports whether two resolutions are the same identity for a
// long-lived surface that pinned one at startup. The revision covers every pin,
// the matcher and the session header declaration, so a changed registration
// differs.
func (r Resolution) SameAs(o Resolution) bool {
	return r.Name == o.Name && r.ArmingName == o.ArmingName && r.Source == o.Source &&
		r.Revision == o.Revision && r.BindingMode == o.BindingMode
}

// DeclaresSessionHeader returns the index of the one registered entry that
// matches the launch shape and declares a per-session header.
func DeclaresSessionHeader(cfg *config.Config, t Transport) (int, bool) {
	if cfg == nil {
		return 0, false
	}
	matched, _ := matchingIdentities(cfg.MCPIdentities, t)
	if len(matched) != 1 {
		return 0, false
	}
	v := cfg.MCPIdentities[matched[0]].VerifiedLocalService
	if v == nil || v.SessionHeader == nil {
		return 0, false
	}
	return matched[0], true
}

// StartupLine is the one line a launch prints so the operator sees which
// identity the launch resolved to and which binding its acknowledgments use.
func StartupLine(r Resolution) string {
	name := r.Name
	if name == "" {
		name = unnamedServer
	}
	return fmt.Sprintf("MCP identity: server=%s source=%s binding=%s", name, r.Source, r.BindingMode)
}

func indexList(indexes []int) string {
	parts := make([]string, len(indexes))
	for n, i := range indexes {
		parts[n] = "mcp_identities[" + strconv.Itoa(i) + "]"
	}
	return strings.Join(parts, ", ")
}

// shape is the part of a launch URL an entry's matcher compares.
type shape struct {
	kind   string
	scheme string
	host   string
	path   string
	// portless is set when the URL has no explicit port. An entry that otherwise
	// matches such a URL refuses the launch: a connection to an implicit default
	// port is not something the pins were registered for.
	portless bool
}

// upstreamShape extracts the matchable shape of an upstream. It reports false
// for anything an entry may never match: a subprocess, an unparsable URL, a
// kind that disagrees with the scheme, an invalid port, and any URL carrying
// user info, a query (including an empty one), a fragment or an opaque part.
func upstreamShape(t Transport) (shape, bool) {
	var schemes [2]string
	switch t.Kind {
	case KindHTTP:
		schemes = [2]string{config.MCPIdentitySchemeHTTP, config.MCPIdentitySchemeHTTPS}
	case KindWS:
		schemes = [2]string{config.MCPIdentitySchemeWS, config.MCPIdentitySchemeWSS}
	default:
		return shape{}, false
	}
	if strings.Contains(t.UpstreamURL, "#") {
		return shape{}, false
	}
	u, err := url.Parse(t.UpstreamURL)
	if err != nil {
		return shape{}, false
	}
	if u.Scheme != schemes[0] && u.Scheme != schemes[1] {
		return shape{}, false
	}
	if u.User != nil || u.Opaque != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawFragment != "" {
		return shape{}, false
	}
	portless := u.Port() == ""
	if !portless {
		port, err := strconv.Atoi(u.Port())
		if err != nil || port < 1 || port > 65535 {
			return shape{}, false
		}
	}
	host := u.Hostname()
	if host == "" {
		return shape{}, false
	}
	return shape{kind: t.Kind, scheme: u.Scheme, host: host, path: u.EscapedPath(), portless: portless}, true
}

// matchingIdentities returns the indexes of every entry the launch matches, and
// whether the launch URL lacked the explicit port a match requires.
func matchingIdentities(identities []config.MCPIdentity, t Transport) ([]int, bool) {
	s, ok := upstreamShape(t)
	if !ok {
		return nil, false
	}
	var matched []int
	for i, e := range identities {
		v := e.VerifiedLocalService
		if v == nil {
			continue
		}
		if s.kind == KindWS && v.SessionHeader != nil {
			continue
		}
		if v.Scheme == s.scheme && v.Host == s.host && v.Path == s.path {
			matched = append(matched, i)
		}
	}
	return matched, s.portless
}

// checkSessionHeader enforces the declared session header: exactly one header
// of that name across every source, supplied by the declared carrier, holding
// "<Scheme> <token>" with a single token. A value that could carry more than one
// credential is refused because the binding treats the header as one session.
func checkSessionHeader(i int, sh *config.MCPIdentitySessionHeader, headers []Header) error {
	field := fmt.Sprintf("mcp_identities[%d].verified_local_service.session_header", i)
	var found []Header
	for _, h := range headers {
		if http.CanonicalHeaderKey(h.Name) == sh.Name {
			found = append(found, h)
		}
	}
	switch {
	case len(found) == 0:
		return fmt.Errorf("%s: header %s is required and was not supplied; provide it through the %s carrier", field, sh.Name, sh.Carrier)
	case len(found) > 1:
		return fmt.Errorf("%s: header %s must be supplied exactly once across all sources; it was supplied %d times", field, sh.Name, len(found))
	}
	h := found[0]
	if h.Source != HeaderSourceCarrier {
		return fmt.Errorf("%s: header %s must come from the %s carrier, not a %s", field, sh.Name, sh.Carrier, h.Source)
	}
	if h.Carrier != sh.Carrier {
		return fmt.Errorf("%s: header %s must come from the %s carrier, not %s", field, sh.Name, sh.Carrier, h.Carrier)
	}
	if strings.Contains(h.Value, ",") {
		return fmt.Errorf("%s: header %s must hold exactly one credential; a comma-combined value is refused", field, sh.Name)
	}
	scheme, token, ok := strings.Cut(h.Value, " ")
	if !ok || scheme != sh.Scheme || token == "" || strings.IndexFunc(token, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) >= 0 {
		return fmt.Errorf("%s: header %s must be \"%s <token>\" with exactly one token", field, sh.Name, sh.Scheme)
	}
	return nil
}

func buildPin(i int, v *config.MCPVerifiedLocalService) (*localservice.Pin, error) {
	if v.PrincipalUID == nil {
		return nil, fmt.Errorf("mcp_identities[%d].verified_local_service.principal_uid is not set", i)
	}
	pin := &localservice.Pin{
		PrincipalUID:     *v.PrincipalUID,
		ExecutableSHA256: v.ExecutableSHA256,
	}
	for _, f := range v.MappedFiles {
		pin.MappedFiles = append(pin.MappedFiles, localservice.FilePin{Path: f.Path, SHA256: f.SHA256})
	}
	if len(v.ControlEnvironment) > 0 {
		pin.ControlEnvironment = make(map[string]string, len(v.ControlEnvironment))
		for k, val := range v.ControlEnvironment {
			pin.ControlEnvironment[k] = val
		}
	}
	return pin, nil
}

// SessionBinding returns the digest a verified-local-session acknowledgment
// binds, under ServerBindingDigest("verified-local-session-v1").
//
// Bound: the identity name and revision; the pinned principal uid, executable
// digest and every mapped file (path and digest); the scheme, host and path of
// the registered matcher; the session header's name, carrier name, that it is
// present exactly once, and its authorization scheme; every other effective
// header, by canonical name, with values in sending order; and the
// child-environment overrides.
//
// Not bound: the URL port, which an ephemeral-port service picks on every
// start, and the session header's value, the bearer token that is new for each
// session. Neither can select a different server, tenant or principal: the
// connection owner is verified through the kernel against the same pins, and
// the token only authenticates the session.
func SessionBinding(r Resolution, t Transport) (string, error) {
	if r.BindingMode != config.MCPAckBindingModeVerifiedLocalSession || r.Entry == nil || r.Entry.VerifiedLocalService == nil || r.Pin == nil {
		return "", fmt.Errorf("resolution %q is not a verified local service", r.Name)
	}
	v := r.Entry.VerifiedLocalService
	pin := r.Pin

	files := append([]localservice.FilePin(nil), pin.MappedFiles...)
	sort.Slice(files, func(a, b int) bool {
		if files[a].Path != files[b].Path {
			return files[a].Path < files[b].Path
		}
		return files[a].SHA256 < files[b].SHA256
	})

	parts := []string{
		r.Name,
		r.Revision,
		strconv.FormatUint(uint64(pin.PrincipalUID), 10),
		pin.ExecutableSHA256,
		"files", strconv.Itoa(len(files)),
	}
	for _, f := range files {
		parts = append(parts, f.Path, f.SHA256)
	}
	parts = append(parts, v.Scheme, v.Host, v.Path)

	sessionName := ""
	if sh := v.SessionHeader; sh != nil {
		sessionName = sh.Name
		parts = append(parts, sh.Name, sh.Carrier, "1", "1", sh.Scheme)
	} else {
		parts = append(parts, "", "", "0", "0", "")
	}

	byName := make(map[string][]string)
	for _, h := range t.Headers {
		name := http.CanonicalHeaderKey(h.Name)
		if sessionName != "" && name == sessionName {
			continue
		}
		byName[name] = append(byName[name], h.Value)
	}
	names := make([]string, 0, len(byName))
	for name := range byName {
		names = append(names, name)
	}
	sort.Strings(names)
	parts = append(parts, "headers")
	for _, name := range names {
		parts = append(parts, "header:"+name)
		for _, val := range byName[name] {
			parts = append(parts, "value:"+val)
		}
	}

	parts = append(parts, "env")
	parts = append(parts, mcp.ChildEnvOverrideIdentity(t.ChildEnv)...)
	return tools.ServerBindingDigest(BindingDomain, parts...), nil
}
