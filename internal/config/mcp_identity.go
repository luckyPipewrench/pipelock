// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"net/http"
	"net/url"
	"path"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"github.com/luckyPipewrench/pipelock/internal/mcp/localservice"
)

// Schemes an mcp_identities entry may match.
const (
	MCPIdentitySchemeHTTP  = "http"
	MCPIdentitySchemeHTTPS = "https"
	MCPIdentitySchemeWS    = "ws"
	MCPIdentitySchemeWSS   = "wss"
)

// Literal loopback hosts an mcp_identities entry may match. They are distinct
// destinations: an entry for one never matches the other.
const (
	MCPIdentityHostIPv4Loopback = "127.0.0.1"
	MCPIdentityHostIPv6Loopback = "::1"
)

// MCPIdentitySessionScheme is the only authorization scheme a session header
// may declare.
const MCPIdentitySessionScheme = "Bearer"

// MCPCarrierPrefix is the environment namespace a credential carrier must use.
const MCPCarrierPrefix = "PIPELOCK_VSCODE_"

const (
	mcpIdentityRevisionDomain = "pipelock-mcp-identity-revision-v1"
	mcpIdentityMatcherVLS     = "verified_local_service"
	mcpIdentityMatcherNone    = "none"
)

// MCPIdentity registers one MCP server by what it is rather than by a name the
// launch supplies: the matcher says which upstream the identity covers, and
// the pins say which process must own that upstream's socket.
type MCPIdentity struct {
	// Name is the identity's server name. A launch whose upstream matches the
	// matcher is named by it; a launch that claims the name without matching
	// is refused.
	Name string `yaml:"name"`
	// VerifiedLocalService matches a loopback upstream and pins the process
	// that owns the connection to it.
	VerifiedLocalService *MCPVerifiedLocalService `yaml:"verified_local_service"`
}

// MCPVerifiedLocalService is the matcher and registration of a local service
// whose connection owner the proxy verifies through the kernel.
type MCPVerifiedLocalService struct {
	// Scheme is http, https, ws or wss.
	Scheme string `yaml:"scheme"`
	// Host is the literal 127.0.0.1 or ::1.
	Host string `yaml:"host"`
	// Path is the exact escaped URL path, starting with "/", with no query or
	// fragment. The port is deliberately not part of the matcher: it changes
	// on every start of an ephemeral-port service.
	Path string `yaml:"path"`
	// PrincipalUID is the effective uid the owning process must run as. A
	// pointer so that an omitted value is refused rather than read as root.
	PrincipalUID *uint32 `yaml:"principal_uid"`
	// ExecutableSHA256 is the lowercase hex digest of the owner's executable.
	ExecutableSHA256 string `yaml:"executable_sha256"`
	// MappedFiles are files the owner must hold open or mapped.
	MappedFiles []MCPIdentityFilePin `yaml:"mapped_files,omitempty"`
	// ControlEnvironment names loader or interpreter control variables the
	// owner may carry, each with its exact value.
	ControlEnvironment map[string]string `yaml:"control_environment,omitempty"`
	// SessionHeader declares the one per-session credential header that is
	// excluded from acknowledgment binding. Only http and https may declare it.
	SessionHeader *MCPIdentitySessionHeader `yaml:"session_header,omitempty"`
}

// MCPIdentityFilePin pins one file by absolute path and content digest.
type MCPIdentityFilePin struct {
	Path   string `yaml:"path"`
	SHA256 string `yaml:"sha256"`
}

// MCPIdentitySessionHeader declares the header that carries a per-session
// bearer token. The token value is never configured: it arrives through the
// named environment carrier at launch.
type MCPIdentitySessionHeader struct {
	// Name is the canonical header name, such as Authorization.
	Name string `yaml:"name"`
	// Scheme is the authorization scheme; only Bearer is accepted.
	Scheme string `yaml:"scheme"`
	// Carrier is the environment variable that supplies the header value.
	Carrier string `yaml:"carrier"`
}

// MCPCarrierNameProblem applies the carrier-name rule shared by launch flags
// and mcp_identities: an environment-variable-shaped name in the
// MCPCarrierPrefix namespace. It returns "" for an acceptable name and
// otherwise a message without any flag or field prefix.
func MCPCarrierNameProblem(carrier string) string {
	if !ValidMCPEnvName(carrier) {
		return "invalid carrier name"
	}
	if !strings.HasPrefix(carrier, MCPCarrierPrefix) {
		return "carrier must use the " + MCPCarrierPrefix + " namespace"
	}
	return ""
}

// ValidMCPEnvName reports whether name is shaped like a portable environment
// variable name: a letter or underscore, then letters, digits or underscores.
func ValidMCPEnvName(name string) bool {
	if name == "" || (name[0] != '_' && (name[0] < 'A' || name[0] > 'Z') && (name[0] < 'a' || name[0] > 'z')) {
		return false
	}
	for i := 1; i < len(name); i++ {
		c := name[i]
		if c != '_' && (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') && (c < '0' || c > '9') {
			return false
		}
	}
	return true
}

// FindMCPIdentity returns the registered identity with the given name.
func FindMCPIdentity(identities []MCPIdentity, name string) (MCPIdentity, int, bool) {
	for i, id := range identities {
		if id.Name == name {
			return id, i, true
		}
	}
	return MCPIdentity{}, -1, false
}

// Revision returns a stable digest of the whole entry: name, matcher, every
// pin and the session header declaration. Any change to the entry changes it,
// so state keyed by the revision cannot outlive the registration it was made
// under. Map and list order in the configuration does not affect it.
func (e MCPIdentity) Revision() string {
	h := sha256.New()
	w := revisionWriter{h: h}
	w.str(mcpIdentityRevisionDomain)
	w.str(e.Name)
	v := e.VerifiedLocalService
	if v == nil {
		w.str(mcpIdentityMatcherNone)
		return hex.EncodeToString(h.Sum(nil))
	}
	w.str(mcpIdentityMatcherVLS)
	w.str(v.Scheme)
	w.str(v.Host)
	w.str(v.Path)
	if v.PrincipalUID == nil {
		w.str("uid-absent")
	} else {
		w.str("uid")
		w.str(strconv.FormatUint(uint64(*v.PrincipalUID), 10))
	}
	w.str(v.ExecutableSHA256)
	files := sortedMCPIdentityFiles(v.MappedFiles)
	w.num(len(files))
	for _, f := range files {
		w.str(f.Path)
		w.str(f.SHA256)
	}
	keys := make([]string, 0, len(v.ControlEnvironment))
	for k := range v.ControlEnvironment {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	w.num(len(keys))
	for _, k := range keys {
		w.str(k)
		w.str(v.ControlEnvironment[k])
	}
	if v.SessionHeader == nil {
		w.str("session-header-absent")
	} else {
		w.str("session-header")
		w.str(v.SessionHeader.Name)
		w.str(v.SessionHeader.Scheme)
		w.str(v.SessionHeader.Carrier)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// revisionWriter length-prefixes every field so that no two distinct entries
// share an encoding.
type revisionWriter struct{ h hash.Hash }

func (w revisionWriter) num(n int) {
	_, _ = w.h.Write([]byte(strconv.Itoa(n) + ":"))
}

func (w revisionWriter) str(s string) {
	w.num(len(s))
	_, _ = w.h.Write([]byte(s))
}

func sortedMCPIdentityFiles(files []MCPIdentityFilePin) []MCPIdentityFilePin {
	if len(files) == 0 {
		return nil
	}
	out := append([]MCPIdentityFilePin(nil), files...)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Path != out[j].Path {
			return out[i].Path < out[j].Path
		}
		return out[i].SHA256 < out[j].SHA256
	})
	return out
}

// canonicalMCPIdentities returns a deep copy ordered by name with mapped files
// ordered by path, so two registries that differ only in listing order hash
// equal.
func canonicalMCPIdentities(entries []MCPIdentity) []MCPIdentity {
	out := cloneMCPIdentities(entries)
	for i := range out {
		if v := out[i].VerifiedLocalService; v != nil {
			v.MappedFiles = sortedMCPIdentityFiles(v.MappedFiles)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// cloneMCPIdentities deep-copies the registry in its configured order.
func cloneMCPIdentities(entries []MCPIdentity) []MCPIdentity {
	if len(entries) == 0 {
		return nil
	}
	out := make([]MCPIdentity, len(entries))
	for i, e := range entries {
		out[i] = MCPIdentity{Name: e.Name}
		if e.VerifiedLocalService == nil {
			continue
		}
		v := *e.VerifiedLocalService
		v.MappedFiles = append([]MCPIdentityFilePin(nil), v.MappedFiles...)
		if v.PrincipalUID != nil {
			uid := *v.PrincipalUID
			v.PrincipalUID = &uid
		}
		if v.SessionHeader != nil {
			sh := *v.SessionHeader
			v.SessionHeader = &sh
		}
		if len(v.ControlEnvironment) > 0 {
			env := make(map[string]string, len(v.ControlEnvironment))
			for k, val := range v.ControlEnvironment {
				env[k] = val
			}
			v.ControlEnvironment = env
		} else {
			v.ControlEnvironment = nil
		}
		out[i].VerifiedLocalService = &v
	}
	return out
}

func mcpIdentityField(i int, rest string) string {
	return fmt.Sprintf("mcp_identities[%d]%s", i, rest)
}

// validateMCPIdentities checks the registry at load and on reload.
func validateMCPIdentities(entries []MCPIdentity) error {
	denied := make(map[string]struct{})
	for _, name := range localservice.ControlEnvironmentDenyList() {
		denied[name] = struct{}{}
	}
	names := make(map[string]int, len(entries))
	type matcher struct{ scheme, host, path string }
	matchers := make(map[matcher]int, len(entries))
	for i, e := range entries {
		if err := validateMCPServerName(e.Name, mcpIdentityField(i, ".name")); err != nil {
			return err
		}
		if prior, dup := names[e.Name]; dup {
			return fmt.Errorf("%s %q duplicates mcp_identities[%d].name", mcpIdentityField(i, ".name"), e.Name, prior)
		}
		names[e.Name] = i
		v := e.VerifiedLocalService
		if v == nil {
			return fmt.Errorf("%s: exactly one matcher is required; set verified_local_service", mcpIdentityField(i, ""))
		}
		if err := validateMCPVerifiedLocalService(i, v, denied); err != nil {
			return err
		}
		key := matcher{v.Scheme, v.Host, v.Path}
		if prior, dup := matchers[key]; dup {
			return fmt.Errorf("%s matches the same scheme, host and path as mcp_identities[%d]; one upstream cannot belong to two identities", mcpIdentityField(i, ".verified_local_service"), prior)
		}
		matchers[key] = i
	}
	return nil
}

func validateMCPVerifiedLocalService(i int, v *MCPVerifiedLocalService, denied map[string]struct{}) error {
	at := func(rest string) string { return mcpIdentityField(i, ".verified_local_service"+rest) }
	switch v.Scheme {
	case MCPIdentitySchemeHTTP, MCPIdentitySchemeHTTPS, MCPIdentitySchemeWS, MCPIdentitySchemeWSS:
	case "":
		return fmt.Errorf("%s is required: one of http, https, ws, wss", at(".scheme"))
	default:
		return fmt.Errorf("%s %q must be one of http, https, ws, wss", at(".scheme"), v.Scheme)
	}
	if v.Host != MCPIdentityHostIPv4Loopback && v.Host != MCPIdentityHostIPv6Loopback {
		return fmt.Errorf("%s %q must be the literal %s or %s, without brackets, a port or a hostname", at(".host"), v.Host, MCPIdentityHostIPv4Loopback, MCPIdentityHostIPv6Loopback)
	}
	if err := validateMCPIdentityPath(v.Path); err != nil {
		return fmt.Errorf("%s %w", at(".path"), err)
	}
	if v.PrincipalUID == nil {
		return fmt.Errorf("%s is required: the effective uid the owning process runs as", at(".principal_uid"))
	}
	if len(v.ExecutableSHA256) != 64 || !validLowerHex(v.ExecutableSHA256) {
		return fmt.Errorf("%s must be 64 lowercase hex characters", at(".executable_sha256"))
	}
	if err := validateMCPIdentityFiles(v.MappedFiles, at(".mapped_files")); err != nil {
		return err
	}
	for name, value := range v.ControlEnvironment {
		if _, ok := denied[name]; !ok {
			return fmt.Errorf("%s: %q is not a known loader or interpreter control variable; only names on the control-environment deny list can be registered", at(".control_environment"), name)
		}
		if strings.ContainsRune(value, 0) {
			return fmt.Errorf("%s[%q] must not contain a NUL byte", at(".control_environment"), name)
		}
	}
	if sh := v.SessionHeader; sh != nil {
		return validateMCPIdentitySessionHeader(v.Scheme, sh, at(".session_header"))
	}
	return nil
}

func validateMCPIdentityPath(p string) error {
	if p == "" || p[0] != '/' {
		return fmt.Errorf("%q must start with \"/\"", p)
	}
	if strings.ContainsAny(p, "?#") {
		return fmt.Errorf("%q must not contain a query or fragment", p)
	}
	for _, r := range p {
		if r > unicode.MaxASCII || unicode.IsSpace(r) || unicode.IsControl(r) {
			return fmt.Errorf("%q must be an escaped path of printable ASCII", p)
		}
	}
	u, err := url.Parse("http://" + MCPIdentityHostIPv4Loopback + p)
	if err != nil {
		return fmt.Errorf("%q is not a valid escaped path: %w", p, err)
	}
	if got := u.EscapedPath(); got != p {
		return fmt.Errorf("%q must be written in its canonical escaped form %q", p, got)
	}
	for _, r := range u.Path {
		if unicode.IsControl(r) {
			return fmt.Errorf("%q must not decode to control characters", p)
		}
	}
	return nil
}

func validateMCPIdentityFiles(files []MCPIdentityFilePin, label string) error {
	seen := make(map[string]int, len(files))
	for i, f := range files {
		at := fmt.Sprintf("%s[%d]", label, i)
		if !path.IsAbs(f.Path) || path.Clean(f.Path) != f.Path || strings.ContainsRune(f.Path, 0) {
			return fmt.Errorf("%s.path %q must be an absolute, clean path", at, f.Path)
		}
		if prior, dup := seen[f.Path]; dup {
			return fmt.Errorf("%s.path %q duplicates %s[%d]", at, f.Path, label, prior)
		}
		seen[f.Path] = i
		if len(f.SHA256) != 64 || !validLowerHex(f.SHA256) {
			return fmt.Errorf("%s.sha256 must be 64 lowercase hex characters", at)
		}
	}
	return nil
}

// ValidateMCPIdentitySessionHeader applies the load-time session_header rules
// to a header built elsewhere, such as by pipelock mcp identity register, so a
// printed registration is refused for the same reasons the loader would
// refuse it.
func ValidateMCPIdentitySessionHeader(scheme string, sh *MCPIdentitySessionHeader, label string) error {
	return validateMCPIdentitySessionHeader(scheme, sh, label)
}

func validateMCPIdentitySessionHeader(scheme string, sh *MCPIdentitySessionHeader, label string) error {
	if scheme == MCPIdentitySchemeWS || scheme == MCPIdentitySchemeWSS {
		return fmt.Errorf("%s is not supported with scheme %s: a WebSocket handshake header cannot be separated from the bound session", label, scheme)
	}
	if sh.Name == "" || !validHTTPHeaderToken(sh.Name) {
		return fmt.Errorf("%s.name %q must be an HTTP header name", label, sh.Name)
	}
	if canon := http.CanonicalHeaderKey(sh.Name); canon != sh.Name {
		return fmt.Errorf("%s.name %q must be written in canonical form %q", label, sh.Name, canon)
	}
	if sh.Scheme != MCPIdentitySessionScheme {
		return fmt.Errorf("%s.scheme %q must be %s", label, sh.Scheme, MCPIdentitySessionScheme)
	}
	if problem := MCPCarrierNameProblem(sh.Carrier); problem != "" {
		return fmt.Errorf("%s.carrier %q: %s", label, sh.Carrier, problem)
	}
	return nil
}

func validHTTPHeaderToken(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z':
		case strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0:
		default:
			return false
		}
	}
	return s != ""
}
