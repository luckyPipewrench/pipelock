// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"path"
	"regexp"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/destination"
	"github.com/luckyPipewrench/pipelock/internal/normalize"
)

// CredentialAudienceAllow records a DLP match deliberately allowed because a
// compiled-in provider credential was presented to that provider's declared
// audience. It never carries matched credential bytes.
type CredentialAudienceAllow struct {
	PatternName string `json:"pattern_name"`
	Surface     string `json:"surface"`
	Destination string `json:"destination"`
}

// CredentialAudienceMismatch is explanatory metadata for a provider-bound DLP
// block. It names only compiled pattern metadata and canonical destination,
// never the matched credential.
type CredentialAudienceMismatch struct {
	PatternName string   `json:"pattern_name"`
	Surface     string   `json:"surface"`
	Destination string   `json:"destination"`
	Hosts       []string `json:"hosts"`
}

type credentialAudienceCandidate struct {
	patternName       string
	hosts             []string
	authorizationOnly bool
	carrierMask       uint16
	gitHosts          []string
	registryHosts     []string
	headerValue       string
}

// CredentialAudienceAuthorizationHeaderSurface distinguishes Authorization from other
// request headers during the decision. Both report the existing "header"
// telemetry surface.
const CredentialAudienceAuthorizationHeaderSurface = "authorization_header"

const credentialAudienceAuthorizationHeaderName = "Authorization"

const (
	credentialAudienceAuthorizationTokenSurface = "authorization_header_token"
	credentialAudienceAuthorizationBasicSurface = "authorization_header_basic"
	credentialAudienceAuthorizationOtherSurface = "authorization_header_other"
	credentialAudiencePrivateTokenSurface       = "header_private_token"
	credentialAudienceJobTokenSurface           = "header_job_token"
	// credentialAudienceURLQuerySurface is the decision surface for a match
	// that lives only in the URL query. It reports as the existing "url"
	// telemetry surface. The scanner earns it per match (see
	// urlDLPAudienceSurface); a bare "url" match never carries it.
	credentialAudienceURLQuerySurface = "url_query"
)

// CredentialAudienceHeaderSurface classifies the header that carried a match.
// Authorization is classified by scheme, and only a complete two-field value
// earns a scheme: Bearer stays distinct so the Google OAuth exception cannot
// attach to an arbitrary Authorization value, and any other shape is a surface
// no audience accepts.
func CredentialAudienceHeaderSurface(headerName, value string) string {
	switch {
	case strings.EqualFold(headerName, credentialAudienceAuthorizationHeaderName):
		fields := strings.Fields(value)
		if len(fields) != 2 {
			return credentialAudienceAuthorizationOtherSurface
		}
		switch {
		case strings.EqualFold(fields[0], "Bearer"):
			return CredentialAudienceAuthorizationHeaderSurface
		case strings.EqualFold(fields[0], "token"):
			return credentialAudienceAuthorizationTokenSurface
		case strings.EqualFold(fields[0], "Basic"):
			return credentialAudienceAuthorizationBasicSurface
		default:
			return credentialAudienceAuthorizationOtherSurface
		}
	case strings.EqualFold(headerName, "Private-Token"):
		return credentialAudiencePrivateTokenSurface
	case strings.EqualFold(headerName, "Job-Token"):
		return credentialAudienceJobTokenSurface
	default:
		return "header"
	}
}

func audienceSurfacePermitted(surface string, authorizationOnly bool, mask uint16) bool {
	if !authorizationOnly && mask == 0 {
		return true
	}
	switch surface {
	case CredentialAudienceAuthorizationHeaderSurface:
		return authorizationOnly || mask&config.CredentialAudienceCarrierAuthorizationBearer != 0
	case credentialAudienceAuthorizationTokenSurface:
		return mask&config.CredentialAudienceCarrierAuthorizationToken != 0
	case credentialAudienceAuthorizationBasicSurface:
		return mask&config.CredentialAudienceCarrierAuthorizationBasic != 0
	case credentialAudiencePrivateTokenSurface:
		return mask&config.CredentialAudienceCarrierPrivateToken != 0
	case credentialAudienceJobTokenSurface:
		return mask&config.CredentialAudienceCarrierJobToken != 0
	case credentialAudienceURLQuerySurface:
		return mask&config.CredentialAudienceCarrierURLQuery != 0
	default:
		return false
	}
}

// filterCredentialAudience is the one destination-aware filter for compiled
// credential audience exceptions. An empty host list, a malformed target, and a
// mismatch all retain the DLP match and therefore block. A core-floor pattern is
// filtered here only when it carries a compiled audience: core-ness alone no
// longer disqualifies the exception, because the audience is compiled-in and
// unreachable from YAML, so this cannot widen the floor from configuration. This
// deliberately fails closed: a host allow is never inferred from a parse error.
func filterCredentialAudience(candidates []credentialAudienceCandidate, target, surface string) ([]bool, []CredentialAudienceAllow) {
	keep := make([]bool, len(candidates))
	for i := range keep {
		keep[i] = true
	}
	host, ok := canonicalCredentialAudienceDestination(target)
	if !ok {
		return keep, nil
	}
	// Signed download grants use HTTPS query carriage. The shared host
	// canonicalizer also accepts WSS for other credential carriers.
	if surface == credentialAudienceURLQuerySurface {
		parsed, err := url.Parse(target)
		if err != nil || !strings.EqualFold(parsed.Scheme, "https") {
			return keep, nil
		}
	}

	var allows []CredentialAudienceAllow
	for i, candidate := range candidates {
		restAllowed := audienceSurfacePermitted(surface, candidate.authorizationOnly, candidate.carrierMask) &&
			len(candidate.hosts) > 0 && destination.MatchesDomainList(host, candidate.hosts)
		if !restAllowed && !gitTransportAllowed(candidate, host, target, surface) &&
			!releaseGrantSASCandidateAllowed(candidate, host, target, surface) &&
			!registryBasicAllowed(candidate, host, target, surface) &&
			!registryBearerAllowed(candidate, host, target, surface) {
			continue
		}
		keep[i] = false
		recordSurface := surface
		switch surface {
		case CredentialAudienceAuthorizationHeaderSurface, credentialAudienceAuthorizationTokenSurface, credentialAudienceAuthorizationBasicSurface, credentialAudiencePrivateTokenSurface, credentialAudienceJobTokenSurface:
			recordSurface = "header"
		case credentialAudienceURLQuerySurface:
			recordSurface = "url"
		}
		allows = append(allows, CredentialAudienceAllow{
			PatternName: candidate.patternName,
			Surface:     recordSurface,
			Destination: host,
		})
	}
	return keep, deduplicateCredentialAudienceAllows(allows)
}

// canonicalCredentialAudienceDestination reuses destination's normalized host
// and port validation. Credential audiences establish host ownership, so this
// intentionally ignores the validated port; it is not an exact-destination
// grant, which must continue to bind host and port. WebSocket frame DLP accepts
// ws/wss because the proxy's parsed upstream URL is its verified destination
// authority; raw MCP input has no such target and intentionally never calls
// this helper.
func canonicalCredentialAudienceDestination(target string) (string, bool) {
	parsed, err := url.Parse(target)
	if err != nil || parsed == nil || parsed.User != nil || parsed.Hostname() == "" {
		return "", false
	}

	scheme := strings.ToLower(parsed.Scheme)
	var defaultPort string
	switch scheme {
	case "https", "wss":
		defaultPort = "443"
	default:
		// Only an encrypted scheme may earn an audience allow. Host ownership
		// says who the destination is; it says nothing about who else can read
		// the credential in transit. Removing a DLP match for a cleartext
		// http:// or ws:// request would hand the credential to any observer
		// on the path, so cleartext keeps the match and blocks.
		return "", false
	}
	port := parsed.Port()
	if port == "" {
		port = defaultPort
	}
	value, err := destination.ParsePort(port)
	if err != nil {
		return "", false
	}
	dest, err := destination.New(destination.NetworkTCP, parsed.Hostname(), value)
	if err != nil {
		return "", false
	}
	return dest.Host, true
}

// gitTransportAllowed is the separate git-over-HTTPS audience rule. It is a
// second, narrower grant beside the REST host list, never an extra host in
// it: the credential must ride in Authorization Basic, over https (not wss,
// not cleartext), to a compiled or operator-declared git host, on a git
// transport path. Anything else keeps the match and blocks.
func gitTransportAllowed(candidate credentialAudienceCandidate, host, target, surface string) bool {
	if surface != credentialAudienceAuthorizationBasicSurface ||
		candidate.carrierMask&config.CredentialAudienceCarrierGitBasic == 0 ||
		len(candidate.gitHosts) == 0 || !destination.MatchesDomainList(host, candidate.gitHosts) {
		return false
	}
	parsed, err := url.Parse(target)
	if err != nil || !strings.EqualFold(parsed.Scheme, "https") {
		return false
	}
	return isGitTransportPath(parsed)
}

// githubRegistryPasswordPattern is the whole Basic password: a classic
// token, a server-to-server token, or a fine-grained PAT, and nothing else.
// The DLP patterns are case-insensitive, so a password that only matches
// after case folding stays blocked.
var githubRegistryPasswordPattern = regexp.MustCompile(`^(?:gh[pour]_[A-Za-z0-9_]{36,}|ghs_[A-Za-z0-9.\-_]{36,}|github_pat_[a-zA-Z0-9_]{36,})$`)

// githubRegistryUsernamePattern is an account-name shape. GitHub account
// names are alphanumeric plus dashes, and Enterprise Managed Users also
// carry an underscore before the enterprise shortcode. Dots, at-signs, and
// a token in the username are not that shape.
// https://docs.github.com/en/enterprise-cloud@latest/admin/managing-iam/iam-configuration-reference/username-considerations-for-external-authentication
var githubRegistryUsernamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,38}$`)

// registryBasicAllowed is the package-registry audience rule. The credential
// must be the Basic password, over https, at a compiled registry host. A
// missing header value fails closed: the surface alone does not prove the
// token is the password rather than the username.
func registryBasicAllowed(candidate credentialAudienceCandidate, host, target, surface string) bool {
	if surface != credentialAudienceAuthorizationBasicSurface ||
		candidate.carrierMask&config.CredentialAudienceCarrierRegistryBasic == 0 ||
		len(candidate.registryHosts) == 0 || !destination.MatchesDomainList(host, candidate.registryHosts) {
		return false
	}
	parsed, err := url.Parse(target)
	if err != nil || !strings.EqualFold(parsed.Scheme, "https") {
		return false
	}
	user, password, ok := basicUserPassword(candidate.headerValue)
	if !ok || !githubRegistryUsernamePattern.MatchString(user) || githubRegistryPasswordPattern.MatchString(user) {
		return false
	}
	return githubRegistryPasswordPattern.MatchString(password)
}

// basicUserPassword decodes an Authorization Basic value, or a bare base64
// field of one, into the user and password. The password is the text after
// the first colon. StdEncoding is what container and package clients send.
func basicUserPassword(value string) (string, string, bool) {
	fields := strings.Fields(value)
	var encoded string
	switch len(fields) {
	case 2:
		if !strings.EqualFold(fields[0], "Basic") {
			return "", "", false
		}
		encoded = fields[1]
	case 1:
		encoded = fields[0]
	default:
		return "", "", false
	}
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		raw, err = base64.RawStdEncoding.DecodeString(encoded)
		if err != nil {
			return "", "", false
		}
	}
	if bytes.ContainsAny(raw, "\r\n") {
		return "", "", false
	}
	user, password, ok := strings.Cut(string(raw), ":")
	if !ok || user == "" || password == "" {
		return "", "", false
	}
	return user, password, true
}

// registryBearerAllowed accepts the bearer a container registry issues for
// itself. The JWT audience must name this host. The signature is not
// checked: the allow only delivers the token back to that registry host.
func registryBearerAllowed(candidate credentialAudienceCandidate, host, target, surface string) bool {
	if surface != CredentialAudienceAuthorizationHeaderSurface ||
		candidate.carrierMask&config.CredentialAudienceCarrierRegistryBearer == 0 ||
		len(candidate.registryHosts) == 0 || !destination.MatchesDomainList(host, candidate.registryHosts) {
		return false
	}
	parsed, err := url.Parse(target)
	if err != nil || !strings.EqualFold(parsed.Scheme, "https") {
		return false
	}
	fields := strings.Fields(candidate.headerValue)
	if len(fields) != 2 || !strings.EqualFold(fields[0], "Bearer") {
		return false
	}
	return registryJWTAudienceMatches(fields[1], host)
}

// registryJWTAudienceMatches reports whether token is a registry JWT whose
// aud is host. aud may be a string or an array of strings, which is the
// registered JWT form. An access array is required so a token that only
// copies the audience claim is not treated as a registry grant.
func registryJWTAudienceMatches(token, host string) bool {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return false
	}
	var claims map[string]json.RawMessage
	if !decodeJWTSegment(parts[1], &claims) {
		return false
	}
	if !jwtAudienceNamesHost(claims["aud"], host) {
		return false
	}
	var access []json.RawMessage
	return jsonField(claims, "access", &access) && len(access) > 0
}

func jwtAudienceNamesHost(raw json.RawMessage, host string) bool {
	if len(raw) == 0 {
		return false
	}
	var one string
	if json.Unmarshal(raw, &one) == nil {
		return canonicalAudienceHost(one) == host
	}
	var many []string
	if json.Unmarshal(raw, &many) != nil || len(many) == 0 {
		return false
	}
	for _, aud := range many {
		if canonicalAudienceHost(aud) == host {
			return true
		}
	}
	return false
}

// Git transport endpoints, from the published protocol documents:
//   - gitprotocol-http(5), "Smart Clients": discovery is
//     GET $GIT_URL/info/refs?service=<service>, and the service calls are
//     POST $GIT_URL/git-upload-pack and POST $GIT_URL/git-receive-pack.
//     https://git-scm.com/docs/gitprotocol-http
//   - Git LFS batch and locking APIs: requests go to <git-url>/info/lfs/...
//     (objects/batch, locks, locks/verify, locks/:id/unlock).
//     https://github.com/git-lfs/git-lfs/blob/main/docs/api/batch.md
//     https://github.com/git-lfs/git-lfs/blob/main/docs/api/locking.md
//
// $GIT_URL may or may not end in ".git". The decision is made on the path the
// proxy forwards: any percent-encoding or a path that path.Clean would change
// ("..", ".", "//", trailing slash) is refused, so an encoded slash or a
// traversal segment cannot dress another endpoint up as a git path.
func isGitTransportPath(u *url.URL) bool {
	p := u.EscapedPath()
	if p == "" || strings.Contains(p, "%") || path.Clean(p) != p {
		return false
	}
	repo, suffix, ok := strings.Cut(p, "/info/lfs/")
	if ok {
		return repo != "" && suffix != ""
	}
	for _, service := range []string{"/git-upload-pack", "/git-receive-pack"} {
		if repo, ok := strings.CutSuffix(p, service); ok {
			return repo != ""
		}
	}
	repo, ok = strings.CutSuffix(p, "/info/refs")
	if !ok || repo == "" {
		return false
	}
	query, err := url.ParseQuery(u.RawQuery)
	if err != nil || len(query) != 1 {
		return false
	}
	services := query["service"]
	return len(services) == 1 && (services[0] == "git-upload-pack" || services[0] == "git-receive-pack")
}

// releaseGrantSASSignedParams are the Azure user-delegation SAS query
// parameters that participate in Azure's signed string-to-sign for a blob
// resource: the resource shape (sp permissions, sv API version, sr resource
// type, spr protocol), the validity window (se expiry), the delegation-key
// identity (skoid, sktid, skt, ske, sks, skv), and the signature itself
// (sig). GitHub's redirect also carries rscd/rsct and their
// response-content-disposition/response-content-type mirrors, but those are
// unsigned response-header overrides that Azure does not verify, so requiring
// them here would fail a legitimate download closed if GitHub's storage layer
// ever omits one. An ordinary account-key SAS never sets the sk* delegation
// fields, so it cannot satisfy this shape.
// Source: https://learn.microsoft.com/en-us/rest/api/storageservices/create-user-delegation-sas
var releaseGrantSASSignedParams = []string{"sp", "sv", "sr", "spr", "se", "skoid", "sktid", "skt", "ske", "sks", "skv", "sig"}

var releaseGrantSASSignedParamSet = func() map[string]bool {
	set := make(map[string]bool, len(releaseGrantSASSignedParams))
	for _, name := range releaseGrantSASSignedParams {
		set[name] = true
	}
	return set
}()

// releaseGrantSASShapeValid reports whether parsed's query carries every
// parameter of Azure's user-delegation SAS signature. A forged, truncated, or
// account-key SAS is missing at least one of these, so it fails closed here
// even when it sits beside a valid grant.
// releaseGrantSASFieldFormats pins each signed parameter of Azure's
// user-delegation SAS to its documented value format, as GitHub issues it:
// service and key versions are dates, expiry and key start/expiry are UTC
// timestamps, the key object and tenant IDs are GUIDs, the permission,
// resource, protocol and key-service fields are short fixed codes, and the
// signature is one base64 HMAC-SHA256. A field outside its format cannot
// carry other data under the release grant's DLP and entropy allowance.
var releaseGrantSASFieldFormats = map[string]*regexp.Regexp{
	"sp":    regexp.MustCompile(`^[a-z]{1,16}$`),
	"sv":    regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`),
	"sr":    regexp.MustCompile(`^[a-z]{1,2}$`),
	"spr":   regexp.MustCompile(`^https(,http)?$`),
	"se":    regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,7})?Z$`),
	"skoid": regexp.MustCompile(`^(?i:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$`),
	"sktid": regexp.MustCompile(`^(?i:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$`),
	"skt":   regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,7})?Z$`),
	"ske":   regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,7})?Z$`),
	"sks":   regexp.MustCompile(`^[a-z]$`),
	"skv":   regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`),
	"sig":   regexp.MustCompile(`^[A-Za-z0-9+/]{43}=$`),
}

// releaseGrantSASShapeValid reports whether the query carries every signed
// user-delegation SAS parameter exactly once, each in its documented format.
func releaseGrantSASShapeValid(parsed *url.URL) bool {
	query := parsed.Query()
	for _, name := range releaseGrantSASSignedParams {
		values := query[name]
		format := releaseGrantSASFieldFormats[name]
		if len(values) != 1 || format == nil || !format.MatchString(values[0]) {
			return false
		}
	}
	return true
}

// releaseGrantSASAllowed is the single predicate that grants an Azure SAS
// found in a GitHub release-asset redirect. filterCredentialAudience's DLP
// decision, the url_query surface decision (urlDLPAudienceSurface), and the
// query-entropy exemption (releaseGrantSASQueryValueAllowed) all answer
// through it, so none of them can independently decide a different release
// grant than the others. The SAS signature is never verified here -- it is an
// HMAC under an Azure key this proxy does not hold -- so trust rests
// entirely on the co-located JWT downloadGrantClaimsMatch already proved
// GitHub issued for this exact host, plus the query carrying GitHub's whole
// delegation-key SAS shape.
func releaseGrantSASAllowed(hosts []string, host, target string) bool {
	if len(hosts) == 0 || !destination.MatchesDomainList(host, hosts) {
		return false
	}
	parsed, err := url.Parse(target)
	if err != nil || !strings.EqualFold(parsed.Scheme, "https") {
		return false
	}
	return len(validatedQueryGrants(parsed)) > 0 && releaseGrantSASShapeValid(parsed)
}

// releaseGrantSASCandidateAllowed is releaseGrantSASAllowed gated to the
// url_query surface and the compiled ReleaseGrantSAS carrier, mirroring
// gitTransportAllowed's shape for its own separate grant.
func releaseGrantSASCandidateAllowed(candidate credentialAudienceCandidate, host, target, surface string) bool {
	if surface != credentialAudienceURLQuerySurface || candidate.carrierMask&config.CredentialAudienceCarrierReleaseGrantSAS == 0 {
		return false
	}
	return releaseGrantSASAllowed(candidate.hosts, host, target)
}

func (p *compiledPattern) credentialAudienceCarrierRestricted() bool {
	return p != nil && (p.credentialAudienceAuthorizationOnly || p.credentialAudienceCarrierMask != 0)
}

func (s *Scanner) credentialAudienceAllows(pattern *compiledPattern, target, surface string) (CredentialAudienceAllow, bool) {
	return s.credentialAudienceAllowsWithHeader(pattern, target, surface, "")
}

func (s *Scanner) credentialAudienceAllowsWithHeader(pattern *compiledPattern, target, surface, headerValue string) (CredentialAudienceAllow, bool) {
	if pattern == nil {
		return CredentialAudienceAllow{}, false
	}
	keep, allows := filterCredentialAudience([]credentialAudienceCandidate{{
		patternName:       pattern.name,
		hosts:             pattern.credentialAudienceHosts,
		authorizationOnly: pattern.credentialAudienceAuthorizationOnly,
		carrierMask:       pattern.credentialAudienceCarrierMask,
		gitHosts:          pattern.credentialAudienceGitHosts,
		registryHosts:     pattern.credentialAudienceRegistryHosts,
		headerValue:       headerValue,
	}}, target, surface)
	if len(keep) != 1 || keep[0] || len(allows) != 1 {
		return CredentialAudienceAllow{}, false
	}
	return allows[0], true
}

func (s *Scanner) credentialAudienceMismatch(pattern *compiledPattern, target, surface string) (CredentialAudienceMismatch, bool) {
	if pattern == nil || pattern.core || len(pattern.credentialAudienceHosts) == 0 {
		return CredentialAudienceMismatch{}, false
	}
	host, ok := canonicalCredentialAudienceDestination(target)
	if !ok || destination.MatchesDomainList(host, pattern.credentialAudienceHosts) {
		return CredentialAudienceMismatch{}, false
	}
	return CredentialAudienceMismatch{
		PatternName: pattern.name,
		Surface:     surface,
		Destination: host,
		Hosts:       append([]string(nil), pattern.credentialAudienceHosts...),
	}, true
}

// FilterTextDLPMatchesForDestination applies the compiled-only audience rule
// after raw text scanning. Callers must pass their proxy-owned upstream target;
// destination-free surfaces (notably MCP stdio and MCP HTTP/SSE input) must not
// call it and therefore remain fail-closed.
func (s *Scanner) FilterTextDLPMatchesForDestination(matches []TextDLPMatch, target, surface string) ([]TextDLPMatch, []CredentialAudienceAllow) {
	return s.filterTextDLPMatchesForDestination(matches, target, surface, "")
}

// FilterHeaderDLPMatches applies the audience rule to one header value.
// Registry Basic and registry bearer need that value; without it those
// carriers fail closed. Other carriers ignore it.
func (s *Scanner) FilterHeaderDLPMatches(matches []TextDLPMatch, target, headerName, value string) ([]TextDLPMatch, []CredentialAudienceAllow) {
	return s.filterTextDLPMatchesForDestination(matches, target, CredentialAudienceHeaderSurface(headerName, value), value)
}

func (s *Scanner) filterTextDLPMatchesForDestination(matches []TextDLPMatch, target, surface, headerValue string) ([]TextDLPMatch, []CredentialAudienceAllow) {
	if len(matches) == 0 {
		return matches, nil
	}
	candidates := make([]credentialAudienceCandidate, len(matches))
	for i, match := range matches {
		candidates[i].patternName = match.PatternName
		candidates[i].hosts = match.credentialAudienceHosts
		candidates[i].authorizationOnly = match.credentialAudienceAuthorizationOnly
		candidates[i].carrierMask = match.credentialAudienceCarrierMask
		candidates[i].gitHosts = match.credentialAudienceGitHosts
		candidates[i].registryHosts = match.credentialAudienceRegistryHosts
		candidates[i].headerValue = headerValue
	}
	keep, allows := filterCredentialAudience(candidates, target, surface)
	filtered := make([]TextDLPMatch, 0, len(matches))
	for i, match := range matches {
		if keep[i] {
			filtered = append(filtered, match)
		}
	}
	return filtered, allows
}

// ScrubAuthorizedCredentialFromJoinedHeaders removes only raw matches that
// already qualify for an Authorization-header audience allow. The proxy scans
// each original header value and also scans a joined copy for split secrets.
// Without this narrow scrub the joined copy redetects the same allowed token
// as an unowned header and blocks it. The scrubbed copy decides only the
// Authorization-only patterns; see MergeJoinedHeaderMatches.
func (s *Scanner) ScrubAuthorizedCredentialFromJoinedHeaders(headerName, value, target string) string {
	surface := CredentialAudienceHeaderSurface(headerName, value)
	if surface == "header" {
		return value
	}
	patterns := s.dlpPatterns
	if s.core != nil {
		patterns = append(append([]*compiledPattern{}, patterns...), s.core.dlpPatterns...)
	}
	for _, pattern := range patterns {
		if !pattern.credentialAudienceCarrierRestricted() {
			continue
		}
		if _, ok := s.credentialAudienceAllowsWithHeader(pattern, target, surface, value); !ok {
			continue
		}
		value = pattern.re.ReplaceAllString(value, authorizedCredentialPlaceholder)
	}
	return s.scrubAuthorizedEncodedFields(value, target, surface)
}

const authorizedCredentialPlaceholder = "[authorized-credential]"

// maxAuthorizedEncodedFields bounds the whitespace-separated fields rescanned
// in one carrier header value. Authorization, PRIVATE-TOKEN, and JOB-TOKEN
// carry a scheme plus one credential; the margin tolerates stray tokens.
const maxAuthorizedEncodedFields = 8

// scrubAuthorizedEncodedFields covers the decoded views the raw regex pass
// cannot see, such as HTTP Basic credentials: base64("oauth2:<token>"). A
// field is replaced only when every carrier-restricted match found in it is
// allowed on this surface at this destination, so the joined scan reaches the
// same decision the per-header scan reached for that occurrence. Unallowed and
// unrestricted matches are still reported by the per-header scan.
func (s *Scanner) scrubAuthorizedEncodedFields(value, target, surface string) string {
	fields := strings.Fields(value)
	if len(fields) > maxAuthorizedEncodedFields {
		// A carrier header holds a scheme and one credential. A value with
		// many more fields is not a credential the audience rule describes,
		// and rescanning each field would let a crafted header multiply scan
		// work. Leave it unscrubbed so the joined scan keeps every match.
		return value
	}
	for _, field := range fields {
		if field == authorizedCredentialPlaceholder {
			continue
		}
		result := s.ScanTextForDLPQuiet(context.Background(), field)
		var restricted []TextDLPMatch
		for _, match := range result.Matches {
			if match.credentialAudienceCarrierRestricted() {
				restricted = append(restricted, match)
			}
		}
		if len(restricted) == 0 {
			continue
		}
		kept, allows := s.filterTextDLPMatchesForDestination(restricted, target, surface, field)
		if len(kept) == 0 && len(allows) > 0 {
			value = strings.Replace(value, field, authorizedCredentialPlaceholder, 1)
		}
	}
	return value
}

// MergeJoinedHeaderMatches combines the joined-header scan of the original
// values with the scan of the copy scrubbed by
// ScrubAuthorizedCredentialFromJoinedHeaders. The greedy token match can
// swallow the first half of an unrelated secret whose second half sits in
// another header, so every other pattern is decided on the original text.
// Only Authorization-only patterns are taken from the scrubbed copy.
func MergeJoinedHeaderMatches(original, scrubbed []TextDLPMatch) []TextDLPMatch {
	merged := make([]TextDLPMatch, 0, len(original)+len(scrubbed))
	for _, match := range original {
		if !match.credentialAudienceCarrierRestricted() {
			merged = append(merged, match)
		}
	}
	for _, match := range scrubbed {
		if match.credentialAudienceCarrierRestricted() {
			merged = append(merged, match)
		}
	}
	return merged
}

func deduplicateCredentialAudienceAllows(allows []CredentialAudienceAllow) []CredentialAudienceAllow {
	if len(allows) < 2 {
		return allows
	}
	seen := make(map[string]struct{}, len(allows))
	unique := make([]CredentialAudienceAllow, 0, len(allows))
	for _, allow := range allows {
		key := allow.PatternName + "\x00" + allow.Surface + "\x00" + allow.Destination
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		unique = append(unique, allow)
	}
	return unique
}

// queryValueIsAudienceCredential reports whether a decoded query value is, in
// its entirety, one compiled provider credential whose audience accepts this
// destination on the URL surface. DLP already allows that delivery; without
// this, query entropy would block the same value for looking random. The
// match must span the whole value, so any extra bytes beside the credential
// keep the value under entropy scoring. Every other scanner still runs.
func (s *Scanner) queryValueIsAudienceCredential(target, value string) bool {
	if value == "" {
		return false
	}
	for _, p := range s.dlpPatterns {
		if len(p.credentialAudienceHosts) == 0 {
			continue
		}
		start, end, ok := p.matchSpanInView(value, value)
		if !ok || start != 0 || end != len(value) {
			continue
		}
		if _, allowed := s.credentialAudienceAllows(p, target, credentialAudienceURLQuerySurface); allowed {
			return true
		}
	}
	return false
}

// releaseGrantSASQueryValueAllowed exempts a release-grant SAS's own signed
// query parameters (see releaseGrantSASSignedParams) from query-entropy
// scoring once releaseGrantSASAllowed has already proved the whole query is
// GitHub's release grant. Without this, the high-entropy sig= value (or a
// delegation-key GUID) would still be blocked by entropy even after DLP has
// allowed it, which would make the fix inert for the operator.
func (s *Scanner) releaseGrantSASQueryValueAllowed(parsed *url.URL, key string) bool {
	// The name is matched exactly, as the shape check matches it, so a case
	// alias of a signed field cannot take an exemption meant for the field.
	if parsed == nil || !releaseGrantSASSignedParamSet[key] {
		return false
	}
	host, ok := canonicalCredentialAudienceDestination(parsed.String())
	if !ok {
		return false
	}
	patterns := s.dlpPatterns
	if s.core != nil {
		patterns = append(append([]*compiledPattern{}, patterns...), s.core.dlpPatterns...)
	}
	for _, p := range patterns {
		if p.credentialAudienceCarrierMask&config.CredentialAudienceCarrierReleaseGrantSAS == 0 {
			continue
		}
		if releaseGrantSASAllowed(p.credentialAudienceHosts, host, parsed.String()) {
			return true
		}
	}
	return false
}

// urlDLPAudienceSurfaceForTarget is urlDLPAudienceSurface for a target held as
// a string. An unparseable target keeps the bare "url" surface.
func (s *Scanner) urlDLPAudienceSurfaceForTarget(p *compiledPattern, target string, memo *queryLessDLPMemo) string {
	parsed, err := url.Parse(target)
	if err != nil {
		return "url"
	}
	return s.urlDLPAudienceSurface(p, parsed, memo)
}

// queryLessURLScansClean reports whether the URL without its query passes DLP,
// computing it at most once per memo.
func (s *Scanner) queryLessURLScansClean(parsed *url.URL, memo *queryLessDLPMemo) bool {
	if memo != nil && memo.done {
		return memo.clean
	}
	withoutQuery := *parsed
	withoutQuery.RawQuery = ""
	withoutQuery.ForceQuery = false
	result, _ := s.checkDLP(&withoutQuery)
	if memo != nil {
		memo.done, memo.clean = true, result.Allowed
	}
	return result.Allowed
}

// queryLessDLPMemo holds the query-less rescan result for one outer URL scan,
// so several URL-query audience matches in that scan share one rescan.
type queryLessDLPMemo struct {
	done  bool
	clean bool
}

// urlDLPAudienceSurface picks the decision surface for a URL DLP match. It is
// "url_query" only for a pattern with the URL-query carrier when the credential
// sits in the query and nowhere else in the URL: the query-less URL must scan
// clean, and the pattern must match a query-only view. Everything else,
// including a credential in the path, the host, a userinfo section or a
// fragment, and one split across the path and query, stays "url", which no
// query-carrier audience accepts. Any parse or scan uncertainty stays "url".
func (s *Scanner) urlDLPAudienceSurface(p *compiledPattern, parsed *url.URL, memo *queryLessDLPMemo) string {
	const bareURLSurface = "url"
	const queryCarrierMask = config.CredentialAudienceCarrierURLQuery | config.CredentialAudienceCarrierReleaseGrantSAS
	if p == nil || p.credentialAudienceCarrierMask&queryCarrierMask == 0 ||
		parsed == nil || parsed.RawQuery == "" {
		return bareURLSurface
	}
	// Only an audience host can ever earn url_query, so every other destination
	// skips the query-less rescan below.
	if _, allowed := s.credentialAudienceAllows(p, parsed.String(), credentialAudienceURLQuerySurface); !allowed {
		return bareURLSurface
	}
	if !s.queryLessURLScansClean(parsed, memo) {
		return bareURLSurface
	}
	// The views mirror every query view checkDLP scans, keys included, so a
	// token checkDLP can find is one this check also sees and validates.
	// Joined views concatenate several values, so a match there may run into
	// the next value's text. Every other view comes from one key or value, where
	// a match must be exactly a grant.
	joined := []string{IterativeDecode(parsed.RawQuery), orderedQueryConcat(parsed.RawQuery)}
	var views []string
	for key, values := range parsed.Query() {
		decodedKey := IterativeDecode(key)
		views = append(views, decodedKey, stripURLNoise(decodedKey))
		for _, d := range decodeEncodingsRecursive(decodedKey) {
			views = append(views, d.text)
		}
		for _, v := range values {
			decoded := IterativeDecode(v)
			views = append(views, decoded, stripURLNoise(decoded))
			for _, t := range queryValueDecodedTargets(decoded) {
				views = append(views, t.text)
			}
		}
	}
	// Every credential match in the query must be a download grant issued for
	// this host. One unrelated or undecodable token keeps the whole URL on the
	// bare surface, so a real grant cannot carry a second token past DLP.
	grants := validatedQueryGrants(parsed)
	// The Azure SAS is never itself a grant, so it cannot use the per-match
	// isGrant/startsWithGrant check below, which only makes sense for a
	// pattern whose match text IS the credential being validated (the JWT).
	// It is allowed instead by co-occurrence: a valid grant already proved
	// this exact URL is GitHub's redirect, and the query carries GitHub's
	// whole SAS shape. The match must still be found within the query itself
	// (not merely alongside a query that happens to look right) so a SAS
	// planted in the path or elsewhere cannot ride a genuine grant's query.
	if p.credentialAudienceCarrierMask&config.CredentialAudienceCarrierReleaseGrantSAS != 0 {
		if len(grants) == 0 || !releaseGrantSASShapeValid(parsed) {
			return bareURLSurface
		}
		matchInView := func(view string) bool {
			if view == "" {
				return false
			}
			cleaned := normalize.ForDLP(view)
			_, _, ok := p.matchSpanInView(cleaned, view)
			return ok
		}
		// A real Azure user-delegation SAS signature is standard base64 and
		// routinely contains '+' and '/', which GitHub percent-encodes as %2B
		// and %2F. IterativeDecode's repeated url.QueryUnescape passes decode a
		// percent-encoded '+' to a literal '+' on one round and then, because
		// QueryUnescape treats a literal '+' in ITS OWN input as a space, blank
		// that same '+' out on the next round -- so joined/views below can miss
		// a real signature even though checkDLP's own undecoded "url" view (and
		// this pattern's percent-encoded regex alternative) already found it.
		// The raw, single-pass-decoded, and iteratively-decoded forms are all
		// checked so this cannot disagree with what actually triggered the DLP
		// match.
		//
		// The allowance is bound to the query's one sig parameter. A SAS match
		// anywhere else in the query, in any view checkDLP scans, is a second
		// credential riding the genuine grant, so the URL stays on the bare
		// surface.
		sigSegment, sigCount := rawQueryParamSegment(parsed.RawQuery, "sig")
		if sigCount != 1 {
			return bareURLSurface
		}
		for _, view := range releaseGrantSASQueryViews(rawQueryWithoutParam(parsed.RawQuery, "sig")) {
			if matchInView(view) {
				return bareURLSurface
			}
		}
		sigViews := []string{sigSegment}
		if once, err := url.QueryUnescape(sigSegment); err == nil {
			sigViews = append(sigViews, once)
		}
		for _, view := range sigViews {
			if matchInView(view) {
				return credentialAudienceURLQuerySurface
			}
		}
		return bareURLSurface
	}
	found := false
	check := func(view string, prefixOK bool) bool {
		if view == "" {
			return true
		}
		cleaned := normalize.ForDLP(view)
		if _, _, ok := p.matchSpanInView(cleaned, view); !ok {
			return true
		}
		for _, loc := range p.re.FindAllStringIndex(cleaned, -1) {
			m := cleaned[loc[0]:loc[1]]
			if !isGrant(m, grants) && (!prefixOK || !startsWithGrant(m, grants)) {
				return false
			}
			found = true
		}
		return true
	}
	for _, view := range joined {
		if !check(view, true) {
			return bareURLSurface
		}
	}
	for _, view := range views {
		if !check(view, false) {
			return bareURLSurface
		}
	}
	if found {
		return credentialAudienceURLQuerySurface
	}
	return bareURLSurface
}

// candidateTokensAreGrants reports whether every match of p in text is a
// download grant for target's host. A target that does not parse, or text
// with no match, is false.
func candidateTokensAreGrants(p *compiledPattern, text, target string) bool {
	parsed, err := url.Parse(target)
	if err != nil {
		return false
	}
	grants := validatedQueryGrants(parsed)
	locs := p.re.FindAllStringIndex(text, -1)
	if len(locs) == 0 {
		return false
	}
	for _, loc := range locs {
		if !startsWithGrant(text[loc[0]:loc[1]], grants) {
			return false
		}
	}
	return true
}

// validatedQueryGrants returns the query values that are, whole and on their
// own, a download grant for the URL's host. GitHub sends the grant as one
// query value; a grant reassembled from several values is not one.
func validatedQueryGrants(parsed *url.URL) []string {
	host := canonicalAudienceHost(parsed.Hostname())
	var grants []string
	for _, values := range parsed.Query() {
		for _, v := range values {
			if downloadGrantClaimsMatch(v, host) {
				grants = append(grants, v)
			}
		}
	}
	return grants
}

func isGrant(match string, grants []string) bool {
	for _, g := range grants {
		if match == g {
			return true
		}
	}
	return false
}

// startsWithGrant reports whether a pattern match is a validated grant. A
// view that joins query values lets the match run into the next value's
// text; that tail is scanned on its own, so the match qualifies when it
// begins with the whole grant.
func startsWithGrant(match string, grants []string) bool {
	for _, g := range grants {
		if strings.HasPrefix(match, g) {
			return true
		}
	}
	return false
}

// canonicalAudienceHost lowercases a hostname and drops a trailing dot, the
// same spelling the audience host list uses.
func canonicalAudienceHost(host string) string {
	return strings.TrimSuffix(strings.ToLower(host), ".")
}

// downloadGrantClaimsMatch reports whether token is a JWT whose payload names
// GitHub as issuer and host as audience. Any decode or shape failure is false.
// The signature is not verified: GitHub signs the grant with HS256 under a key
// only GitHub holds, so no proxy can check it. The check binds the token to
// its stated purpose rather than authenticating it. A forged token that
// passes can only deliver its bytes to GitHub's own download storage, which
// the sender cannot read back; the destination check is what stops a leak.
func downloadGrantClaimsMatch(token, host string) bool {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return false
	}
	// Header: exactly the two fields GitHub sends.
	var header map[string]string
	if !decodeJWTSegment(parts[0], &header) || len(header) != 2 || header["typ"] != "JWT" || header["alg"] != "HS256" {
		return false
	}
	// Signature: an HS256 MAC is exactly 32 bytes, so it has no room to carry
	// anything else.
	if sig, err := base64.RawURLEncoding.DecodeString(parts[2]); err != nil || len(sig) != sha256.Size {
		return false
	}
	var claims map[string]json.RawMessage
	if !decodeJWTSegment(parts[1], &claims) {
		return false
	}
	for name := range claims {
		if !downloadGrantClaimNames[name] {
			return false
		}
	}
	var iss, aud, key, grantPath string
	var exp, nbf int64
	if !jsonField(claims, "iss", &iss) || iss != config.GitHubDownloadGrantIssuer ||
		!jsonField(claims, "aud", &aud) || canonicalAudienceHost(aud) != host ||
		!jsonField(claims, "exp", &exp) || !jsonField(claims, "nbf", &nbf) ||
		exp <= nbf || exp-nbf > downloadGrantMaxLifetimeSeconds {
		return false
	}
	// key and path are optional in shape but must be plain strings when set.
	if _, ok := claims["key"]; ok && !jsonField(claims, "key", &key) {
		return false
	}
	if _, ok := claims["path"]; ok && !jsonField(claims, "path", &grantPath) {
		return false
	}
	return true
}

// downloadGrantClaimNames is the complete claim set of GitHub's release
// download grant. A token carrying any other claim is not that grant.
var downloadGrantClaimNames = map[string]bool{"aud": true, "exp": true, "iss": true, "key": true, "nbf": true, "path": true}

// downloadGrantMaxLifetimeSeconds is a local safety cap on exp minus nbf.
// GitHub does not publish the grant lifetime. Measured grants were 300 or
// 1800 seconds (assets from 1 KB to 29 MB), so a five-minute cap refused
// some release archives while letting checksums through. Assets near
// GitHub's 2 GiB file limit have not been measured.
const downloadGrantMaxLifetimeSeconds = 1800

func decodeJWTSegment(segment string, v any) bool {
	raw, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil {
		return false
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	return dec.Decode(v) == nil && !dec.More()
}

func jsonField(claims map[string]json.RawMessage, name string, v any) bool {
	raw, ok := claims[name]
	return ok && json.Unmarshal(raw, v) == nil
}

// rawQueryParamSegment returns the raw "key=value" segment of the one query
// parameter whose unescaped key is name, and how many such parameters the raw
// query holds. Keys are compared after unescaping, so an encoded duplicate
// such as "si%67" counts as a second "sig".
func rawQueryParamSegment(rawQuery, name string) (string, int) {
	segment, count := "", 0
	for _, part := range strings.Split(rawQuery, "&") {
		key, _, _ := strings.Cut(part, "=")
		if unescaped, err := url.QueryUnescape(key); err == nil && unescaped == name {
			segment = part
			count++
		}
	}
	return segment, count
}

// rawQueryWithoutParam drops every segment whose unescaped key is name and
// keeps the rest of the raw query unchanged.
func rawQueryWithoutParam(rawQuery, name string) string {
	parts := strings.Split(rawQuery, "&")
	kept := parts[:0:0]
	for _, part := range parts {
		key, _, _ := strings.Cut(part, "=")
		if unescaped, err := url.QueryUnescape(key); err == nil && unescaped == name {
			continue
		}
		kept = append(kept, part)
	}
	return strings.Join(kept, "&")
}

// releaseGrantSASQueryViews mirrors the query views urlDLPAudienceSurface and
// checkDLP scan: the raw and decoded query, joined values, and every key and
// value with their nested decodings. It is used to prove that no SAS match
// exists outside the one sig parameter a release grant covers.
func releaseGrantSASQueryViews(rawQuery string) []string {
	views := []string{rawQuery, IterativeDecode(rawQuery), orderedQueryConcat(rawQuery)}
	if once, err := url.QueryUnescape(rawQuery); err == nil {
		views = append(views, once)
	}
	values, _ := url.ParseQuery(rawQuery)
	for key, vals := range values {
		decodedKey := IterativeDecode(key)
		views = append(views, decodedKey, stripURLNoise(decodedKey))
		for _, d := range decodeEncodingsRecursive(decodedKey) {
			views = append(views, d.text)
		}
		for _, v := range vals {
			decoded := IterativeDecode(v)
			views = append(views, decoded, stripURLNoise(decoded))
			for _, t := range queryValueDecodedTargets(decoded) {
				views = append(views, t.text)
			}
		}
	}
	return views
}
