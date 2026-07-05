// Package plsentry provides opt-in Sentry error reporting with event minimization.
// Events are structurally allowlisted and scrubbed before leaving the process.
package plsentry

import (
	"regexp"
	"runtime"
	"strings"

	"github.com/getsentry/sentry-go"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/redact"
)

// safetyNetPatterns are always applied regardless of user config.
// They catch common secret formats as a defense-in-depth measure.
var safetyNetPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)Bearer\s+\S+`),
	regexp.MustCompile(`(?i)Authorization:\s*\S+`),
	regexp.MustCompile(`(?:sk-ant-|sk-)[a-zA-Z0-9_-]{20,}`),
	regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
	regexp.MustCompile(`ghp_[a-zA-Z0-9]{36}`),
	regexp.MustCompile(`xox[bpsa]-[a-zA-Z0-9-]+`),
}

// redacted is the replacement string for scrubbed secrets.
const redacted = "[REDACTED]"

// urlParamValueRe matches query parameter values in URL-like strings.
var urlParamValueRe = regexp.MustCompile(`([?&][^=&]+)=([^&\s]+)`)

// secretAssignmentValueRe catches key/value payloads that can appear in
// basename-like frame strings without URL delimiters.
var secretAssignmentValueRe = regexp.MustCompile(`(?i)\b((?:[A-Za-z0-9_-]*-)?(?:api[_-]?key|token|secret|password|passwd|pwd|credential|session)[A-Za-z0-9_-]*=)[^\s"'<>/\\?&]+`)

// urlLikeRe matches URL-bearing text. Sentry crash payloads do not need hosts,
// userinfo, paths, or query values; keep only the coarse scheme.
var urlLikeRe = regexp.MustCompile(`\b([a-zA-Z][a-zA-Z0-9+.-]*)://[^\s"'<>]+`)

// protocolRelativeURLRe catches parse-error strings such as
// "//host/private/path" that do not have a scheme for urlLikeRe to anchor on.
var protocolRelativeURLRe = regexp.MustCompile(`(^|[^:])//[^\s"'<>]+`)

// Filesystem paths and bare network identifiers commonly appear in Go error
// strings. They are deployment/agent-local data, so surviving diagnostic
// strings keep only coarse redaction markers.
var (
	unixAbsPathRe      = regexp.MustCompile(`(^|[\s"'(=:])(/(?:[^/\s"'<>:]+/)+[^/\s"'<>:]*)`)
	windowsAbsPathRe   = regexp.MustCompile(`(?i)\b[A-Z]:\\[^\s"'<>]+`)
	uncPathRe          = regexp.MustCompile(`\\\\[^\s"'<>\\]+\\[^\s"'<>]+`)
	userinfoEndpointRe = regexp.MustCompile(`[A-Za-z0-9._~-]+:[^\s"'<>/@]+@(?:[A-Za-z0-9.-]+|\[[0-9A-Fa-f:.]+\])(?::\d{1,5})?(?:/[^\s"'<>]*)?`)
	ipv4EndpointRe     = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?(?:/[^\s"'<>]*)?\b`)
	ipv6EndpointRe     = regexp.MustCompile(`\[[0-9A-Fa-f:.]+\](?::\d{1,5})?(?:/[^\s"'<>]*)?`)
	bareFQDNPathRe     = regexp.MustCompile(`(?i)\b(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}(?::\d{1,5})?/[^/\s"'<>][^\s"'<>]*`)
	fqdnEndpointRe     = regexp.MustCompile(`(?i)\b((?:lookup|host|server|upstream|endpoint|address|addr|for|not|on|to|from|tcp|udp|connect(?:ing)?(?:\s+to)?|dial(?:ing)?(?:\s+tcp|\s+udp)?)\s+)(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}(?::\d{1,5})?(?:/[^\s"'<>]*)?\b`)
)

// Scrubber redacts secrets from strings and Sentry events using
// DLP patterns from config plus hardcoded safety-net patterns.
type Scrubber struct {
	matcher  *redact.Matcher
	patterns []*regexp.Regexp
	secrets  []string
}

// NewScrubber creates a scrubber from the given DLP patterns and env secrets.
func NewScrubber(dlpPatterns []config.DLPPattern, envSecrets []string) *Scrubber {
	s := &Scrubber{
		matcher: redact.NewDefaultMatcher(),
		secrets: envSecrets,
	}
	for _, p := range dlpPatterns {
		pattern := p.Regex
		if !strings.HasPrefix(pattern, "(?i)") {
			pattern = "(?i)" + pattern
		}
		re, err := regexp.Compile(pattern)
		if err != nil {
			continue
		}
		s.patterns = append(s.patterns, re)
	}
	s.patterns = append(s.patterns, safetyNetPatterns...)

	return s
}

// ScrubString redacts all known secrets from the input string.
func (s *Scrubber) ScrubString(input string) string {
	if input == "" {
		return input
	}

	var matchFn func(string) []redact.Match
	if s.matcher != nil {
		matchFn = s.matcher.Scan
	}
	return s.applyRedactionPipeline(input, matchFn)
}

func scrubDeploymentLocators(input string) string {
	result := unixAbsPathRe.ReplaceAllString(input, "${1}"+redacted)
	result = windowsAbsPathRe.ReplaceAllString(result, redacted)
	result = uncPathRe.ReplaceAllString(result, redacted)
	result = userinfoEndpointRe.ReplaceAllString(result, redacted)
	result = ipv6EndpointRe.ReplaceAllString(result, redacted)
	result = ipv4EndpointRe.ReplaceAllString(result, redacted)
	result = bareFQDNPathRe.ReplaceAllString(result, redacted)
	result = fqdnEndpointRe.ReplaceAllString(result, "${1}"+redacted)
	return result
}

func replaceMatchedSpans(input string, matches []redact.Match, replacement func(redact.Match) string) string {
	if input == "" || len(matches) == 0 {
		return input
	}

	var b strings.Builder
	b.Grow(len(input) + len(matches)*len(redacted))

	cursor := 0
	for _, match := range matches {
		if match.Start < cursor || match.Start < 0 || match.End > len(input) || match.End <= match.Start {
			continue
		}
		b.WriteString(input[cursor:match.Start])
		b.WriteString(replacement(match))
		cursor = match.End
	}
	b.WriteString(input[cursor:])
	return b.String()
}

func (s *Scrubber) safeScrubString(input string) string {
	if s == nil {
		return ""
	}
	return s.ScrubString(input)
}

func (s *Scrubber) safeScrubCodeString(input string) string {
	if s == nil {
		return ""
	}
	return s.applyRedactionPipeline(input, s.sensitiveCodeMatches)
}

func (s *Scrubber) applyRedactionPipeline(input string, matchFn func(string) []redact.Match) string {
	result := input

	// Drop locators before generic matching so composite forms like
	// user:pass@host are removed as one unit instead of leaving the username
	// behind after email/FQDN matching.
	result = urlLikeRe.ReplaceAllString(result, "${1}://"+redacted)
	result = protocolRelativeURLRe.ReplaceAllString(result, "${1}//"+redacted)
	result = scrubDeploymentLocators(result)

	// Shared matcher surface: typed secret classes from internal/redact. The
	// caller chooses the full string scanner or the narrower code-identifier
	// scanner, but the rest of the redaction order stays shared.
	if matchFn != nil {
		result = replaceMatchedSpans(result, matchFn(result), func(redact.Match) string { return redacted })
	}

	// Safety-net patterns stay separate: they intentionally cover cases not
	// yet modelled in the redact class registry (Bearer headers, URL auth).
	for _, re := range s.patterns {
		result = re.ReplaceAllString(result, redacted)
	}

	// Redact known env secret values.
	for _, secret := range s.secrets {
		if secret != "" && strings.Contains(result, secret) {
			result = strings.ReplaceAll(result, secret, redacted)
		}
	}

	// Redact URL query parameter values and key/value-style secret payloads.
	result = urlParamValueRe.ReplaceAllString(result, "${1}="+redacted)
	result = secretAssignmentValueRe.ReplaceAllString(result, "${1}"+redacted)
	return result
}

func (s *Scrubber) sensitiveCodeMatches(input string) []redact.Match {
	if s.matcher == nil {
		return nil
	}
	matches := s.matcher.Scan(input)
	filtered := matches[:0]
	for _, match := range matches {
		switch match.Class {
		case redact.ClassIPv4, redact.ClassIPv6, redact.ClassCIDR, redact.ClassFQDN, redact.ClassEmail, redact.ClassMAC, redact.ClassADUser:
			continue
		default:
			filtered = append(filtered, match)
		}
	}
	return filtered
}

func (s *Scrubber) safeScrubFilename(input string) string {
	if s == nil {
		return ""
	}
	result := codePathLeaf(input)
	return s.safeScrubCodeString(result)
}

func (s *Scrubber) safeScrubCodePath(input string) string {
	if s == nil {
		return ""
	}
	return s.safeScrubCodeString(codePathLeaf(input))
}

func codePathLeaf(input string) string {
	result := input
	if idx := strings.LastIndexAny(result, `/\`); idx >= 0 && idx+1 < len(result) {
		result = result[idx+1:]
	}
	return result
}

// scrubStacktrace returns a minimized copy of a stacktrace. It keeps only
// package/function/file-basename/line and drops vars, abs_path, context lines,
// addresses, package images, and frame-local data.
func (s *Scrubber) scrubStacktrace(st *sentry.Stacktrace) *sentry.Stacktrace {
	if st == nil {
		return nil
	}

	frames := make([]sentry.Frame, 0, len(st.Frames))
	for i := range st.Frames {
		frame := st.Frames[i]
		safeFrame := sentry.Frame{
			Function: s.safeScrubCodePath(frame.Function),
			Module:   s.safeScrubCodePath(frame.Module),
			Filename: s.safeScrubFilename(frame.Filename),
			Lineno:   frame.Lineno,
		}
		frames = append(frames, safeFrame)
	}
	return &sentry.Stacktrace{Frames: frames}
}

// ScrubEvent returns a minimized allowlisted Sentry event before transmission.
// This is used as the BeforeSend hook in sentry.ClientOptions.
//
// Fail-closed: any sanitizer panic drops the event rather than risking a raw
// event. This is deliberately structural: request, user, server_name,
// breadcrumbs, tags, contexts, modules, debug meta, attachments, spans, logs,
// metrics, frame vars, abs_path, and source context lines are omitted by
// construction.
func (s *Scrubber) ScrubEvent(event *sentry.Event, _ *sentry.EventHint) (safe *sentry.Event) {
	defer func() {
		if recover() != nil {
			safe = nil
		}
	}()

	if event == nil {
		return nil
	}

	safe = &sentry.Event{
		EventID:   event.EventID,
		Timestamp: event.Timestamp,
		Level:     event.Level,
		Release:   s.safeScrubString(event.Release),
		Message:   s.safeScrubString(event.Message),
		Platform:  "go/" + runtime.GOOS + "/" + runtime.GOARCH,
	}

	if len(event.Exception) > 0 {
		safe.Exception = make([]sentry.Exception, 0, len(event.Exception))
		for i := range event.Exception {
			exception := event.Exception[i]
			safe.Exception = append(safe.Exception, sentry.Exception{
				Type:       s.safeScrubString(exception.Type),
				Value:      s.safeScrubString(exception.Value),
				Stacktrace: s.scrubStacktrace(exception.Stacktrace),
			})
		}
	}

	if len(safe.Exception) == 0 && safe.Message == "" {
		for i := range event.Threads {
			if event.Threads[i].Stacktrace == nil {
				continue
			}
			safe.Exception = append(safe.Exception, sentry.Exception{
				Type:       "thread",
				Value:      "stacktrace",
				Stacktrace: s.scrubStacktrace(event.Threads[i].Stacktrace),
			})
		}
	}

	safe.MakeSerializationSafe()
	return safe
}
