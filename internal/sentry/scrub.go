// Package plsentry provides Sentry error reporting with secret redaction.
// All error data is scrubbed through DLP patterns before leaving the process.
package plsentry

import (
	"regexp"
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

	result := input

	// Shared matcher surface: typed secret classes from internal/redact.
	if s.matcher != nil {
		result = replaceMatchedSpans(result, s.matcher.Scan(result), func(redact.Match) string { return redacted })
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

	// Redact URL query parameter values.
	result = urlParamValueRe.ReplaceAllString(result, "${1}="+redacted)

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

// scrubStacktrace redacts secrets in stacktrace frame variables.
// Shared by exception and thread scrubbing paths.
func (s *Scrubber) scrubStacktrace(st *sentry.Stacktrace) {
	if st == nil {
		return
	}
	for i := range st.Frames {
		for k, v := range st.Frames[i].Vars {
			if sv, ok := v.(string); ok {
				st.Frames[i].Vars[k] = s.ScrubString(sv)
			} else {
				// Fail-closed: delete non-string vars rather than
				// risk leaking secrets in serialized form.
				delete(st.Frames[i].Vars, k)
			}
		}
	}
}

// ScrubEvent scrubs all string fields in a Sentry event before transmission.
// This is used as the BeforeSend hook in sentry.ClientOptions.
//
// Fail-closed: non-string interface{} values in Extra, Breadcrumbs.Data,
// and Stacktrace.Vars are deleted rather than passed through unscrubbed.
func (s *Scrubber) ScrubEvent(event *sentry.Event, _ *sentry.EventHint) *sentry.Event {
	if event == nil {
		return nil
	}

	// Scrub message.
	event.Message = s.ScrubString(event.Message)

	// Scrub transaction name (can contain URL paths with tokens).
	event.Transaction = s.ScrubString(event.Transaction)

	// Scrub fingerprint strings.
	for i, fp := range event.Fingerprint {
		event.Fingerprint[i] = s.ScrubString(fp)
	}

	// Scrub exceptions — both Type and Value can contain secrets.
	for i := range event.Exception {
		event.Exception[i].Type = s.ScrubString(event.Exception[i].Type)
		event.Exception[i].Value = s.ScrubString(event.Exception[i].Value)
		s.scrubStacktrace(event.Exception[i].Stacktrace)
	}

	// Scrub threads — same Stacktrace structure as exceptions.
	for i := range event.Threads {
		s.scrubStacktrace(event.Threads[i].Stacktrace)
	}

	// Scrub breadcrumbs.
	for i := range event.Breadcrumbs {
		event.Breadcrumbs[i].Message = s.ScrubString(event.Breadcrumbs[i].Message)
		for k, v := range event.Breadcrumbs[i].Data {
			if sv, ok := v.(string); ok {
				event.Breadcrumbs[i].Data[k] = s.ScrubString(sv)
			} else {
				delete(event.Breadcrumbs[i].Data, k)
			}
		}
	}

	// Scrub tags.
	for k, v := range event.Tags {
		event.Tags[k] = s.ScrubString(v)
	}

	// Scrub extra values — fail-closed for non-strings.
	for k, v := range event.Extra {
		if sv, ok := v.(string); ok {
			event.Extra[k] = s.ScrubString(sv)
		} else {
			delete(event.Extra, k)
		}
	}

	// Scrub contexts — auto-populated with device/os/runtime info (ints,
	// bools for OS/device/runtime) but custom contexts could contain secrets.
	// Fail-closed: delete non-string values to prevent serialization leaks.
	for ctxName, ctx := range event.Contexts {
		for k, v := range ctx {
			if sv, ok := v.(string); ok {
				event.Contexts[ctxName][k] = s.ScrubString(sv)
			} else {
				delete(event.Contexts[ctxName], k)
			}
		}
	}

	// Wipe request entirely — URLs, headers, body all dangerous.
	event.Request = nil

	// Wipe user — IP could identify targets.
	event.User = sentry.User{}

	// Wipe server name — reveals internal infrastructure hostname.
	event.ServerName = ""

	return event
}
