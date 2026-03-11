// Package plsentry provides Sentry error reporting with secret redaction.
// All error data is scrubbed through DLP patterns before leaving the process.
package plsentry

import (
	"regexp"
	"strings"

	"github.com/getsentry/sentry-go"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// safetyNetPatterns are always applied regardless of user config.
// They catch common secret formats as a defense-in-depth measure.
var safetyNetPatterns = []*regexp.Regexp{
	regexp.MustCompile(`Bearer\s+\S+`),
	regexp.MustCompile(`Authorization:\s*\S+`),
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
	patterns []*regexp.Regexp
	secrets  []string
}

// NewScrubber creates a scrubber from the given DLP patterns and env secrets.
func NewScrubber(dlpPatterns []config.DLPPattern, envSecrets []string) *Scrubber {
	s := &Scrubber{
		secrets: envSecrets,
	}

	// Add config DLP patterns.
	for _, p := range dlpPatterns {
		re, err := regexp.Compile(p.Regex)
		if err != nil {
			continue // skip invalid patterns (already validated by config)
		}
		s.patterns = append(s.patterns, re)
	}

	// Add safety-net patterns.
	s.patterns = append(s.patterns, safetyNetPatterns...)

	return s
}

// ScrubString redacts all known secrets from the input string.
func (s *Scrubber) ScrubString(input string) string {
	if input == "" {
		return input
	}

	result := input

	// Apply DLP regex patterns.
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
		if event.Exception[i].Stacktrace != nil {
			for j := range event.Exception[i].Stacktrace.Frames {
				for k, v := range event.Exception[i].Stacktrace.Frames[j].Vars {
					if sv, ok := v.(string); ok {
						event.Exception[i].Stacktrace.Frames[j].Vars[k] = s.ScrubString(sv)
					} else {
						// Fail-closed: delete non-string vars rather than
						// risk leaking secrets in serialized form.
						delete(event.Exception[i].Stacktrace.Frames[j].Vars, k)
					}
				}
			}
		}
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

	// Scrub contexts — auto-populated with device/os/runtime info (benign)
	// but custom contexts could contain secrets in string values.
	for ctxName, ctx := range event.Contexts {
		for k, v := range ctx {
			if sv, ok := v.(string); ok {
				event.Contexts[ctxName][k] = s.ScrubString(sv)
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
