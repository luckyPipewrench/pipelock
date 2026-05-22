// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package discover

import (
	"net/url"
	"sort"
	"strings"
)

const redactedValue = "[REDACTED]"

// secretMarker is the substring "secret"; matched against config keys to flag
// likely-credential fields for redaction.
const secretMarker = "secret"

// RedactReportForOutput returns a copy of a discovery report suitable for CLI
// output and evidence files. Discovery keeps raw values internally for local
// classification, but output must not print secret env values, bearer URLs, or
// connection-string passwords.
func RedactReportForOutput(r *Report) *Report {
	if r == nil {
		return nil
	}
	out := &Report{
		Clients: append([]ClientConfig(nil), r.Clients...),
		Summary: r.Summary,
	}
	if r.Servers != nil {
		out.Servers = make([]MCPServer, 0, len(r.Servers))
		for _, s := range r.Servers {
			out.Servers = append(out.Servers, RedactServerForOutput(s))
		}
	}
	return out
}

// RedactServerForOutput returns a copy of a discovered server with sensitive
// values replaced by stable placeholders while preserving enough shape for a
// human to identify and wrap the server.
func RedactServerForOutput(s MCPServer) MCPServer {
	s.Command = redactURLLike(s.Command)
	s.Args = redactArgs(s.Args)
	s.Env = redactEnv(s.Env)
	s.URL = redactURLLike(s.URL)
	return s
}

func redactEnv(env map[string]string) map[string]string {
	if len(env) == 0 {
		return nil
	}
	out := make(map[string]string, len(env))
	for k := range env {
		out[k] = redactedValue
	}
	return out
}

func redactArgs(args []string) []string {
	if args == nil {
		return nil
	}
	out := make([]string, len(args))
	redactNext := false
	for i, arg := range args {
		if redactNext {
			out[i] = redactedValue
			redactNext = false
			continue
		}
		var next bool
		out[i], next = redactArg(arg)
		redactNext = next
	}
	return out
}

func redactArg(arg string) (string, bool) {
	if arg == "" {
		return arg, false
	}
	if isSensitiveHeaderValue(arg) {
		return redactedValue, false
	}
	if key, value, ok := strings.Cut(arg, "="); ok && isSensitiveKey(key) {
		if value == "" {
			return key + "=", false
		}
		return key + "=" + redactedValue, false
	}
	if key, value, ok := strings.Cut(arg, "="); ok && strings.Contains(value, "://") {
		return key + "=" + redactURLLike(value), false
	}
	if isSensitiveKey(arg) {
		return arg, true
	}
	return redactURLLike(arg), false
}

func redactURLLike(raw string) string {
	if raw == "" || !strings.Contains(raw, "://") {
		return raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return raw
	}

	if u.User != nil {
		u.User = nil
	}

	if u.RawQuery != "" {
		q := u.Query()
		keys := make([]string, 0, len(q))
		for k := range q {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		redacted := url.Values{}
		for _, k := range keys {
			if len(q[k]) == 0 {
				redacted[k] = nil
				continue
			}
			values := make([]string, len(q[k]))
			for i := range values {
				values[i] = redactedValue
			}
			redacted[k] = values
		}
		u.RawQuery = redacted.Encode()
	}
	u.Fragment = ""
	return u.String()
}

func isSensitiveKey(key string) bool {
	k := strings.ToLower(strings.TrimSpace(key))
	k = strings.TrimLeft(k, "-")
	k = strings.NewReplacer("-", "_", ".", "_").Replace(k)
	for _, marker := range []string{
		"token",
		secretMarker,
		"password",
		"passwd",
		"api_key",
		"apikey",
		"credential",
		"private_key",
		"authorization",
		"auth_header",
		"header",
		"bearer",
	} {
		if strings.Contains(k, marker) {
			return true
		}
	}
	return false
}

func isSensitiveHeaderValue(value string) bool {
	v := strings.ToLower(value)
	return strings.Contains(v, "authorization:") ||
		strings.Contains(v, "bearer ") ||
		strings.Contains(v, "basic ")
}
