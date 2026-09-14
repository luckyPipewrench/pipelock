// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

// Package sigv4scope validates the shared structural portion of AWS SigV4
// credential scopes.
package sigv4scope

import (
	"regexp"
	"strings"
)

const (
	terminator      = "aws4_request"
	maxComponentLen = 64
)

var componentRe = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)

// IsComponent reports whether value has the lowercase region/service shape
// accepted in a SigV4 credential scope. AWS documents SigV4 scope as
// YYYYMMDD/region/service/aws4_request and requires lowercase region and
// service codes: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv-create-signed-request.html.
// The inclusive 64-byte ceiling is Pipelock's existing scanner contract; it
// is intentionally not an AWS-published maximum.
func IsComponent(value string) bool {
	return len(value) <= maxComponentLen && componentRe.MatchString(value)
}

// IsScope reports whether scope is the SigV4 credential scope without the
// access-key ID: YYYYMMDD/region/service/aws4_request.
func IsScope(scope string) bool {
	parts := strings.Split(scope, "/")
	if len(parts) != 4 || parts[3] != terminator || len(parts[0]) != 8 {
		return false
	}
	for _, ch := range parts[0] {
		if ch < '0' || ch > '9' {
			return false
		}
	}
	return IsComponent(parts[1]) && IsComponent(parts[2])
}

// IsScopeTail reports whether value starts with a SigV4 credential scope
// tail. It accepts the literal and percent-encoded slash forms accepted by
// query strings, and requires that nothing continues or extends the scope
// after aws4_request, so it accepts exactly the scopes IsScope accepts.
func IsScopeTail(value string) bool {
	parts := make([]string, 0, 4)
	for range 3 {
		var ok bool
		value, ok = consumeSeparator(value)
		if !ok {
			return false
		}
		part, remainder := nextComponent(value)
		parts = append(parts, part)
		value = remainder
	}
	var ok bool
	value, ok = consumeSeparator(value)
	if !ok || !strings.HasPrefix(value, terminator) {
		return false
	}
	parts = append(parts, terminator)
	value = strings.TrimPrefix(value, terminator)
	return IsScope(strings.Join(parts, "/")) && terminatorEnds(value)
}

// terminatorEnds reports whether remainder, the text immediately after
// aws4_request, ends the credential value. The scanner validates a whole
// X-Amz-Credential value, so a scope with anything appended to its final
// segment is not a credential scope to it. The redactor sees the scope
// embedded in arbitrary text and has no value delimiter, so it refuses any
// byte that could continue the segment (a word byte or the hyphen a scope
// component allows) or start another one (a literal or percent-encoded
// slash, or a truncated percent escape). A real pre-signed URL ends the
// value with a query, quote, or whitespace byte, none of which are refused.
func terminatorEnds(remainder string) bool {
	if remainder == "" {
		return true
	}
	switch remainder[0] {
	case '-', '/', '%':
		return false
	}
	return !isWordByte(remainder[0])
}

func consumeSeparator(value string) (string, bool) {
	if strings.HasPrefix(value, "/") {
		return value[1:], true
	}
	if len(value) >= 3 && value[0] == '%' && value[1] == '2' && (value[2] == 'F' || value[2] == 'f') {
		return value[3:], true
	}
	return "", false
}

func nextComponent(value string) (string, string) {
	for index := 0; index < len(value); index++ {
		if value[index] == '/' || (value[index] == '%' && index+2 < len(value) && value[index+1] == '2' && (value[index+2] == 'F' || value[index+2] == 'f')) {
			return value[:index], value[index:]
		}
	}
	return value, ""
}

func isWordByte(value byte) bool {
	return value == '_' || (value >= 'a' && value <= 'z') || (value >= 'A' && value <= 'Z') || (value >= '0' && value <= '9')
}
