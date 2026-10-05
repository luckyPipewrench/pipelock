// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// systemdBindRecursiveFlag is the recursive mount bit systemd stores on a
// bind entry when the unit asked for rbind. A plain norbind entry carries
// flags 0. systemctl show prints the dbus tuple, not the unit-file colon form.
const systemdBindRecursiveFlag = 16384

// parseSystemdBindShow normalizes one BindPaths or BindReadOnlyPaths value
// from systemctl show. It accepts colon triples (src:dest:norbind) and the
// dbus 4-tuple layout (source, destination, ignore-missing, flags). An
// unparseable value fails closed. An ignore-missing bind is refused because
// the managed profile never asks for one.
func parseSystemdBindShow(value string) ([]string, error) {
	if strings.TrimSpace(value) == "" {
		return nil, nil
	}
	tokens, err := splitSystemdShowTokens(value)
	if err != nil {
		return nil, err
	}
	colon := 0
	for _, token := range tokens {
		if strings.Contains(token, ":") {
			colon++
		}
	}
	var parsed []string
	switch {
	case colon == len(tokens):
		parsed = make([]string, 0, len(tokens))
		for _, token := range tokens {
			entry, entryErr := parseColonBind(token)
			if entryErr != nil {
				return nil, entryErr
			}
			parsed = append(parsed, entry)
		}
	case colon == 0:
		if len(tokens)%4 != 0 {
			return nil, errors.New("systemd bind list has an incomplete entry")
		}
		parsed = make([]string, 0, len(tokens)/4)
		for i := 0; i < len(tokens); i += 4 {
			entry, entryErr := parseTupleBind(tokens[i], tokens[i+1], tokens[i+2], tokens[i+3])
			if entryErr != nil {
				return nil, entryErr
			}
			parsed = append(parsed, entry)
		}
	default:
		return nil, errors.New("systemd bind list mixes colon and tuple entries")
	}
	sort.Strings(parsed)
	return parsed, nil
}

func sameBindList(got, want []string) bool {
	if len(got) == 0 && len(want) == 0 {
		return true
	}
	left := append([]string(nil), got...)
	right := append([]string(nil), want...)
	sort.Strings(left)
	sort.Strings(right)
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func parseColonBind(token string) (string, error) {
	parts := strings.Split(token, ":")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" {
		return "", fmt.Errorf("systemd bind entry %q is not src:dest:option", token)
	}
	opt, err := bindOption(parts[2])
	if err != nil {
		return "", err
	}
	return canonicalBind(parts[0], parts[1], opt), nil
}

func parseTupleBind(src, dest, ignore, flags string) (string, error) {
	if src == "" || dest == "" {
		return "", errors.New("systemd bind entry is missing a path")
	}
	switch strings.ToLower(ignore) {
	case "0", "no", "false":
	default:
		return "", fmt.Errorf("systemd bind %s ignores a missing path", src)
	}
	opt, err := bindOption(flags)
	if err != nil {
		return "", err
	}
	return canonicalBind(src, dest, opt), nil
}

func bindOption(raw string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "norbind", "0":
		return "norbind", nil
	case "rbind", strconv.Itoa(systemdBindRecursiveFlag):
		return "rbind", nil
	default:
		return "", fmt.Errorf("systemd bind option %q is not norbind or rbind", raw)
	}
}

func splitSystemdShowTokens(value string) ([]string, error) {
	var tokens []string
	var b strings.Builder
	inQuote := false
	escaped := false
	for _, r := range value {
		if escaped {
			b.WriteRune(r)
			escaped = false
			continue
		}
		if r == '\\' && inQuote {
			escaped = true
			continue
		}
		if r == '"' {
			inQuote = !inQuote
			continue
		}
		if !inQuote && (r == ' ' || r == '\t') {
			if b.Len() > 0 {
				tokens = append(tokens, b.String())
				b.Reset()
			}
			continue
		}
		b.WriteRune(r)
	}
	if inQuote || escaped {
		return nil, errors.New("systemd bind list has an unbalanced quote")
	}
	if b.Len() > 0 {
		tokens = append(tokens, b.String())
	}
	if len(tokens) == 0 {
		return nil, errors.New("systemd bind list is empty")
	}
	return tokens, nil
}
