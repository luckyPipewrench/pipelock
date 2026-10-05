// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/jsonscan"
)

// systemdBindRecursiveFlag is the recursive mount bit systemd stores on a
// bind entry when the unit asked for rbind. A plain norbind entry carries
// flags 0. systemctl show prints the dbus tuple, not the unit-file colon form.
const systemdBindRecursiveFlag = 16384

// systemdBindEntry is one typed BindPaths or BindReadOnlyPaths tuple.
// systemd's D-Bus signature is a(ssbt): source, destination, ignore-missing,
// flags. The recursive mount bit is systemdBindRecursiveFlag.
type systemdBindEntry struct {
	Source        string
	Destination   string
	IgnoreMissing bool
	Flags         uint64
}

// errTypedBindsUnavailable means the typed D-Bus reader cannot be invoked.
// Callers may then read systemctl show, and that display text fails closed
// when it does not name norbind or rbind. A present reader that returns any
// other error is a failed observation, not permission to guess.
var errTypedBindsUnavailable = errors.New("typed systemd bind reader is unavailable")

// parseTypedSystemdBinds decodes one busctl --json=short get-property body
// for BindPaths or BindReadOnlyPaths. The signature must be a(ssbt).
// ignore-missing must be the JSON false; any other spelling is refused.
func parseTypedSystemdBinds(body []byte) ([]systemdBindEntry, error) {
	body = bytes.TrimSpace(body)
	if len(body) == 0 {
		return nil, errors.New("typed systemd bind list is empty")
	}
	if len(body) > maxCmdOutputBytes {
		return nil, errors.New("typed systemd bind list exceeds bound")
	}
	if err := jsonscan.RejectDuplicateKeys(body); err != nil {
		return nil, fmt.Errorf("invalid typed systemd bind JSON: %w", err)
	}
	if err := jsonscan.RejectCaseFoldedAliases(body, "type", "data"); err != nil {
		return nil, fmt.Errorf("invalid typed systemd bind fields: %w", err)
	}
	var payload struct {
		Type string              `json:"type"`
		Data [][]json.RawMessage `json:"data"`
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil {
		return nil, fmt.Errorf("decode typed systemd binds: %w", err)
	}
	if payload.Type != "a(ssbt)" {
		return nil, fmt.Errorf("typed systemd binds have signature %q", payload.Type)
	}
	out := make([]systemdBindEntry, 0, len(payload.Data))
	for _, row := range payload.Data {
		if len(row) != 4 {
			return nil, errors.New("typed systemd bind entry does not have four fields")
		}
		var entry systemdBindEntry
		if err := errors.Join(
			json.Unmarshal(row[0], &entry.Source),
			json.Unmarshal(row[1], &entry.Destination),
			json.Unmarshal(row[2], &entry.IgnoreMissing),
			json.Unmarshal(row[3], &entry.Flags),
		); err != nil {
			return nil, fmt.Errorf("decode typed systemd bind entry: %w", err)
		}
		if string(bytes.TrimSpace(row[2])) != "false" || entry.IgnoreMissing {
			return nil, fmt.Errorf("systemd bind %s ignores a missing path", entry.Source)
		}
		if entry.Source == "" || entry.Destination == "" {
			return nil, errors.New("typed systemd bind entry is missing a path")
		}
		if entry.Flags&^uint64(systemdBindRecursiveFlag) != 0 {
			return nil, fmt.Errorf("systemd bind %s has unexpected flags %d", entry.Source, entry.Flags)
		}
		out = append(out, entry)
	}
	return out, nil
}

// matchTypedBindEntries compares a typed observation with the canonical
// src:dest:option list the launch recorded. norbind requires the recursive
// flag to be absent. rbind, including the display-socket entry the launch
// asked for, requires that flag. ignore-missing is never accepted.
func matchTypedBindEntries(got []systemdBindEntry, want []string) error {
	if len(got) != len(want) {
		return errors.New("differ from managed launch")
	}
	used := make([]bool, len(got))
	for _, recorded := range want {
		src, dest, opt, err := splitCanonicalBind(recorded)
		if err != nil {
			return err
		}
		matched := false
		for i, entry := range got {
			if used[i] || entry.Source != src || entry.Destination != dest {
				continue
			}
			recursive := entry.Flags&uint64(systemdBindRecursiveFlag) != 0
			switch opt {
			case "norbind":
				if recursive {
					return fmt.Errorf("systemd bind %s is recursive", src)
				}
			case "rbind":
				if !recursive {
					return fmt.Errorf("systemd bind %s is not recursive", src)
				}
			default:
				return fmt.Errorf("recorded bind option %q is not norbind or rbind", opt)
			}
			used[i] = true
			matched = true
			break
		}
		if !matched {
			return errors.New("differ from managed launch")
		}
	}
	return nil
}

func splitCanonicalBind(value string) (string, string, string, error) {
	src, rest, ok := strings.Cut(value, ":")
	if !ok {
		return "", "", "", fmt.Errorf("recorded bind %q is not src:dest:option", value)
	}
	dest, opt, ok := strings.Cut(rest, ":")
	if !ok || src == "" || dest == "" || strings.Contains(dest, ":") {
		return "", "", "", fmt.Errorf("recorded bind %q is not src:dest:option", value)
	}
	return src, dest, opt, nil
}

// parseSystemdBindShow normalizes one BindPaths or BindReadOnlyPaths value
// from systemctl show. It is the fallback when the typed D-Bus reader is
// unavailable. A value that does not name norbind or rbind fails closed:
// systemd 261 prints a norbind entry as src:dest and drops the option, so
// the display text must not be treated as norbind. An ignore-missing bind
// is refused because the managed profile never asks for one.
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
		if entry, ok := parseSpacedColonBind(value); ok {
			return []string{entry}, nil
		}
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

// parseSpacedColonBind accepts one unquoted colon triple whose paths contain
// spaces, which splitSystemdShowTokens would otherwise break apart. Quoted
// sides never reach this. systemctl show's exact spelling for a spaced path
// was not captured here, so both this form and the quoted form are accepted.
func parseSpacedColonBind(value string) (string, bool) {
	value = strings.TrimSpace(value)
	opt := ""
	for _, candidate := range []string{"norbind", "rbind"} {
		suffix := ":" + candidate
		if strings.HasSuffix(value, suffix) {
			opt = candidate
			value = strings.TrimSuffix(value, suffix)
			break
		}
	}
	if opt == "" || strings.Contains(value, `"`) {
		return "", false
	}
	src, dest, ok := splitAbsoluteColon(value)
	if !ok {
		return "", false
	}
	return canonicalBind(src, dest, opt), true
}

func splitAbsoluteColon(value string) (string, string, bool) {
	for i := 1; i < len(value)-1; i++ {
		if value[i] != ':' || value[i+1] != '/' {
			continue
		}
		src, dest := value[:i], value[i+1:]
		if strings.HasPrefix(src, "/") && !strings.Contains(src, ":") && !strings.Contains(dest, ":") {
			return src, dest, true
		}
	}
	return "", "", false
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

func unquoteSystemdPath(value string) string {
	if len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"' {
		inner := value[1 : len(value)-1]
		inner = strings.ReplaceAll(inner, `\"`, `"`)
		inner = strings.ReplaceAll(inner, `\\`, `\`)
		return inner
	}
	return value
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
