// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package browserdefaults merges Pipelock's Chromium launch default into
// agent-browser's user config (~/.agent-browser/config.json) and removes it
// again. It is pure: callers own every file read and write, so the
// unprivileged Hermes path and the root-run containment path can each apply
// their own filesystem rules while sharing one definition of what the merge
// and the removal mean.
//
// agent-browser reads the user config at the lowest precedence (below a
// project agent-browser.json, AGENT_BROWSER_* environment variables, and CLI
// flags, each of which replaces rather than extends the value), so a default
// written here never overrides an agent's or project's own setting.
package browserdefaults

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Flag is the Chromium launch argument Pipelock adds. Under automation
// Chromium advertises an automation marker that managed bot challenges can
// loop on; this flag removes it.
const Flag = "--disable-blink-features=AutomationControlled"

// ErrMalformed reports a config that is not a JSON object.
var ErrMalformed = errors.New("browser defaults: malformed JSON")

// ErrArgsNotString reports an args value that is not a JSON string.
var ErrArgsNotString = errors.New("browser defaults: args must be a string")

// Record is the ownership record written when Pipelock adds Flag. It lets a
// later removal take out only Pipelock's copy and restore the prior value.
// The JSON field names are a stored format; existing records on disk use them.
type Record struct {
	// Created is true when the config file did not exist before install.
	Created bool
	// OriginalArgs is the args value before install ("" when absent).
	OriginalArgs string
	// HadArgs distinguishes an explicit "args": "" from no args key.
	HadArgs bool
	// Path optionally binds the record to the config it describes. The Hermes
	// path leaves it empty; containment sets it so a record cannot be applied
	// to a different file.
	Path string
}

type recordJSON struct {
	Created      json.RawMessage `json:"created"`
	OriginalArgs json.RawMessage `json:"original_args"`
	HadArgs      json.RawMessage `json:"had_args"`
	Path         json.RawMessage `json:"path,omitempty"`
}

// Marshal encodes the record in the stored format.
func (r Record) Marshal() []byte {
	m := map[string]interface{}{
		"created":       r.Created,
		"original_args": r.OriginalArgs,
		"had_args":      r.HadArgs,
	}
	if r.Path != "" {
		m["path"] = r.Path
	}
	data, _ := json.Marshal(m)
	return data
}

// DecodeRecord parses a stored record, refusing any missing or null
// required field. A malformed record must never read as "not created" or as
// an empty original value, because either would steer the removal.
func DecodeRecord(data []byte) (Record, error) {
	var raw recordJSON
	if err := json.Unmarshal(data, &raw); err != nil {
		return Record{}, fmt.Errorf("browser defaults: malformed ownership record: %w", err)
	}
	var r Record
	if err := DecodeStrict(raw.Created, &r.Created); err != nil {
		return Record{}, fmt.Errorf("browser defaults: malformed ownership record: created: %w", err)
	}
	if err := DecodeStrict(raw.OriginalArgs, &r.OriginalArgs); err != nil {
		return Record{}, fmt.Errorf("browser defaults: malformed ownership record: original_args: %w", err)
	}
	if err := DecodeStrict(raw.HadArgs, &r.HadArgs); err != nil {
		return Record{}, fmt.Errorf("browser defaults: malformed ownership record: had_args: %w", err)
	}
	if len(raw.Path) > 0 {
		if err := DecodeStrict(raw.Path, &r.Path); err != nil {
			return Record{}, fmt.Errorf("browser defaults: malformed ownership record: path: %w", err)
		}
	}
	return r, nil
}

// DecodeStrict decodes one field, refusing a missing value or a literal
// null. encoding/json leaves the destination at its zero value for null, which
// would silently turn "args": null into an empty string or a malformed
// ownership record into "not created".
func DecodeStrict(raw json.RawMessage, dst interface{}) error {
	if len(raw) == 0 || strings.TrimSpace(string(raw)) == "null" {
		return errors.New("value is missing or null")
	}
	return json.Unmarshal(raw, dst)
}

// Parse decodes a config file's contents. Empty or whitespace-only content is
// an empty object; anything that is not a JSON object is ErrMalformed.
func Parse(data []byte) (map[string]json.RawMessage, error) {
	if len(strings.TrimSpace(string(data))) == 0 {
		return map[string]json.RawMessage{}, nil
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(data, &obj); err != nil || obj == nil {
		return nil, ErrMalformed
	}
	return obj, nil
}

// Args returns the config's args string, "" when absent.
func Args(obj map[string]json.RawMessage) (string, error) {
	data, ok := obj["args"]
	if !ok {
		return "", nil
	}
	var value string
	if err := DecodeStrict(data, &value); err != nil {
		return "", ErrArgsNotString
	}
	return value, nil
}

// ArgParts splits agent-browser's args string on both documented separators
// (comma and newline), so detection and removal agree.
func ArgParts(args string) []string {
	return strings.FieldsFunc(args, func(r rune) bool { return r == ',' || r == '\n' })
}

// HasFlag reports whether args already carries Flag.
func HasFlag(args string) bool {
	for _, part := range ArgParts(args) {
		if strings.TrimSpace(part) == Flag {
			return true
		}
	}
	return false
}

// Encode renders a config object the way both callers write it.
func Encode(obj map[string]json.RawMessage) ([]byte, error) {
	data, err := json.MarshalIndent(obj, "", "  ")
	return append(data, '\n'), err
}

// Inspect parses a config and reports whether Flag is already present. It
// performs every validation Merge does without producing output, so a caller
// can refuse a bad file before changing anything else.
func Inspect(data []byte) (present bool, err error) {
	obj, err := Parse(data)
	if err != nil {
		return false, err
	}
	args, err := Args(obj)
	if err != nil {
		return false, err
	}
	return HasFlag(args), nil
}

// Merge appends Flag to the config's args, keeping every other key and
// argument. existed says whether the config file was present. When Flag is
// already there, already is true and nothing else is returned: the caller
// writes nothing and records no ownership, because Pipelock did not add it.
func Merge(data []byte, existed bool) (out []byte, rec Record, already bool, err error) {
	obj, err := Parse(data)
	if err != nil {
		return nil, Record{}, false, err
	}
	args, err := Args(obj)
	if err != nil {
		return nil, Record{}, false, err
	}
	if HasFlag(args) {
		return nil, Record{}, true, nil
	}
	_, hadArgs := obj["args"]
	rec = Record{Created: !existed, OriginalArgs: args, HadArgs: hadArgs}
	merged := Flag
	if args != "" {
		merged = args + "," + Flag
	}
	obj["args"], _ = json.Marshal(merged)
	out, err = Encode(obj)
	if err != nil {
		return nil, Record{}, false, err
	}
	return out, rec, false, nil
}

// Remove takes Pipelock's copy of Flag back out of a config described by rec.
// changed is false when the flag is no longer present (nothing to write).
// remove is true when Pipelock created the file and nothing else is left in
// it, so the caller should delete the file rather than write out.
func Remove(data []byte, rec Record) (out []byte, remove, changed bool, err error) {
	obj, err := Parse(data)
	if err != nil {
		return nil, false, false, err
	}
	args, err := Args(obj)
	if err != nil {
		return nil, false, false, err
	}
	if !HasFlag(args) {
		return nil, false, false, nil
	}
	// Install appends exactly one copy at the end, so remove only the last
	// copy; an identical flag the operator added stays.
	parts := ArgParts(args)
	last := -1
	for i, part := range parts {
		if strings.TrimSpace(part) == Flag {
			last = i
		}
	}
	kept := make([]string, 0, len(parts))
	for i, part := range parts {
		if i != last {
			kept = append(kept, part)
		}
	}
	remaining := strings.Join(kept, ",")
	if strings.Join(ArgParts(rec.OriginalArgs), ",") == remaining {
		// Nothing else changed since install: restore the operator's value
		// byte for byte, separators included.
		remaining = rec.OriginalArgs
	}
	keepExplicitEmpty := rec.HadArgs && rec.OriginalArgs == ""
	if remaining == "" && !keepExplicitEmpty {
		// Only Pipelock's flag is left. An operator who removed their own
		// arguments after install keeps that removal; an operator whose file
		// said "args": "" before install gets that back.
		delete(obj, "args")
	} else {
		obj["args"], _ = json.Marshal(remaining)
	}
	if rec.Created && len(obj) == 0 {
		// Pipelock created the file and nothing else lives in it.
		return nil, true, true, nil
	}
	out, err = Encode(obj)
	if err != nil {
		return nil, false, false, err
	}
	return out, false, true, nil
}
