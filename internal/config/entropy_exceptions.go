// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"time"
	"unicode"

	"gopkg.in/yaml.v3"
)

// MaxContentEntropyHostExclusionHorizon bounds an expiring host-wide content
// entropy exclusion. It matches the sibling warn-route horizon: a host-wide
// relaxation is broader than one route, so it never gets a longer window.
const MaxContentEntropyHostExclusionHorizon = 90 * 24 * time.Hour

// EntropyHostExclusion is one host pattern exempt from per-message content
// entropy. It reads from YAML in either of two shapes, mixed freely in one list.
// The bare string is the original form: no expiry, no metadata.
//
//	content_entropy_exclusions:
//	  - uploads.vendor.example
//
// The mapping form is the temporary exception, and expires is required:
//
//	content_entropy_exclusions:
//	  - host: challenge.vendor.example
//	    expires: 2026-12-31
//	    reason: bot challenge payloads are opaque
//	    owner: platform team
//
// reason and owner are optional, as they are on path_entropy_exclusions.
type EntropyHostExclusion struct {
	Host    string
	Expires string
	Reason  string
	Owner   string

	// mapped records that the entry was written as a mapping, so a mapping
	// without expires is reported by validation instead of silently becoming a
	// permanent exclusion.
	mapped bool
}

type entropyHostExclusionYAML struct {
	Host    string `yaml:"host" json:"host"`
	Expires string `yaml:"expires" json:"expires"`
	Reason  string `yaml:"reason,omitempty" json:"reason,omitempty"`
	Owner   string `yaml:"owner,omitempty" json:"owner,omitempty"`
}

// UnmarshalJSON accepts the same string and mapping forms as YAML, retaining
// mapping provenance so validation cannot turn a missing expiry into a
// permanent exclusion.
func (e *EntropyHostExclusion) UnmarshalJSON(data []byte) error {
	data = bytes.TrimSpace(data)
	if len(data) == 0 || (data[0] != '"' && data[0] != '{') {
		return fmt.Errorf("content_entropy_exclusions entry must be a host string or a {host, expires, reason, owner} mapping")
	}
	if data[0] == '"' {
		var host string
		if err := json.Unmarshal(data, &host); err != nil {
			return fmt.Errorf("content_entropy_exclusions entry: %w", err)
		}
		*e = EntropyHostExclusion{Host: host}
		return nil
	}
	var raw entropyHostExclusionYAML
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&raw); err != nil {
		return fmt.Errorf("content_entropy_exclusions entry: %w", err)
	}
	*e = EntropyHostExclusion{Host: raw.Host, Expires: raw.Expires, Reason: raw.Reason, Owner: raw.Owner, mapped: true}
	return nil
}

// UnmarshalYAML accepts the bare-string and mapping shapes. A scalar keeps the
// pre-existing []string decoding exactly, so configs written before the mapping
// form existed load unchanged.
func (e *EntropyHostExclusion) UnmarshalYAML(value *yaml.Node) error {
	switch value.Kind {
	case yaml.ScalarNode:
		*e = EntropyHostExclusion{Host: value.Value}
		return nil
	case yaml.MappingNode:
		for i := 0; i < len(value.Content); i += 2 {
			switch value.Content[i].Value {
			case "host", "expires", "reason", "owner":
			default:
				return fmt.Errorf("content_entropy_exclusions entry has unsupported field %q (allowed: host, expires, reason, owner)", value.Content[i].Value)
			}
		}
		var raw entropyHostExclusionYAML
		if err := value.Decode(&raw); err != nil {
			return fmt.Errorf("content_entropy_exclusions entry: %w", err)
		}
		*e = EntropyHostExclusion{Host: raw.Host, Expires: raw.Expires, Reason: raw.Reason, Owner: raw.Owner, mapped: true}
		return nil
	default:
		return fmt.Errorf("content_entropy_exclusions entry must be a host string or a {host, expires, reason, owner} mapping (got YAML kind %d)", value.Kind)
	}
}

// temporary reports whether the entry carries expiry metadata and so must obey
// the temporary-exception rules. A plain host string is the permanent form.
func (e EntropyHostExclusion) temporary() bool {
	return e.mapped || e.Expires != "" || e.Reason != "" || e.Owner != ""
}

// MarshalYAML writes a plain entry back as the bare string it was read from.
func (e EntropyHostExclusion) MarshalYAML() (any, error) {
	if !e.temporary() {
		return e.Host, nil
	}
	return entropyHostExclusionYAML{Host: e.Host, Expires: e.Expires, Reason: e.Reason, Owner: e.Owner}, nil
}

// MarshalJSON keeps the JSON form of a plain entry identical to the []string it
// replaced, which keeps the canonical policy hash of existing configs stable.
func (e EntropyHostExclusion) MarshalJSON() ([]byte, error) {
	if !e.temporary() {
		return json.Marshal(e.Host)
	}
	return json.Marshal(struct {
		Host    string `json:"host"`
		Expires string `json:"expires"`
		Reason  string `json:"reason,omitempty"`
		Owner   string `json:"owner,omitempty"`
	}{e.Host, e.Expires, e.Reason, e.Owner})
}

// EntropyHostExclusions builds plain (permanent) entries from host strings.
func EntropyHostExclusions(hosts ...string) []EntropyHostExclusion {
	if len(hosts) == 0 {
		return nil
	}
	out := make([]EntropyHostExclusion, len(hosts))
	for i, h := range hosts {
		out[i] = EntropyHostExclusion{Host: h}
	}
	return out
}

// ActiveEntropyExclusionHosts returns the host patterns still in force at now.
// A plain entry never expires. A temporary entry stops applying after its
// expires date (the date itself is still active), matching the warn routes, so
// a long-running process stops honoring it without a reload. A date that does
// not parse counts as expired: entropy enforcement is the safe direction.
func ActiveEntropyExclusionHosts(entries []EntropyHostExclusion, now time.Time) []string {
	if len(entries) == 0 {
		return nil
	}
	today := now.UTC().Format(time.DateOnly)
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.temporary() {
			if _, err := time.Parse(time.DateOnly, e.Expires); err != nil || e.Expires < today {
				continue
			}
		}
		out = append(out, e.Host)
	}
	return out
}

// validateEntropyHostExclusions applies the host-pattern rules every plain
// entry already had, then the temporary-exception rules to mapping entries.
func validateEntropyHostExclusions(field string, entries []EntropyHostExclusion) error {
	hosts := make([]string, len(entries))
	for i := range entries {
		hosts[i] = entries[i].Host
	}
	if err := validateHostnamePatternList(field, hosts); err != nil {
		return err
	}
	for i := range entries {
		entry := &entries[i]
		entry.Host = hosts[i]
		if !entry.temporary() {
			continue
		}
		label := fmt.Sprintf("%s[%d]", field, i)
		entry.Expires = strings.TrimSpace(entry.Expires)
		entry.Reason = strings.TrimSpace(entry.Reason)
		entry.Owner = strings.TrimSpace(entry.Owner)
		if entry.Expires == "" {
			return fmt.Errorf("%s.expires is required when an exclusion is written as a mapping", label)
		}
		if err := validateTemporaryExpiryDate(label+".expires", entry.Expires, MaxContentEntropyHostExclusionHorizon); err != nil {
			return err
		}
		for _, text := range []struct {
			name  string
			value string
			max   int
		}{{"reason", entry.Reason, 200}, {"owner", entry.Owner, 100}} {
			if len(text.value) > text.max {
				return fmt.Errorf("%s.%s must be %d characters or fewer", label, text.name, text.max)
			}
			if strings.IndexFunc(text.value, unicode.IsControl) >= 0 {
				return fmt.Errorf("%s.%s must not contain control characters", label, text.name)
			}
		}
	}
	return nil
}

// validateEntropyExclusionExpiry re-checks expiry only. Hot reload runs it
// without the full validator, as it does for the other temporary exceptions.
func validateEntropyExclusionExpiry(field string, entries []EntropyHostExclusion) error {
	for i, entry := range entries {
		if !entry.temporary() {
			continue
		}
		label := fmt.Sprintf("%s[%d].expires", field, i)
		if err := validateTemporaryExpiryDate(label, strings.TrimSpace(entry.Expires), MaxContentEntropyHostExclusionHorizon); err != nil {
			return err
		}
	}
	return nil
}

// RequestPathHasSegmentPrefix reports whether path falls under prefix on a path
// segment boundary. A prefix without a trailing slash matches itself and its
// children but not a sibling that merely shares leading characters
// (/cdn-cgi/challenge does not match /cdn-cgi/challengeX). A prefix with a
// trailing slash matches only paths below it.
func RequestPathHasSegmentPrefix(path, prefix string) bool {
	if prefix == "" {
		return false
	}
	base := strings.TrimSuffix(prefix, "/")
	if base == "" {
		return false
	}
	if path == base {
		return base == prefix
	}
	return strings.HasPrefix(path, base+"/")
}

// entropyPathPrefixBase strips the load-bearing trailing slash.
func entropyPathPrefixBase(prefix string) string { return strings.TrimSuffix(prefix, "/") }

// entropyRoutePathsOverlap reports whether two warn routes on one host can
// cover a common request path. Either side may be an exact path or a prefix.
func entropyRoutePathsOverlap(a, b RequestBodyEntropyWarnRoute) bool {
	switch {
	case a.PathPrefix == "" && b.PathPrefix == "":
		return a.Path == b.Path
	case a.PathPrefix != "" && b.PathPrefix == "":
		return RequestPathHasSegmentPrefix(b.Path, a.PathPrefix)
	case a.PathPrefix == "" && b.PathPrefix != "":
		return RequestPathHasSegmentPrefix(a.Path, b.PathPrefix)
	}
	ab, bb := entropyPathPrefixBase(a.PathPrefix), entropyPathPrefixBase(b.PathPrefix)
	return ab == bb || strings.HasPrefix(ab, bb+"/") || strings.HasPrefix(bb, ab+"/")
}
