// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"errors"
	"fmt"
	"strings"
)

// hostPatternList names one host-pattern list on a Config together with the
// validator Validate already applies to that list.
//
// The check is a field, not a switch, because the directionality of a list
// decides its rule: a GRANT list gets the wildcard breadth test, a MATCH or
// DENY list deliberately does not, and a request_policy route gets shape only.
// Pairing each list with its own validator here keeps that mapping in one
// table instead of re-deciding it per call site.
type hostPatternList struct {
	field string
	hosts []string
	check func(hosts []string, label string) error
	// single marks a row whose field already names one host, so the reported
	// location must not gain a "[0]" the YAML has no counterpart for.
	single bool
}

// hostPatternLists returns every host-pattern list that can reach a Scanner,
// each paired with the validator Validate uses for it.
//
// Per-agent profiles are deliberately absent. A profile reaches a Scanner only
// through the enterprise merge, which REPLACES the top-level lists rather than
// merging them, so the merged Config handed to scanner.New carries them as
// api_allowlist and trusted_domains and the first two rows below check them at
// that boundary. Walking cfg.Agents here as well would refuse an inert profile
// on a build where agent profiles are not enabled, which removes working
// configuration without covering anything the merged walk misses.
func (c *Config) hostPatternLists() []hostPatternList {
	lists := []hostPatternList{
		{field: "api_allowlist", hosts: c.APIAllowlist, check: ValidateHostGrantList},
		{field: "trusted_domains", hosts: c.TrustedDomains, check: ValidateTrustedDomains},
		{field: "fetch_proxy.monitoring.blocklist", hosts: c.FetchProxy.Monitoring.Blocklist, check: ValidateHostMatchList},
		{
			field: "fetch_proxy.monitoring.subdomain_entropy_exclusions",
			hosts: c.FetchProxy.Monitoring.SubdomainEntropyExclusions,
			check: hostnamePatternListCheck,
		},
		{
			field: "fetch_proxy.monitoring.query_entropy_exclusions",
			hosts: c.FetchProxy.Monitoring.QueryEntropyExclusions,
			check: hostnamePatternListCheck,
		},
	}

	for i := range c.FetchProxy.Monitoring.PathEntropyExclusions {
		lists = append(lists, hostPatternList{
			field:  fmt.Sprintf("fetch_proxy.monitoring.path_entropy_exclusions[%d].host", i),
			hosts:  []string{c.FetchProxy.Monitoring.PathEntropyExclusions[i].Host},
			check:  hostnamePatternListCheck,
			single: true,
		})
	}

	// The parameter exclusions take an EXACT host, not a wildcard, so they get
	// their own normalizer rather than the wildcard-aware one above. Routing
	// them through the wildcard checker would accept "*.example.com" here, which
	// the runtime compares literally and would never match.
	for i := range c.FetchProxy.Monitoring.QueryEntropyParamExclusions {
		lists = append(lists, hostPatternList{
			field:  fmt.Sprintf("fetch_proxy.monitoring.query_entropy_param_exclusions[%d].host", i),
			hosts:  []string{c.FetchProxy.Monitoring.QueryEntropyParamExclusions[i].Host},
			check:  queryEntropyParamHostCheck,
			single: true,
		})
	}

	// Route hosts get SHAPE only. Breadth on a request_policy route is the
	// operator's policy rather than a mistake, and refusing a broad wildcard
	// here would remove the ability to express one. Validate makes the same
	// call at validate.go:2583.
	//
	// Both route-bearing shapes are walked. A batch route is a route: it
	// reaches the same matcher, and covering only rules would leave the newer
	// of the two shapes unguarded, which is the failure this whole walk exists
	// to prevent.
	for i := range c.RequestPolicy.Rules {
		lists = append(lists, hostPatternList{
			field: fmt.Sprintf("request_policy.rules[%q].route.hosts", c.RequestPolicy.Rules[i].Name),
			hosts: c.RequestPolicy.Rules[i].Route.Hosts,
			check: routeHostCheck,
		})
	}
	for i := range c.RequestPolicy.Batch {
		lists = append(lists, hostPatternList{
			field: fmt.Sprintf("request_policy.batch[%d].route.hosts", i),
			hosts: c.RequestPolicy.Batch[i].Route.Hosts,
			check: routeHostCheck,
		})
	}

	for i := range c.DLP.Patterns {
		p := &c.DLP.Patterns[i]
		if len(p.ExemptDomains) == 0 {
			continue
		}
		lists = append(lists, hostPatternList{
			field: fmt.Sprintf("dlp.patterns[%q].exempt_domains", p.Name),
			hosts: p.ExemptDomains,
			check: ValidateTrustedDomains,
		})
	}

	return lists
}

// hostnamePatternListCheck adapts validateHostnamePatternList, whose parameters
// are ordered label-first, to the shared check signature.
func hostnamePatternListCheck(hosts []string, label string) error {
	return validateHostnamePatternList(label, hosts)
}

func queryEntropyParamHostCheck(hosts []string, label string) error {
	for i, raw := range hosts {
		if _, err := normalizeQueryEntropyParamHost(raw); err != nil {
			return fmt.Errorf("%s[%d] %q: %w", label, i, raw, err)
		}
	}
	return nil
}

func routeHostCheck(hosts []string, label string) error {
	for i, raw := range hosts {
		if _, err := NormalizeAndCheckHostPattern(raw); err != nil {
			return fmt.Errorf("%s[%d] %q: %w", label, i, raw, err)
		}
	}
	return nil
}

// ValidateHostPatterns re-checks every host-pattern list on the Config against
// the same rules Validate applies to it.
//
// It exists because two boundaries take a *Config without being able to tell
// whether Validate ever ran on it: scanner.New, reached by the enterprise
// per-agent merge among others, and the reload activation seam, which the
// Conductor apply path enters directly rather than through the file reloader.
// Neither is a live operator bypass today, because every production caller
// still arrives by way of config.Load. This is the guard that keeps that true
// when a caller arrives that does not.
//
// It walks the whole set rather than filtering each list at its point of use.
// A per-list filter puts a copy of the same predicate at every site and leaves
// the next list uncovered the moment someone adds one; the path-entropy builder
// is exactly that shape and needed three separate repairs. One walk over one
// table means a new list is covered by adding a row.
//
// It REFUSES rather than dropping. Dropping an invalid entry changes what the
// scanner enforces while the operator still sees their configuration as
// accepted: an exemption silently disappears and scanning becomes stricter than
// the YAML says, or a blocklist entry disappears and it becomes looser. Either
// way the posture moves and nothing tells them.
//
// It does not mutate the Config. Two of the shared validators normalize their
// input in place, and this runs at a construction boundary where the Config may
// already be shared with a live runtime, so every list is copied first.
func (c *Config) ValidateHostPatterns() error {
	for _, list := range c.hostPatternLists() {
		for i, raw := range list.hosts {
			// One entry at a time, on a copy, so the offending value is known
			// exactly and an in-place normalizer cannot reach the caller's
			// slice.
			if err := list.check([]string{raw}, list.field); err != nil {
				where := list.field
				if !list.single {
					where = fmt.Sprintf("%s[%d]", list.field, i)
				}
				return fmt.Errorf("%s %q (normalizes to %q): %s",
					where, raw, NormalizeHostPattern(raw),
					hostPatternReason(list.field, err))
			}
		}
	}
	return nil
}

// hostPatternReason strips the field/index prefix the shared validators add, so
// the caller can print the field, the raw value and the normalized value once
// each instead of twice.
//
// The prefix is deterministic rather than guessed: every list above is checked
// one entry at a time under a label this package passed in, so a validator that
// formats its own prefix produces exactly "<label>[0]".
func hostPatternReason(label string, err error) string {
	if inner := errors.Unwrap(err); inner != nil {
		return inner.Error()
	}
	msg := strings.TrimPrefix(err.Error(), fmt.Sprintf("%s[0]", label))
	return strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(msg), ":"))
}
