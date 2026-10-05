// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package launchcontract defines the proxy and CA environment contract shared
// by command launchers. Profiles retain the existing containment contracts.
package launchcontract

import "strings"

// Profile selects an existing launcher's supported environment.
type Profile uint8

const (
	Contain Profile = 1 << iota
	Sandbox
	Exec
)

// Variable is an ordered environment assignment.
type Variable struct {
	Name  string
	Value string
}

type valueKind uint8

const (
	proxyValue valueKind = iota
	noProxyValue
	caValue
	additiveCAValue
	nodeProxyValue
)

// This is the only list of proxy/CA variable names. Contain deliberately omits
// new runtime CA overrides; sandbox deliberately retains its proxy-only subset.
var variables = []struct {
	name     string
	kind     valueKind
	profiles Profile
}{
	{"HTTP_PROXY", proxyValue, Contain | Sandbox | Exec},
	{"http_proxy", proxyValue, Contain | Sandbox | Exec},
	{"HTTPS_PROXY", proxyValue, Contain | Sandbox | Exec},
	{"https_proxy", proxyValue, Contain | Sandbox | Exec},
	{"ALL_PROXY", proxyValue, Contain | Exec},
	{"all_proxy", proxyValue, Contain | Exec},
	{"NO_PROXY", noProxyValue, Contain | Sandbox | Exec},
	{"no_proxy", noProxyValue, Contain | Sandbox | Exec},
	// npm and pnpm let a project config widen the bypass list unless the
	// environment sets this. Contain keeps its own npm policy.
	{"npm_config_noproxy", noProxyValue, Exec},
	{"SSL_CERT_FILE", caValue, Contain | Exec},
	{"REQUESTS_CA_BUNDLE", caValue, Contain | Exec},
	{"CURL_CA_BUNDLE", caValue, Contain | Exec},
	{"GIT_SSL_CAINFO", caValue, Contain | Exec},
	{"CARGO_HTTP_CAINFO", caValue, Contain | Exec},
	{"PIP_CERT", caValue, Contain | Exec},
	{"NODE_EXTRA_CA_CERTS", caValue, Contain | Exec},
	{"npm_config_cafile", caValue, Exec},
	// Codex adds this file to its existing roots and refuses to build its HTTP
	// client if any certificate in the file fails to load. A combined system
	// bundle is the wrong file: one unusable system certificate stops Codex.
	{"CODEX_CA_CERTIFICATE", additiveCAValue, Exec},
	{"DENO_CERT", caValue, Exec},
	{"NODE_USE_ENV_PROXY", nodeProxyValue, Contain | Exec},
}

// Vars returns a fresh list. Without a CA, certificate overrides are omitted.
// additiveCA is the Pipelock CA file for stores that add to existing roots.
// Containment and sandbox pass an empty additiveCA; they don't emit that variable.
func Vars(profile Profile, proxyURL, noProxy, caBundle, additiveCA string) []Variable {
	result := make([]Variable, 0, len(variables))
	for _, v := range variables {
		if v.profiles&profile == 0 || (profile == Exec && v.kind == caValue && caBundle == "") || (profile == Exec && v.kind == additiveCAValue && additiveCA == "") {
			continue
		}
		value := proxyURL
		switch v.kind {
		case noProxyValue:
			value = noProxy
		case caValue:
			value = caBundle
		case additiveCAValue:
			value = additiveCA
		case nodeProxyValue:
			value = "1"
		}
		result = append(result, Variable{v.name, value})
	}
	// Preserve sandbox's historical ordering as well as its values.
	if profile == Sandbox {
		result[1], result[2] = result[2], result[1]
	}
	return result
}

// Entries renders environment assignments without shell interpretation.
func Entries(vars []Variable) []string {
	result := make([]string, 0, len(vars))
	for _, v := range vars {
		result = append(result, v.Name+"="+v.Value)
	}
	return result
}

// Merge strips every inherited *_PROXY key (case-insensitive), and stale CA
// overrides, before appending the exact selected contract. Other settings,
// including credentials and NODE_OPTIONS, remain the caller's responsibility.
func Merge(inherited []string, vars []Variable) []string {
	result := make([]string, 0, len(inherited)+len(vars))
	for _, entry := range inherited {
		key, _, ok := strings.Cut(entry, "=")
		if !ok || strings.HasSuffix(strings.ToUpper(key), "_PROXY") || managedKey(key) {
			continue
		}
		result = append(result, entry)
	}
	return append(result, Entries(vars)...)
}

func managedKey(key string) bool {
	for _, v := range variables {
		if strings.EqualFold(v.name, key) {
			return true
		}
	}
	return false
}
