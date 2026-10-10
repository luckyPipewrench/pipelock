// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/mcp/localservice"
)

const (
	idTestExecSHA   = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	idTestFileSHA   = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	idTestCarrier   = "PIPELOCK_VSCODE_EXAMPLE_AUTHORIZATION"
	idTestNativeLib = "/opt/vendor/app/lib/native.so"
	idTestLoaderVar = "LD_PRELOAD"
)

func idTestUID(v uint32) *uint32 { return &v }

func TestIdentityTestLoaderVarIsDenyListed(t *testing.T) {
	for _, name := range localservice.ControlEnvironmentDenyList() {
		if name == idTestLoaderVar {
			return
		}
	}
	t.Fatalf("%s is not on the localservice deny list", idTestLoaderVar)
}

func validIdentity(name string) MCPIdentity {
	return MCPIdentity{
		Name: name,
		VerifiedLocalService: &MCPVerifiedLocalService{
			Scheme:           MCPIdentitySchemeHTTP,
			Host:             MCPIdentityHostIPv4Loopback,
			Path:             "/mcp",
			PrincipalUID:     idTestUID(1000),
			ExecutableSHA256: idTestExecSHA,
		},
	}
}

func TestValidateMCPIdentitiesAccepts(t *testing.T) {
	full := validIdentity("full")
	full.VerifiedLocalService.Path = "/v1/mcp%2Fx"
	full.VerifiedLocalService.MappedFiles = []MCPIdentityFilePin{
		{Path: idTestNativeLib, SHA256: idTestFileSHA},
		{Path: "/opt/vendor/app/lib/other.so", SHA256: idTestFileSHA},
	}
	full.VerifiedLocalService.ControlEnvironment = map[string]string{idTestLoaderVar: ""}
	full.VerifiedLocalService.SessionHeader = &MCPIdentitySessionHeader{Name: "Authorization", Scheme: "Bearer", Carrier: idTestCarrier}
	v6 := validIdentity("v6")
	v6.VerifiedLocalService.Host = MCPIdentityHostIPv6Loopback
	ws := validIdentity("sock")
	ws.VerifiedLocalService.Scheme = MCPIdentitySchemeWSS
	ws.VerifiedLocalService.Path = "/"
	zero := validIdentity("root-owned")
	zero.VerifiedLocalService.Path = "/root"
	zero.VerifiedLocalService.PrincipalUID = idTestUID(0)

	tests := []struct {
		name    string
		entries []MCPIdentity
	}{
		{"none", nil},
		{"minimal", []MCPIdentity{validIdentity("local-tools")}},
		{"full", []MCPIdentity{full}},
		{"loopback hosts are distinct", []MCPIdentity{validIdentity("v4"), v6}},
		{"ws without session header", []MCPIdentity{ws}},
		{"uid zero is explicit", []MCPIdentity{zero}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := validateMCPIdentities(tt.entries); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestValidateMCPIdentitiesRejects(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*[]MCPIdentity)
		want   string
	}{
		{"empty name", func(e *[]MCPIdentity) { (*e)[0].Name = "" }, "mcp_identities[0].name"},
		{"bad name character", func(e *[]MCPIdentity) { (*e)[0].Name = "bad name" }, "mcp_identities[0].name"},
		{"duplicate name", func(e *[]MCPIdentity) {
			second := validIdentity("local-tools")
			second.VerifiedLocalService.Path = "/other"
			*e = append(*e, second)
		}, "mcp_identities[1].name"},
		{"no matcher", func(e *[]MCPIdentity) { (*e)[0].VerifiedLocalService = nil }, "exactly one matcher"},
		{"scheme missing", func(e *[]MCPIdentity) { (*e)[0].VerifiedLocalService.Scheme = "" }, "verified_local_service.scheme is required"},
		{"scheme unknown", func(e *[]MCPIdentity) { (*e)[0].VerifiedLocalService.Scheme = "ftp" }, "verified_local_service.scheme"},
		{"host name", func(e *[]MCPIdentity) { (*e)[0].VerifiedLocalService.Host = "localhost" }, "verified_local_service.host"},
		{"host bracketed", func(e *[]MCPIdentity) { (*e)[0].VerifiedLocalService.Host = "[::1]" }, "verified_local_service.host"},
		{"host with port", func(e *[]MCPIdentity) { (*e)[0].VerifiedLocalService.Host = "127.0.0.1:8080" }, "verified_local_service.host"},
		{"host other loopback", func(e *[]MCPIdentity) { (*e)[0].VerifiedLocalService.Host = "127.0.0.2" }, "verified_local_service.host"},
		{"path empty", func(e *[]MCPIdentity) { (*e)[0].VerifiedLocalService.Path = "" }, "verified_local_service.path"},
		{"path relative", func(e *[]MCPIdentity) { (*e)[0].VerifiedLocalService.Path = "mcp" }, "verified_local_service.path"},
		{"path query", func(e *[]MCPIdentity) { (*e)[0].VerifiedLocalService.Path = "/mcp?x=1" }, "verified_local_service.path"},
		{"path fragment", func(e *[]MCPIdentity) { (*e)[0].VerifiedLocalService.Path = "/mcp#x" }, "verified_local_service.path"},
		{"path space", func(e *[]MCPIdentity) { (*e)[0].VerifiedLocalService.Path = "/m cp" }, "verified_local_service.path"},
		{"path non ascii", func(e *[]MCPIdentity) { (*e)[0].VerifiedLocalService.Path = "/mé" }, "verified_local_service.path"},
		{"path not canonical escape", func(e *[]MCPIdentity) { (*e)[0].VerifiedLocalService.Path = "/a\"b" }, "canonical escaped form"},
		{"path bad escape", func(e *[]MCPIdentity) { (*e)[0].VerifiedLocalService.Path = "/%zz" }, "verified_local_service.path"},
		{"path decodes to control", func(e *[]MCPIdentity) { (*e)[0].VerifiedLocalService.Path = "/a%01b" }, "verified_local_service.path"},
		{"principal uid omitted", func(e *[]MCPIdentity) { (*e)[0].VerifiedLocalService.PrincipalUID = nil }, "principal_uid is required"},
		{"executable empty", func(e *[]MCPIdentity) { (*e)[0].VerifiedLocalService.ExecutableSHA256 = "" }, "executable_sha256"},
		{"executable short", func(e *[]MCPIdentity) { (*e)[0].VerifiedLocalService.ExecutableSHA256 = "abc" }, "executable_sha256"},
		{"executable uppercase", func(e *[]MCPIdentity) {
			(*e)[0].VerifiedLocalService.ExecutableSHA256 = strings.ToUpper(idTestExecSHA)
		}, "executable_sha256"},
		{"mapped file relative", func(e *[]MCPIdentity) {
			(*e)[0].VerifiedLocalService.MappedFiles = []MCPIdentityFilePin{{Path: "lib/native.so", SHA256: idTestFileSHA}}
		}, "mapped_files[0].path"},
		{"mapped file unclean", func(e *[]MCPIdentity) {
			(*e)[0].VerifiedLocalService.MappedFiles = []MCPIdentityFilePin{{Path: "/opt/vendor/../app.so", SHA256: idTestFileSHA}}
		}, "mapped_files[0].path"},
		{"mapped file nul", func(e *[]MCPIdentity) {
			(*e)[0].VerifiedLocalService.MappedFiles = []MCPIdentityFilePin{{Path: "/opt/a\x00b", SHA256: idTestFileSHA}}
		}, "mapped_files[0].path"},
		{"mapped file duplicate", func(e *[]MCPIdentity) {
			(*e)[0].VerifiedLocalService.MappedFiles = []MCPIdentityFilePin{
				{Path: idTestNativeLib, SHA256: idTestFileSHA}, {Path: idTestNativeLib, SHA256: idTestFileSHA},
			}
		}, "mapped_files[1].path"},
		{"mapped file bad digest", func(e *[]MCPIdentity) {
			(*e)[0].VerifiedLocalService.MappedFiles = []MCPIdentityFilePin{{Path: idTestNativeLib, SHA256: "zz"}}
		}, "mapped_files[0].sha256"},
		{"control env not on deny list", func(e *[]MCPIdentity) {
			(*e)[0].VerifiedLocalService.ControlEnvironment = map[string]string{"HARMLESS_SETTING": "1"}
		}, "control_environment"},
		{"control env nul value", func(e *[]MCPIdentity) {
			(*e)[0].VerifiedLocalService.ControlEnvironment = map[string]string{idTestLoaderVar: "a\x00b"}
		}, "NUL"},
		{"session header name not canonical", func(e *[]MCPIdentity) {
			(*e)[0].VerifiedLocalService.SessionHeader = &MCPIdentitySessionHeader{Name: "authorization", Scheme: "Bearer", Carrier: idTestCarrier}
		}, "session_header.name"},
		{"session header name invalid", func(e *[]MCPIdentity) {
			(*e)[0].VerifiedLocalService.SessionHeader = &MCPIdentitySessionHeader{Name: "Bad Name", Scheme: "Bearer", Carrier: idTestCarrier}
		}, "session_header.name"},
		{"session header name empty", func(e *[]MCPIdentity) {
			(*e)[0].VerifiedLocalService.SessionHeader = &MCPIdentitySessionHeader{Scheme: "Bearer", Carrier: idTestCarrier}
		}, "session_header.name"},
		{"session header scheme basic", func(e *[]MCPIdentity) {
			(*e)[0].VerifiedLocalService.SessionHeader = &MCPIdentitySessionHeader{Name: "Authorization", Scheme: "Basic", Carrier: idTestCarrier}
		}, "session_header.scheme"},
		{"session header carrier outside namespace", func(e *[]MCPIdentity) {
			(*e)[0].VerifiedLocalService.SessionHeader = &MCPIdentitySessionHeader{Name: "Authorization", Scheme: "Bearer", Carrier: "HOME"}
		}, "namespace"},
		{"session header carrier invalid", func(e *[]MCPIdentity) {
			(*e)[0].VerifiedLocalService.SessionHeader = &MCPIdentitySessionHeader{Name: "Authorization", Scheme: "Bearer", Carrier: "bad-name"}
		}, "invalid carrier name"},
		{"session header with ws", func(e *[]MCPIdentity) {
			(*e)[0].VerifiedLocalService.Scheme = MCPIdentitySchemeWS
			(*e)[0].VerifiedLocalService.SessionHeader = &MCPIdentitySessionHeader{Name: "Authorization", Scheme: "Bearer", Carrier: idTestCarrier}
		}, "session_header is not supported with scheme ws"},
		{"session header with wss", func(e *[]MCPIdentity) {
			(*e)[0].VerifiedLocalService.Scheme = MCPIdentitySchemeWSS
			(*e)[0].VerifiedLocalService.SessionHeader = &MCPIdentitySessionHeader{Name: "Authorization", Scheme: "Bearer", Carrier: idTestCarrier}
		}, "session_header is not supported with scheme wss"},
		{"same matcher twice", func(e *[]MCPIdentity) { *e = append(*e, validIdentity("other")) }, "mcp_identities[1].verified_local_service matches the same scheme, host and path as mcp_identities[0]"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entries := []MCPIdentity{validIdentity("local-tools")}
			tt.mutate(&entries)
			err := validateMCPIdentities(entries)
			if err == nil {
				t.Fatal("expected an error")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error %q does not contain %q", err, tt.want)
			}
		})
	}
}

func TestMCPCarrierNameProblem(t *testing.T) {
	tests := []struct {
		carrier string
		want    string
	}{
		{idTestCarrier, ""},
		{"", "invalid carrier name"},
		{"1BAD", "invalid carrier name"},
		{"PIPELOCK_VSCODE_A-B", "invalid carrier name"},
		{"HOME", "namespace"},
	}
	for _, tt := range tests {
		t.Run(tt.carrier, func(t *testing.T) {
			got := MCPCarrierNameProblem(tt.carrier)
			if tt.want == "" && got != "" || !strings.Contains(got, tt.want) {
				t.Fatalf("MCPCarrierNameProblem(%q) = %q, want %q", tt.carrier, got, tt.want)
			}
		})
	}
}

func TestFindMCPIdentity(t *testing.T) {
	entries := []MCPIdentity{validIdentity("a"), validIdentity("b")}
	if _, i, ok := FindMCPIdentity(entries, "b"); !ok || i != 1 {
		t.Fatalf("got index %d found %v", i, ok)
	}
	if _, i, ok := FindMCPIdentity(entries, "c"); ok || i != -1 {
		t.Fatalf("got index %d found %v for a missing name", i, ok)
	}
}

const idTestYAMLHeader = "version: 1\nmcp_identities:\n"

func idTestYAML(body string) []byte { return []byte(idTestYAMLHeader + body) }

const idTestYAMLEntry = `  - name: local-tools
    verified_local_service:
      scheme: http
      host: 127.0.0.1
      path: /mcp
      principal_uid: 1000
      executable_sha256: ` + idTestExecSHA + "\n"

func TestLoadMCPIdentitiesYAML(t *testing.T) {
	t.Run("valid entry loads", func(t *testing.T) {
		cfg, err := LoadBytes(idTestYAML(idTestYAMLEntry))
		if err != nil {
			t.Fatal(err)
		}
		if len(cfg.MCPIdentities) != 1 || *cfg.MCPIdentities[0].VerifiedLocalService.PrincipalUID != 1000 {
			t.Fatalf("unexpected registry: %+v", cfg.MCPIdentities)
		}
	})
	t.Run("full entry loads", func(t *testing.T) {
		body := idTestYAMLEntry + `      mapped_files:
        - {path: ` + idTestNativeLib + `, sha256: ` + idTestFileSHA + `}
      control_environment: {` + idTestLoaderVar + `: ""}
      session_header: {name: Authorization, scheme: Bearer, carrier: ` + idTestCarrier + `}
`
		if _, err := LoadBytes(idTestYAML(body)); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("principal_uid explicit zero loads", func(t *testing.T) {
		body := strings.Replace(idTestYAMLEntry, "principal_uid: 1000", "principal_uid: 0", 1)
		cfg, err := LoadBytes(idTestYAML(body))
		if err != nil {
			t.Fatal(err)
		}
		if uid := cfg.MCPIdentities[0].VerifiedLocalService.PrincipalUID; uid == nil || *uid != 0 {
			t.Fatalf("explicit zero lost: %v", uid)
		}
	})
	rejects := []struct {
		name string
		body string
		want string
	}{
		{"principal_uid omitted", strings.Replace(idTestYAMLEntry, "      principal_uid: 1000\n", "", 1), "principal_uid is required"},
		{"principal_uid null", strings.Replace(idTestYAMLEntry, "principal_uid: 1000", "principal_uid: null", 1), "principal_uid is required"},
		{"principal_uid negative", strings.Replace(idTestYAMLEntry, "principal_uid: 1000", "principal_uid: -1", 1), "uint32"},
		{"unknown identity field", idTestYAMLEntry + "    surprise: true\n", "surprise"},
		{"unknown matcher field", idTestYAMLEntry + "      surprise: true\n", "surprise"},
		{"unknown session header field", idTestYAMLEntry + "      session_header: {name: Authorization, scheme: Bearer, carrier: " + idTestCarrier + ", value: x}\n", "value"},
		{"unknown mapped file field", idTestYAMLEntry + "      mapped_files:\n        - {path: " + idTestNativeLib + ", sha256: " + idTestFileSHA + ", mode: 755}\n", "mode"},
	}
	for _, tt := range rejects {
		t.Run(tt.name, func(t *testing.T) {
			_, err := LoadBytes(idTestYAML(tt.body))
			if err == nil {
				t.Fatal("expected an error")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error %q does not contain %q", err, tt.want)
			}
		})
	}
}

func idTestFullIdentity() MCPIdentity {
	e := validIdentity("local-tools")
	v := e.VerifiedLocalService
	v.MappedFiles = []MCPIdentityFilePin{
		{Path: idTestNativeLib, SHA256: idTestFileSHA},
		{Path: "/opt/vendor/app/lib/other.so", SHA256: idTestExecSHA},
	}
	v.ControlEnvironment = map[string]string{idTestLoaderVar: "x"}
	v.SessionHeader = &MCPIdentitySessionHeader{Name: "Authorization", Scheme: "Bearer", Carrier: idTestCarrier}
	return e
}

func TestMCPIdentityRevision(t *testing.T) {
	base := idTestFullIdentity()
	baseRev := base.Revision()
	if len(baseRev) != 64 || baseRev != base.Revision() {
		t.Fatalf("revision unstable or malformed: %q", baseRev)
	}

	reordered := idTestFullIdentity()
	reordered.VerifiedLocalService.MappedFiles[0], reordered.VerifiedLocalService.MappedFiles[1] =
		reordered.VerifiedLocalService.MappedFiles[1], reordered.VerifiedLocalService.MappedFiles[0]
	if reordered.Revision() != baseRev {
		t.Fatal("reordering mapped files changed the revision")
	}

	changes := []struct {
		name   string
		mutate func(*MCPIdentity)
	}{
		{"name", func(e *MCPIdentity) { e.Name = "renamed" }},
		{"scheme", func(e *MCPIdentity) { e.VerifiedLocalService.Scheme = MCPIdentitySchemeHTTPS }},
		{"host", func(e *MCPIdentity) { e.VerifiedLocalService.Host = MCPIdentityHostIPv6Loopback }},
		{"path", func(e *MCPIdentity) { e.VerifiedLocalService.Path = "/other" }},
		{"principal", func(e *MCPIdentity) { e.VerifiedLocalService.PrincipalUID = idTestUID(1001) }},
		{"principal absent", func(e *MCPIdentity) { e.VerifiedLocalService.PrincipalUID = nil }},
		{"executable", func(e *MCPIdentity) { e.VerifiedLocalService.ExecutableSHA256 = idTestFileSHA }},
		{"mapped file digest", func(e *MCPIdentity) { e.VerifiedLocalService.MappedFiles[0].SHA256 = idTestExecSHA }},
		{"mapped file removed", func(e *MCPIdentity) { e.VerifiedLocalService.MappedFiles = e.VerifiedLocalService.MappedFiles[:1] }},
		{"control env value", func(e *MCPIdentity) {
			for k := range e.VerifiedLocalService.ControlEnvironment {
				e.VerifiedLocalService.ControlEnvironment[k] = "y"
			}
		}},
		{"control env removed", func(e *MCPIdentity) { e.VerifiedLocalService.ControlEnvironment = nil }},
		{"session header removed", func(e *MCPIdentity) { e.VerifiedLocalService.SessionHeader = nil }},
		{"session header carrier", func(e *MCPIdentity) { e.VerifiedLocalService.SessionHeader.Carrier = "PIPELOCK_VSCODE_OTHER" }},
		{"matcher removed", func(e *MCPIdentity) { e.VerifiedLocalService = nil }},
	}
	seen := map[string]string{baseRev: "base"}
	for _, tt := range changes {
		t.Run(tt.name, func(t *testing.T) {
			e := idTestFullIdentity()
			tt.mutate(&e)
			rev := e.Revision()
			if prior, dup := seen[rev]; dup {
				t.Fatalf("revision equals the one for %q", prior)
			}
			seen[rev] = tt.name
		})
	}

	t.Run("length prefixed fields do not collide", func(t *testing.T) {
		a, b := validIdentity("ab"), validIdentity("a")
		a.VerifiedLocalService.Path, b.VerifiedLocalService.Path = "/c", "/bc"
		if a.Revision() == b.Revision() {
			t.Fatal("field boundaries are ambiguous")
		}
	})
}

func TestCanonicalPolicyHashMCPIdentities(t *testing.T) {
	hash := func(entries []MCPIdentity) string {
		cfg := Defaults()
		cfg.MCPIdentities = entries
		return cfg.computeCanonicalPolicyHash()
	}
	none := hash(nil)
	if hash([]MCPIdentity{}) != none {
		t.Fatal("an empty registry must hash like an absent one")
	}
	one := hash([]MCPIdentity{idTestFullIdentity()})
	if one == none {
		t.Fatal("registering an identity did not change the policy hash")
	}

	t.Run("stable under reordering", func(t *testing.T) {
		a := idTestFullIdentity()
		other := validIdentity("zeta")
		other.VerifiedLocalService.Path = "/zeta"
		b := idTestFullIdentity()
		b.VerifiedLocalService.MappedFiles[0], b.VerifiedLocalService.MappedFiles[1] =
			b.VerifiedLocalService.MappedFiles[1], b.VerifiedLocalService.MappedFiles[0]
		if hash([]MCPIdentity{a, other}) != hash([]MCPIdentity{other, b}) {
			t.Fatal("entry or mapped file order changed the hash")
		}
	})

	t.Run("hashing does not mutate the config", func(t *testing.T) {
		cfg := Defaults()
		first, second := validIdentity("zeta"), validIdentity("alpha")
		second.VerifiedLocalService.Path = "/alpha"
		cfg.MCPIdentities = []MCPIdentity{first, second}
		_ = cfg.computeCanonicalPolicyHash()
		if cfg.MCPIdentities[0].Name != "zeta" {
			t.Fatal("canonicalization reordered the live registry")
		}
	})

	changes := []struct {
		name   string
		mutate func(*MCPIdentity)
	}{
		{"matcher path", func(e *MCPIdentity) { e.VerifiedLocalService.Path = "/other" }},
		{"matcher host", func(e *MCPIdentity) { e.VerifiedLocalService.Host = MCPIdentityHostIPv6Loopback }},
		{"executable pin", func(e *MCPIdentity) { e.VerifiedLocalService.ExecutableSHA256 = idTestFileSHA }},
		{"mapped file pin", func(e *MCPIdentity) { e.VerifiedLocalService.MappedFiles[1].SHA256 = idTestFileSHA }},
		{"principal", func(e *MCPIdentity) { e.VerifiedLocalService.PrincipalUID = idTestUID(7) }},
		{"control environment", func(e *MCPIdentity) {
			for k := range e.VerifiedLocalService.ControlEnvironment {
				e.VerifiedLocalService.ControlEnvironment[k] = "changed"
			}
		}},
		{"session header carrier", func(e *MCPIdentity) { e.VerifiedLocalService.SessionHeader.Carrier = "PIPELOCK_VSCODE_OTHER" }},
	}
	for _, tt := range changes {
		t.Run("changes on "+tt.name, func(t *testing.T) {
			e := idTestFullIdentity()
			tt.mutate(&e)
			if hash([]MCPIdentity{e}) == one {
				t.Fatal("hash did not change")
			}
		})
	}
}

func TestConfigCloneDeepCopiesMCPIdentities(t *testing.T) {
	cfg := Defaults()
	cfg.MCPIdentities = []MCPIdentity{idTestFullIdentity()}
	clone := cfg.Clone()
	v := clone.MCPIdentities[0].VerifiedLocalService
	*v.PrincipalUID = 9
	v.MappedFiles[0].Path = "/changed"
	v.SessionHeader.Carrier = "PIPELOCK_VSCODE_CHANGED"
	for k := range v.ControlEnvironment {
		v.ControlEnvironment[k] = "changed"
	}
	want := idTestFullIdentity().Revision()
	if got := cfg.MCPIdentities[0].Revision(); got != want {
		t.Fatal("mutating the clone changed the original registry")
	}
	if Defaults().Clone().MCPIdentities != nil {
		t.Fatal("an empty registry must clone to nil")
	}
}

func TestValidateReloadMCPIdentities(t *testing.T) {
	reload := func(old, updated []MCPIdentity) []ReloadWarning {
		o, u := Defaults(), Defaults()
		o.MCPIdentities, u.MCPIdentities = old, updated
		var out []ReloadWarning
		for _, w := range ValidateReload(o, u) {
			if w.Field == "mcp_identities" {
				out = append(out, w)
			}
		}
		return out
	}
	base := idTestFullIdentity()
	tests := []struct {
		name     string
		old, new []MCPIdentity
		mutate   func(*MCPIdentity)
		want     []string
		advisory bool
	}{
		{name: "unchanged", old: []MCPIdentity{base}, new: []MCPIdentity{base}},
		{name: "unchanged but reordered", old: []MCPIdentity{base}, mutate: func(e *MCPIdentity) {
			e.VerifiedLocalService.MappedFiles[0], e.VerifiedLocalService.MappedFiles[1] =
				e.VerifiedLocalService.MappedFiles[1], e.VerifiedLocalService.MappedFiles[0]
		}},
		{name: "both empty"},
		{name: "added", new: []MCPIdentity{base}, want: []string{"added"}},
		{name: "removed", old: []MCPIdentity{base}, want: []string{"removed"}, advisory: true},
		{name: "matcher path", old: []MCPIdentity{base}, mutate: func(e *MCPIdentity) { e.VerifiedLocalService.Path = "/other" }, want: []string{"matcher changed"}},
		{name: "matcher scheme", old: []MCPIdentity{base}, mutate: func(e *MCPIdentity) { e.VerifiedLocalService.Scheme = MCPIdentitySchemeHTTPS }, want: []string{"matcher changed"}},
		{name: "matcher host", old: []MCPIdentity{base}, mutate: func(e *MCPIdentity) { e.VerifiedLocalService.Host = MCPIdentityHostIPv6Loopback }, want: []string{"matcher changed"}},
		{name: "matcher kind", old: []MCPIdentity{base}, mutate: func(e *MCPIdentity) { e.VerifiedLocalService = nil }, want: []string{"matcher changed"}},
		{name: "executable", old: []MCPIdentity{base}, mutate: func(e *MCPIdentity) { e.VerifiedLocalService.ExecutableSHA256 = idTestFileSHA }, want: []string{"executable_sha256"}},
		{name: "mapped files", old: []MCPIdentity{base}, mutate: func(e *MCPIdentity) { e.VerifiedLocalService.MappedFiles = nil }, want: []string{"mapped_files"}},
		{name: "control environment", old: []MCPIdentity{base}, mutate: func(e *MCPIdentity) { e.VerifiedLocalService.ControlEnvironment = nil }, want: []string{"control_environment"}},
		{name: "principal", old: []MCPIdentity{base}, mutate: func(e *MCPIdentity) { e.VerifiedLocalService.PrincipalUID = idTestUID(5) }, want: []string{"principal_uid"}},
		{name: "session header added", old: []MCPIdentity{validIdentity("local-tools")}, mutate: func(e *MCPIdentity) {
			e.VerifiedLocalService.SessionHeader = &MCPIdentitySessionHeader{Name: "Authorization", Scheme: "Bearer", Carrier: idTestCarrier}
		}, want: []string{"session header scope added"}},
		{name: "session header changed", old: []MCPIdentity{base}, mutate: func(e *MCPIdentity) { e.VerifiedLocalService.SessionHeader.Name = "X-Session" }, want: []string{"session header scope changed"}},
		{name: "session header removed", old: []MCPIdentity{base}, mutate: func(e *MCPIdentity) { e.VerifiedLocalService.SessionHeader = nil }, want: []string{"session header scope removed"}},
		{name: "two classes at once", old: []MCPIdentity{base}, mutate: func(e *MCPIdentity) {
			e.VerifiedLocalService.ExecutableSHA256 = idTestFileSHA
			e.VerifiedLocalService.PrincipalUID = idTestUID(5)
		}, want: []string{"executable_sha256", "principal_uid"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			updated := tt.new
			if tt.mutate != nil {
				e := cloneMCPIdentities(tt.old)[0]
				tt.mutate(&e)
				updated = []MCPIdentity{e}
			}
			got := reload(tt.old, updated)
			if len(got) != len(tt.want) {
				t.Fatalf("got %d warnings %+v, want %d", len(got), got, len(tt.want))
			}
			for i, frag := range tt.want {
				if !strings.Contains(got[i].Message, frag) {
					t.Fatalf("warning %q does not contain %q", got[i].Message, frag)
				}
				if tt.advisory != (got[i].Disposition != ReloadWarning{}.Disposition) {
					t.Fatalf("warning %q advisory=%v, want %v", got[i].Message, !tt.advisory, tt.advisory)
				}
			}
		})
	}
}

func TestMCPAckBindingMode(t *testing.T) {
	tests := []struct {
		mode string
		want string
	}{
		{"", MCPAckBindingModeTransportV2},
		{MCPAckBindingModeTransportV2, MCPAckBindingModeTransportV2},
		{MCPAckBindingModeVerifiedLocalSession, MCPAckBindingModeVerifiedLocalSession},
	}
	for _, tt := range tests {
		t.Run(tt.mode, func(t *testing.T) {
			if got := MCPAckBindingMode(MCPAcknowledgedFinding{ServerBindingMode: tt.mode}); got != tt.want {
				t.Fatalf("got %q want %q", got, tt.want)
			}
		})
	}
}

func TestValidateMCPAckBindingMode(t *testing.T) {
	registry := []MCPIdentity{validIdentity("local-tools"), {Name: "bare"}}
	tests := []struct {
		name          string
		server, mode  string
		identities    []MCPIdentity
		checkRegistry bool
		want          string
	}{
		{"empty mode is transport-v2", "vault", "", nil, true, ""},
		{"transport-v2 explicit", "vault", MCPAckBindingModeTransportV2, registry, true, ""},
		{"verified session for registered identity", "local-tools", MCPAckBindingModeVerifiedLocalSession, registry, true, ""},
		{"verified session for unregistered name", "vault", MCPAckBindingModeVerifiedLocalSession, registry, true, "must name an mcp_identities entry"},
		{"verified session with no registry", "local-tools", MCPAckBindingModeVerifiedLocalSession, nil, true, "must name an mcp_identities entry"},
		{"verified session for entry without matcher", "bare", MCPAckBindingModeVerifiedLocalSession, registry, true, "must name an mcp_identities entry"},
		{"shape-only check skips the registry", "vault", MCPAckBindingModeVerifiedLocalSession, nil, false, ""},
		{"unknown mode", "vault", "transport-v3", registry, true, "not supported"},
		{"unknown mode, shape only", "vault", "transport-v3", nil, false, "not supported"},
		{"mode is case sensitive", "local-tools", "Verified-Local-Session", registry, true, "not supported"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := validAck()
			e.Server, e.ServerBindingMode = tt.server, tt.mode
			err := validateMCPAckList([]MCPAcknowledgedFinding{e}, tt.identities, tt.checkRegistry, ackTestNow)
			if tt.want == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error %v does not contain %q", err, tt.want)
			}
		})
	}
	t.Run("exported validator checks the value only", func(t *testing.T) {
		e := validAck()
		e.ServerBindingMode = MCPAckBindingModeVerifiedLocalSession
		if err := ValidateMCPAcknowledgedFinding(e, ackTestNow); err != nil {
			t.Fatal(err)
		}
		e.ServerBindingMode = "bogus"
		if err := ValidateMCPAcknowledgedFinding(e, ackTestNow); err == nil {
			t.Fatal("expected a refusal")
		}
	})
}
