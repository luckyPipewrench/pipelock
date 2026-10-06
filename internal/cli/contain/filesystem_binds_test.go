// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// systemd261BindFixture is captured output, not a reconstructed display grammar.
// See testdata/systemd261_binds.json for the systemd-run and busctl commands.
type systemd261BindFixture struct {
	Source string `json:"source"`
	Cases  []struct {
		Name     string          `json:"name"`
		Path     string          `json:"path"`
		Option   string          `json:"option"`
		Property string          `json:"property"`
		Show     string          `json:"show"`
		Typed    json.RawMessage `json:"typed"`
	} `json:"cases"`
}

func loadSystemd261Binds(t *testing.T) systemd261BindFixture {
	t.Helper()
	body, err := os.ReadFile(filepath.Join("testdata", "systemd261_binds.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture systemd261BindFixture
	if err := json.Unmarshal(body, &fixture); err != nil {
		t.Fatal(err)
	}
	if len(fixture.Cases) < 4 || !strings.Contains(fixture.Source, "systemd 261.2") || !strings.Contains(fixture.Source, "busctl") {
		t.Fatalf("capture fixture is incomplete: %s", fixture.Source)
	}
	return fixture
}

func TestTypedSystemdBindsMatchCapturedNorbind(t *testing.T) {
	fixture := loadSystemd261Binds(t)
	for _, tc := range fixture.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			got, err := parseTypedSystemdBinds(tc.Typed)
			if err != nil {
				t.Fatal(err)
			}
			want := []string{canonicalBind(tc.Path, tc.Path, tc.Option)}
			if err := matchTypedBindEntries(got, want); err != nil {
				t.Fatalf("typed binds = %#v: %v", got, err)
			}
			showValue := showProperty(t, tc.Show, tc.Property)
			if tc.Option == "norbind" {
				parsed, parseErr := parseSystemdBindShow(showValue)
				if parseErr == nil {
					t.Fatalf("display form %q was accepted as %v; norbind must not be assumed", showValue, parsed)
				}
			}
		})
	}
}

func TestTypedSystemdBindsRejectIgnoreMissingAndExtraFlags(t *testing.T) {
	if _, err := parseTypedSystemdBinds([]byte(`{"type":"a(ssbt)","data":[["/src","/src",true,0]]}`)); err == nil {
		t.Fatal("accepted ignore-missing")
	}
	if _, err := parseTypedSystemdBinds([]byte(`{"type":"a(ssbt)","data":[["/src","/src",false,1]]}`)); err == nil {
		t.Fatal("accepted an unknown flag bit")
	}
	if err := matchTypedBindEntries([]systemdBindEntry{{Source: "/src", Destination: "/src", Flags: systemdBindRecursiveFlag}}, []string{canonicalBind("/src", "/src", "norbind")}); err == nil {
		t.Fatal("norbind matched a recursive bind")
	}
	if err := matchTypedBindEntries([]systemdBindEntry{{Source: "/tmp/.X11-unix/X0", Destination: "/tmp/.X11-unix/X0", Flags: 0}}, []string{canonicalBind("/tmp/.X11-unix/X0", "/tmp/.X11-unix/X0", "rbind")}); err == nil {
		t.Fatal("display socket matched a non-recursive bind")
	}
}

func showProperty(t *testing.T, show, name string) string {
	t.Helper()
	for _, line := range strings.Split(show, "\n") {
		if strings.HasPrefix(line, name+"=") {
			return strings.TrimPrefix(line, name+"=")
		}
	}
	t.Fatalf("show text has no %s", name)
	return ""
}
