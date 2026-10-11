// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receiptcontent

import (
	"strings"
	"testing"
)

func TestRunSessionSuffixProof(t *testing.T) {
	suffix := NewRunSessionSuffix("proxy")
	if len(suffix) != runSuffixHexLen || strings.ToLower(suffix) != suffix {
		t.Fatalf("suffix %q has the wrong shape", suffix)
	}
	session := "proxy.run." + suffix
	if base, ok := SplitProvenRunSession(session); !ok || base != "proxy" {
		t.Fatalf("minted session not proven: %q %t", base, ok)
	}
	for name, s := range map[string]string{
		"no infix":         "proxy",
		"empty base":       ".run." + suffix,
		"chosen suffix":    "proxy.run.0123456789abcdef0123456789abcdef",
		"grafted base":     "other.run." + suffix,
		"short suffix":     "proxy.run." + suffix[:30],
		"uppercase suffix": "proxy.run." + strings.ToUpper(suffix),
		"non-hex suffix":   "proxy.run." + suffix[:30] + "zz",
		"second infix":     "proxy.run.x.run." + suffix,
	} {
		if _, ok := SplitProvenRunSession(s); ok {
			t.Errorf("%s: %q proven", name, s)
		}
	}
}

func TestRunSessionClassProjectsOnlyTheBase(t *testing.T) {
	p := &Producer{schema: &Schema{Kind: "test.run_session", Fields: map[string]Class{"s": RunSession}}}
	minted := "opbase.run." + NewRunSessionSuffix("opbase")
	proj, err := p.Project([]byte(`{"s":"` + minted + `"}`))
	if err != nil {
		t.Fatal(err)
	}
	atoms := proj.Atoms()
	if len(atoms) != 1 || atoms[0].Text != "opbase" || !atoms[0].Identity {
		t.Fatalf("proven session atoms = %+v, want the base as an identity", atoms)
	}
	if strings.Contains(string(proj.Structured()), ".run.") {
		t.Fatalf("structured view kept the generated suffix: %s", proj.Structured())
	}
	chosen := "opbase.run.0123456789abcdef0123456789abcdef"
	proj, err = p.Project([]byte(`{"s":"` + chosen + `"}`))
	if err != nil {
		t.Fatal(err)
	}
	atoms = proj.Atoms()
	if len(atoms) != 1 || atoms[0].Text != chosen || !atoms[0].Identity {
		t.Fatalf("unproven session atoms = %+v, want the whole value as an identity", atoms)
	}
}
