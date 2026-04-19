// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package redact

import (
	"reflect"
	"testing"
)

// Common expected placeholder values. Extracted to satisfy goconst.
const (
	wantIPv4First = "<pl:ipv4:1>"
)

func TestRedactor_SingleMatchFirstPlaceholder(t *testing.T) {
	t.Parallel()
	r := NewRedactor()
	got := r.Placeholder(ClassIPv4, "192.0.2.104")
	if got != wantIPv4First {
		t.Fatalf("first placeholder = %q, want %q", got, wantIPv4First)
	}
	if r.Total() != 1 {
		t.Fatalf("total = %d, want 1", r.Total())
	}
}

func TestRedactor_MultipleDistinctSameClass(t *testing.T) {
	t.Parallel()
	r := NewRedactor()
	cases := []struct {
		original string
		want     string
	}{
		{"192.0.2.104", wantIPv4First},
		{"192.168.1.5", "<pl:ipv4:2>"},
		{"127.0.0.1", "<pl:ipv4:3>"},
	}
	for _, tc := range cases {
		if got := r.Placeholder(ClassIPv4, tc.original); got != tc.want {
			t.Errorf("Placeholder(%q) = %q, want %q", tc.original, got, tc.want)
		}
	}
	if r.Total() != 3 {
		t.Fatalf("total = %d, want 3", r.Total())
	}
}

func TestRedactor_SameValueDeduplicated(t *testing.T) {
	t.Parallel()
	r := NewRedactor()
	first := r.Placeholder(ClassFQDN, "dc01.corp.local")
	second := r.Placeholder(ClassFQDN, "dc01.corp.local")
	third := r.Placeholder(ClassFQDN, "dc01.corp.local")
	if first != "<pl:fqdn:1>" {
		t.Fatalf("first = %q, want <pl:fqdn:1>", first)
	}
	if second != first || third != first {
		t.Fatalf("dedup broke: first=%q second=%q third=%q", first, second, third)
	}
	if r.Total() != 1 {
		t.Fatalf("total = %d after 3 lookups of same value, want 1", r.Total())
	}
}

func TestRedactor_DifferentClassesHaveIndependentCounters(t *testing.T) {
	t.Parallel()
	r := NewRedactor()
	cases := []struct {
		class    Class
		original string
		want     string
	}{
		{ClassIPv4, "10.0.0.1", "<pl:ipv4:1>"},
		{ClassFQDN, "one.example", "<pl:fqdn:1>"},
		{ClassIPv4, "10.0.0.2", "<pl:ipv4:2>"},
		{ClassEmail, "a@b", "<pl:email:1>"},
		{ClassFQDN, "two.example", "<pl:fqdn:2>"},
		{ClassIPv4, "10.0.0.3", "<pl:ipv4:3>"},
	}
	for _, tc := range cases {
		if got := r.Placeholder(tc.class, tc.original); got != tc.want {
			t.Errorf("Placeholder(%s, %q) = %q, want %q", tc.class, tc.original, got, tc.want)
		}
	}
}

func TestRedactor_SequenceResetsAcrossInstances(t *testing.T) {
	t.Parallel()
	// Request 1
	r1 := NewRedactor()
	r1.Placeholder(ClassIPv4, "10.0.0.1")
	r1.Placeholder(ClassIPv4, "10.0.0.2")
	// Request 2: fresh Redactor starts numbering at 1 even for the same value.
	r2 := NewRedactor()
	got := r2.Placeholder(ClassIPv4, "10.0.0.1")
	if got != wantIPv4First {
		t.Fatalf("second-instance placeholder = %q, want %q", got, wantIPv4First)
	}
}

func TestRedactor_ByClassAndTotalReport(t *testing.T) {
	t.Parallel()
	r := NewRedactor()
	r.Placeholder(ClassIPv4, "10.0.0.1")
	r.Placeholder(ClassIPv4, "10.0.0.2")
	r.Placeholder(ClassIPv4, "10.0.0.1") // dedup, does not increment
	r.Placeholder(ClassFQDN, "one.example")
	r.Placeholder(ClassAWSAccessKey, "AKIA"+"IOSFODNN7EXAMPLE")

	if r.Total() != 4 {
		t.Fatalf("total = %d, want 4", r.Total())
	}
	wantByClass := map[Class]int{
		ClassIPv4:         2,
		ClassFQDN:         1,
		ClassAWSAccessKey: 1,
	}
	if got := r.ByClass(); !reflect.DeepEqual(got, wantByClass) {
		t.Fatalf("ByClass() = %v, want %v", got, wantByClass)
	}
}

func TestRedactor_ByClassReturnsCopy(t *testing.T) {
	t.Parallel()
	r := NewRedactor()
	r.Placeholder(ClassIPv4, "10.0.0.1")
	snapshot := r.ByClass()
	snapshot[ClassIPv4] = 99
	if r.ByClass()[ClassIPv4] != 1 {
		t.Fatalf("mutating ByClass() result affected internal state")
	}
}

func TestRedactor_BuiltInClassesFormatCorrectly(t *testing.T) {
	t.Parallel()
	classes := []Class{
		ClassIPv4, ClassIPv6, ClassCIDR, ClassFQDN, ClassEmail,
		ClassAWSAccessKey, ClassGoogleAPIKey,
		ClassGitHubToken, ClassSlackToken, ClassJWT,
		ClassHashMD5, ClassHashSHA1, ClassHashSHA256, ClassHashSHA512,
		ClassMAC, ClassSSN, ClassCreditCard,
		ClassSSHPrivateKey, ClassADUser,
	}
	for _, c := range classes {
		t.Run(string(c), func(t *testing.T) {
			t.Parallel()
			r := NewRedactor()
			got := r.Placeholder(c, "value")
			want := "<pl:" + string(c) + ":1>"
			if got != want {
				t.Fatalf("Placeholder(%s) = %q, want %q", c, got, want)
			}
		})
	}
}

func TestRedactor_ReservedClassesFormatCorrectly(t *testing.T) {
	t.Parallel()
	classes := []Class{
		ClassAWSSecretKey,
		ClassBearer,
		ClassHashNTLM,
		ClassCredential,
	}
	for _, c := range classes {
		t.Run(string(c), func(t *testing.T) {
			t.Parallel()
			r := NewRedactor()
			got := r.Placeholder(c, "value")
			want := "<pl:" + string(c) + ":1>"
			if got != want {
				t.Fatalf("Placeholder(%s) = %q, want %q", c, got, want)
			}
		})
	}
}

func TestRedactor_CustomClassAccepted(t *testing.T) {
	t.Parallel()
	// Operator-dictionary classes (e.g. "customer", "hostname", "codename") are
	// not in the shipped constants but must work end-to-end.
	r := NewRedactor()
	if got, want := r.Placeholder(Class("customer"), "AcmeCorp"), "<pl:customer:1>"; got != want {
		t.Fatalf("custom class = %q, want %q", got, want)
	}
}

func TestRedactor_EmptyOriginalStillPlaceholders(t *testing.T) {
	t.Parallel()
	// Defensive: DLP generally matches non-empty, but an empty original must
	// not panic and must still number deterministically.
	r := NewRedactor()
	first := r.Placeholder(ClassIPv4, "")
	second := r.Placeholder(ClassIPv4, "")
	if first != wantIPv4First {
		t.Fatalf("empty original first = %q, want %q", first, wantIPv4First)
	}
	if second != first {
		t.Fatalf("empty original not deduped: first=%q second=%q", first, second)
	}
	if r.Total() != 1 {
		t.Fatalf("total = %d, want 1", r.Total())
	}
}
