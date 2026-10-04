// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func validityGrant(t *testing.T, nbf, exp int64, mutate func(map[string]any)) string {
	t.Helper()
	claims := map[string]any{
		"iss": "github.com", "aud": githubReleaseAssetsHost,
		"key": "key1", "path": githubReleaseGrantStorageHosts[0],
		"nbf": nbf, "exp": exp,
	}
	if mutate != nil {
		mutate(claims)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	return claimJWT(string(payload))
}

func validityScanner(t *testing.T, now time.Time) *Scanner {
	t.Helper()
	cfg := config.Defaults()
	cfg.Internal = nil
	s, err := NewWithOptions(cfg, Options{Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}

func TestDownloadGrantValidityWindow(t *testing.T) {
	t.Parallel()
	grant := validityGrant(t, 1000, 1300, nil)
	skew := int64(downloadGrantClockSkew / time.Second)
	for _, tc := range []struct {
		name string
		now  int64
		want bool
	}{
		{"before start leeway", 1000 - skew - 1, false},
		{"at start leeway", 1000 - skew, true},
		{"after start leeway", 1000 - skew + 1, true},
		{"before expiry leeway", 1300 + skew - 1, true},
		{"at expiry leeway", 1300 + skew, false},
		{"after expiry leeway", 1300 + skew + 1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			now := time.Unix(tc.now, 0)
			if got := downloadGrantClaimsMatch(grant, githubReleaseAssetsHost, now); got != tc.want {
				t.Fatalf("claims match = %v, want %v", got, tc.want)
			}
			r := validityScanner(t, now).Scan(t.Context(), githubReleaseAssetsBase+"?jwt="+grant)
			if r.Allowed != tc.want {
				t.Fatalf("allowed = %v, want %v: %s", r.Allowed, tc.want, r.Reason)
			}
			if !tc.want && (!strings.Contains(r.Reason, "outside its validity window") || len(r.CredentialAudienceAllows) != 0) {
				t.Fatalf("window refusal = %#v", r)
			}
			if !tc.want && !strings.Contains(r.Hint, "outside its validity window") {
				t.Fatalf("window hint = %q", r.Hint)
			}
			if got := validityScanner(t, now).queryValueIsAudienceCredential(githubReleaseAssetsBase, grant); got != tc.want {
				t.Fatalf("entropy allowance = %v, want %v", got, tc.want)
			}
		})
	}
	// The exclusive upper bound also applies at subsecond precision.
	if !downloadGrantClaimsMatch(grant, githubReleaseAssetsHost, time.Unix(1300+skew-1, int64(time.Second-1))) ||
		downloadGrantClaimsMatch(grant, githubReleaseAssetsHost, time.Unix(1300+skew, 1)) {
		t.Fatal("expiry leeway must remain exclusive")
	}
}

func TestDownloadGrantLifetimeArithmeticSafety(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name     string
		nbf, exp int64
		want     bool
	}{
		{"one hour", 1000, 4600, true},
		{"over one hour", 1000, 4601, false},
		{"equal dates", 1000, 1000, false},
		{"reversed dates", 1300, 1000, false},
		{"negative start and maximum expiry", -1, math.MaxInt64, false},
		{"minimum start and positive expiry", math.MinInt64, 1300, false},
		{"maximum dates", math.MaxInt64 - 300, math.MaxInt64, false},
		{"negative dates", -300, -1, false},
		{"calendar upper bound", downloadGrantMaxUnixSeconds - 300, downloadGrantMaxUnixSeconds, true},
		{"past calendar upper bound", downloadGrantMaxUnixSeconds - 300, downloadGrantMaxUnixSeconds + 1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := downloadGrantLifetimeValid(tc.nbf, tc.exp); got != tc.want {
				t.Fatalf("lifetime valid = %v, want %v", got, tc.want)
			}
			if !tc.want {
				grant := validityGrant(t, tc.nbf, tc.exp, nil)
				if r := validityScanner(t, time.Unix(1100, 0)).Scan(t.Context(), githubReleaseAssetsBase+"?jwt="+grant); r.Allowed {
					t.Fatal("out-of-range grant allowed")
				}
			}
		})
	}
}

func TestDownloadGrantClaimLengthAndFormat(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name  string
		field string
		value any
		want  bool
	}{
		{"sampled key", "key", "key1", true},
		{"other key index", "key", "key2", true},
		{"widest key index", "key", "key999", true},
		{"key index past width bound", "key", "key1000", false},
		{"key without index", "key", "key", false},
		{"key index case", "key", "KEY1", false},
		{"key trailing byte", "key", "key1\n", false},
		{"sampled storage host", "path", githubReleaseGrantStorageHosts[0], true},
		{"key length bound", "key", strings.Repeat("k", downloadGrantMaxKeyLength+1), false},
		{"path length bound", "path", strings.Repeat("p", downloadGrantMaxPathLength+1), false},
		{"other key format", "key", "abcd", false},
		{"other storage host", "path", "storage.vendor.example", false},
		{"other account on the storage suffix", "path", "assets.blob.core.windows.net", false},
		{"storage host case", "path", strings.ToUpper(githubReleaseGrantStorageHosts[0]), false},
		{"storage host suffix", "path", githubReleaseGrantStorageHosts[0] + ".example", false},
		{"URL path format", "path", "/asset", false},
		{"null key", "key", nil, false},
		{"null path", "path", nil, false},
		{"numeric key", "key", 1, false},
		{"empty path", "path", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			grant := validityGrant(t, 1000, 1300, func(c map[string]any) { c[tc.field] = tc.value })
			now := time.Unix(1100, 0)
			if got := downloadGrantClaimsMatch(grant, githubReleaseAssetsHost, now); got != tc.want {
				t.Fatalf("claims match = %v, want %v", got, tc.want)
			}
			if r := validityScanner(t, now).Scan(t.Context(), githubReleaseAssetsBase+"?jwt="+grant); r.Allowed != tc.want {
				t.Fatalf("allowed = %v, want %v: %s", r.Allowed, tc.want, r.Reason)
			}
		})
	}
}

func TestSASValidityWindow(t *testing.T) {
	t.Parallel()
	start := time.Date(2026, 10, 4, 19, 0, 0, 0, time.UTC)
	expiry := start.Add(30 * time.Minute)
	for _, tc := range []struct {
		name string
		now  time.Time
		want bool
	}{
		{"before start leeway", start.Add(-downloadGrantClockSkew - time.Second), false},
		{"at start leeway", start.Add(-downloadGrantClockSkew), true},
		{"after start leeway", start.Add(-downloadGrantClockSkew + time.Second), true},
		{"before expiry leeway", expiry.Add(downloadGrantClockSkew - time.Second), true},
		{"at expiry leeway", expiry.Add(downloadGrantClockSkew), false},
		{"after expiry leeway", expiry.Add(downloadGrantClockSkew + time.Second), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Keep the grant current throughout the SAS boundary checks.
			grant := validityGrant(t, tc.now.Add(-time.Minute).Unix(), tc.now.Add(time.Minute).Unix(), nil)
			query, err := url.ParseQuery(releaseGrantSASQuery(grant, "validity-sas"))
			if err != nil {
				t.Fatal(err)
			}
			query.Set("st", start.Format(time.RFC3339))
			query.Set("se", expiry.Format(time.RFC3339))
			target := githubReleaseAssetsBase + "?" + query.Encode()
			if got := releaseGrantSASAllowed([]string{githubReleaseAssetsHost}, githubReleaseAssetsHost, target, tc.now); got != tc.want {
				t.Fatalf("release SAS allowed = %v, want %v", got, tc.want)
			}
			if r := validityScanner(t, tc.now).Scan(t.Context(), target); r.Allowed != tc.want {
				t.Fatalf("release URL allowed = %v, want %v: %s", r.Allowed, tc.want, r.Reason)
			}
			bundleQuery := attestationBundleQuery("validity-bundle", func(v url.Values) {
				v.Set("st", start.Format(time.RFC3339))
				v.Set("se", expiry.Format(time.RFC3339))
			})
			bundle := attestationBundleURL(githubAttestationBundleHosts[0], bundleQuery)
			if r := validityScanner(t, tc.now).Scan(t.Context(), bundle); r.Allowed != tc.want {
				t.Fatalf("bundle URL allowed = %v, want %v: %s", r.Allowed, tc.want, r.Reason)
			}
		})
	}
	for _, tc := range []struct{ name, st, se string }{
		{"invalid calendar expiry", "", "2026-02-30T19:00:00Z"},
		{"invalid calendar start", "2026-02-30T19:00:00Z", expiry.Format(time.RFC3339)},
		{"start after expiry", expiry.Add(time.Second).Format(time.RFC3339), expiry.Format(time.RFC3339)},
		{"empty start", "", expiry.Format(time.RFC3339)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			query := url.Values{"st": {tc.st}, "se": {tc.se}}
			if sasValidityWindowValid(query, start) {
				t.Fatal("invalid SAS dates accepted")
			}
		})
	}
	query := url.Values{"se": {expiry.Format(time.RFC3339)}}
	if !sasValidityWindowValid(query, start) || sasValidityWindowValid(query, expiry.Add(downloadGrantClockSkew)) {
		t.Fatal("optional start must preserve the expiry window")
	}
	query["st"] = []string{start.Format(time.RFC3339), start.Format(time.RFC3339)}
	if sasValidityWindowValid(query, start) {
		t.Fatal("duplicate SAS start accepted")
	}
	query = url.Values{"se": {expiry.Format(time.RFC3339), expiry.Format(time.RFC3339)}}
	if sasValidityWindowValid(query, start) {
		t.Fatal("duplicate SAS expiry accepted")
	}
}

func TestScan_GrantClockReadOnce(t *testing.T) {
	t.Parallel()
	var reads atomic.Int64
	cfg := config.Defaults()
	cfg.Internal = nil
	s, err := NewWithOptions(cfg, Options{Now: func() time.Time {
		reads.Add(1)
		return time.Unix(1100, 0)
	}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	target := githubReleaseAssetsBase + "?" + releaseGrantSASQuery(fakeAudienceJWT(), "clock-sas")
	for _, scan := range []func(context.Context, string) Result{s.Scan, s.ScanPreflight} {
		before := reads.Load()
		if r := scan(t.Context(), target); !r.Allowed {
			t.Fatal(r.Reason)
		}
		if delta := reads.Load() - before; delta != 1 {
			t.Fatalf("clock reads = %d, want 1", delta)
		}
	}
}

func TestGrantClockDefault(t *testing.T) {
	t.Parallel()
	before := time.Now()
	now := (&Scanner{}).currentTime()
	after := time.Now()
	if now.Before(before) || now.After(after) {
		t.Fatalf("default clock = %s, want a current time", now)
	}
}

func TestReleaseGrantSASTargetValidity(t *testing.T) {
	t.Parallel()
	now := time.Unix(1100, 0)
	if !releaseGrantSASAllowed([]string{githubReleaseAssetsHost}, githubReleaseAssetsHost,
		githubReleaseAssetsBase+"?"+releaseGrantSASQuery(fakeAudienceJWT(), "target-validity"), now) {
		t.Fatal("valid target refused")
	}
	for _, target := range []string{"https://%zz/asset", "http://" + githubReleaseAssetsHost + "/asset"} {
		if releaseGrantSASAllowed([]string{githubReleaseAssetsHost}, githubReleaseAssetsHost, target, now) {
			t.Fatalf("invalid target allowed: %s", target)
		}
	}
}

func TestAttestationBundleSASCalendarValidity(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 3, 22, 0, 0, 0, time.UTC)
	for _, field := range []string{"st", "se"} {
		t.Run(field, func(t *testing.T) {
			query := attestationBundleQuery("calendar-validity", func(v url.Values) {
				v.Set(field, "2026-02-30T22:00:00Z")
			})
			u, err := url.Parse(attestationBundleURL(githubAttestationBundleHosts[0], query))
			if err != nil {
				t.Fatal(err)
			}
			if attestationBundleSASQueryValid(u, now) || hasValidityCandidate(u, now) {
				t.Fatal("invalid calendar date must retain the match without a clock diagnostic")
			}
		})
	}
}

func hasValidityCandidate(u *url.URL, now time.Time) bool {
	_, _, ok := queryGrantValidityCandidate(u, now)
	return ok
}

func rawGrantJWT(header, payload string) string {
	enc := base64.RawURLEncoding
	sum := sha256.Sum256([]byte("serialization-fixture"))
	return enc.EncodeToString([]byte(header)) + "." + enc.EncodeToString([]byte(payload)) + "." + enc.EncodeToString(sum[:])
}

func TestDownloadGrantSerializationBounds(t *testing.T) {
	t.Parallel()
	const header = `{"typ":"JWT","alg":"HS256"}`
	host := githubReleaseAssetsHost
	payload := func(prefix string) string {
		return `{` + prefix + `"iss":"github.com","aud":"` + host + `","key":"key1","exp":1300,"nbf":1000,"path":"` + githubReleaseGrantStorageHosts[0] + `"}`
	}
	// The largest accepted claim set fills the payload bound exactly.
	maxDate := strconv.FormatInt(downloadGrantMaxUnixSeconds, 10)
	largest := `{"iss":"github.com","aud":"` + host + `.","key":"key999","exp":` + maxDate +
		`,"nbf":` + strconv.FormatInt(downloadGrantMaxUnixSeconds-60, 10) + `,"path":"` + githubReleaseGrantStorageHosts[0] + `"}`
	if len(largest) != downloadGrantMaxPayloadBytes(host) {
		t.Fatalf("largest payload = %d bytes, bound = %d", len(largest), downloadGrantMaxPayloadBytes(host))
	}
	largestAt := time.Unix(downloadGrantMaxUnixSeconds-30, 0)
	for _, tc := range []struct {
		name, header, payload string
		now                   time.Time
		want                  bool
	}{
		{"sampled serialization", header, payload(""), time.Unix(1100, 0), true},
		{"other header member order", `{"alg":"HS256","typ":"JWT"}`, payload(""), time.Unix(1100, 0), true},
		{"largest accepted claims", header, largest, largestAt, true},
		{"payload past bound", header, strings.Replace(largest, `{`, `{ `, 1), largestAt, false},
		{"header whitespace", `{"typ":"JWT", "alg":"HS256"}`, payload(""), time.Unix(1100, 0), false},
		{"header duplicate member", `{"typ":"JWT","alg":"HS256","alg":"HS256"}`, payload(""), time.Unix(1100, 0), false},
		{"payload duplicate member", header, payload(`"iss":"github.com",`), time.Unix(1100, 0), false},
		{"payload duplicate member after unescaping", header, payload(`"\u0069ss":"github.com",`), time.Unix(1100, 0), false},
		{"payload nested value", header, strings.Replace(payload(""), `"key":"key1"`, `"key":{"k":"key1"}`, 1), time.Unix(1100, 0), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			grant := rawGrantJWT(tc.header, tc.payload)
			if got := downloadGrantClaimsMatch(grant, host, tc.now); got != tc.want {
				t.Fatalf("claims match = %v, want %v", got, tc.want)
			}
			if r := validityScanner(t, tc.now).Scan(t.Context(), githubReleaseAssetsBase+"?jwt="+grant); r.Allowed != tc.want {
				t.Fatalf("allowed = %v, want %v: %s", r.Allowed, tc.want, r.Reason)
			}
		})
	}
}

func TestJSONMemberNamesUnique(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		raw  string
		want bool
	}{
		{`{"a":1,"b":"a"}`, true},
		{`[{"a":1},{"a":2}]`, true},
		{`{"a":{"b":1},"b":[{"b":2},{"b":3}],"c":null}`, true},
		{`{"a":1,"a":2}`, false},
		{`{"a":{"b":1,"b":2}}`, false},
		{`{"a":[{"x":1,"x":2}]}`, false},
		{`{"a":[1,2],"a":3}`, false},
		{`{"a":`, false},
		{`{"a":1}}`, false},
	} {
		if got := jsonMemberNamesUnique([]byte(tc.raw)); got != tc.want {
			t.Fatalf("%s: unique = %v, want %v", tc.raw, got, tc.want)
		}
	}
}

func TestRegistryJWTAudienceRejectsDuplicateMembers(t *testing.T) {
	t.Parallel()
	const host = "ghcr.io"
	for _, tc := range []struct {
		name, payload string
		want          bool
	}{
		{"nested access grant", `{"aud":"ghcr.io","access":[{"type":"repository","name":"o/r","actions":["pull"]}]}`, true},
		{"duplicate audience", `{"aud":"registry.vendor.example","aud":"ghcr.io","access":[{"type":"repository"}]}`, false},
		{"duplicate nested member", `{"aud":"ghcr.io","access":[{"type":"repository","type":"repository"}]}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := registryJWTAudienceMatches(claimJWT(tc.payload), host); got != tc.want {
				t.Fatalf("audience matches = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestGrantValidityNoteRequiresSoleCause(t *testing.T) {
	t.Parallel()
	expired := validityGrant(t, 1000, 1300, nil)
	now := time.Unix(1300+int64(2*downloadGrantClockSkew/time.Second), 0)
	stripe := "sk_" + "live_" + "4eC39HqLyjWDarjtT1zdp7dc"
	for _, tc := range []struct {
		name, target string
		wantNote     bool
	}{
		{"window is the only cause", githubReleaseAssetsBase + "?jwt=" + expired, true},
		{"other credential in path", "https://" + githubReleaseAssetsHost + "/" + stripe + "/asset?jwt=" + expired, false},
		{"other credential in query", githubReleaseAssetsBase + "?jwt=" + expired + "&token=" + stripe, false},
		{"grant for another destination", "https://download.vendor.example/asset?jwt=" + validityGrant(t, 1000, 1300, func(c map[string]any) { c["aud"] = "download.vendor.example" }), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := validityScanner(t, now).Scan(t.Context(), tc.target)
			if r.Allowed {
				t.Fatal("expired grant allowed")
			}
			if got := strings.Contains(r.Reason, "outside its validity window"); got != tc.wantNote {
				t.Fatalf("validity note = %v, want %v: %s", got, tc.wantNote, r.Reason)
			}
			g, ok := GuidanceForResult(r.Scanner, r.Reason)
			if got := ok && strings.Contains(g.OperatorKnob, "host clock"); got != tc.wantNote {
				t.Fatalf("clock guidance = %v, want %v: %q", got, tc.wantNote, g.OperatorKnob)
			}
		})
	}
}
