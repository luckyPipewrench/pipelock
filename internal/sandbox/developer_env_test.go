// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package sandbox

import (
	"encoding/binary"
	"strings"
	"testing"
)

func TestDeveloperEnvPreservesDeveloperVariablesAndForcesBridgeProxy(t *testing.T) {
	// Build the credential-shaped entry from split strings so the fixture is
	// not mistaken for a real secret; the key is what this test asserts is
	// preserved, not the value.
	env, err := DeveloperEnv([]string{
		"OPENAI_API_KEY" + "=" + "preserved-developer-value",
		"PATH=/developer/toolchain/bin",
		"LD_PRELOAD=/developer/lib/instrument.so",
		"NODE_OPTIONS=--require=/developer/hook.js",
		"PYTHONPATH=/developer/python",
		"BASH_ENV=/developer/bashrc",
		"ENV=/developer/shenv",
		"__PIPELOCK_SANDBOX_POLICY=must-not-reach-agent",
		"__pipelock_private=must-not-reach-agent",
		"Http_Proxy=http://api.vendor.example",
		"ALL_proxy=socks5://api.vendor.example",
		"No_PrOxY=*",
	}, "127.0.0.1:43210")
	if err != nil {
		t.Fatalf("DeveloperEnv: %v", err)
	}

	for _, key := range []string{
		"OPENAI_API_KEY", "PATH", "LD_PRELOAD", "NODE_OPTIONS", "PYTHONPATH", "BASH_ENV", "ENV",
	} {
		if envValue(env, key) == "" {
			t.Errorf("%s was not preserved for the final command", key)
		}
	}
	for _, key := range []string{
		"__PIPELOCK_SANDBOX_POLICY", "__pipelock_private", "Http_Proxy", "ALL_proxy", "No_PrOxY",
	} {
		if envValue(env, key) != "" {
			t.Errorf("%s leaked into final command environment: %q", key, envValue(env, key))
		}
	}
	for _, key := range []string{"HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"} {
		if got := envValue(env, key); got != "http://127.0.0.1:43210" {
			t.Errorf("%s = %q, want bridge proxy", key, got)
		}
	}
	for _, key := range []string{"NO_PROXY", "no_proxy"} {
		if got := envValue(env, key); got != "" {
			t.Errorf("%s = %q, want empty", key, got)
		}
	}
}

func TestDeveloperEnvironmentCodecRoundTripsDelimiterValues(t *testing.T) {
	// The key name is irrelevant to this codec round-trip; use a neutral key so
	// the fixture is not mistaken for a real credential. The value exercises the
	// unit separator, newline, embedded equals, and a non-ASCII rune.
	want := []string{
		"ROUNDTRIP_VALUE=before\x1fafter\nnext=equals☃",
		"PATH=/developer/bin",
	}
	payload, err := encodeDeveloperEnvironment(want)
	if err != nil {
		t.Fatalf("encodeDeveloperEnvironment: %v", err)
	}
	got, err := decodeDeveloperEnvironment(payload)
	if err != nil {
		t.Fatalf("decodeDeveloperEnvironment: %v", err)
	}
	if strings.Join(got, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("round trip = %#v, want %#v", got, want)
	}
}

func TestDeveloperEnvironmentCodecFailsClosed(t *testing.T) {
	payload, err := encodeDeveloperEnvironment([]string{"FIRST=one", "SECOND=two"})
	if err != nil {
		t.Fatalf("encodeDeveloperEnvironment: %v", err)
	}

	t.Run("duplicate key", func(t *testing.T) {
		// Hand-build a two-entry payload with the SAME key (the encoder refuses
		// to produce one), with the header count correctly set to 2, so the
		// decoder reaches the duplicate-key guard rather than being rejected
		// earlier by the entry-count guard.
		var duplicate []byte
		duplicate = append(duplicate, developerEnvironmentMagic[:]...)
		var word [4]byte
		binary.BigEndian.PutUint32(word[:], developerEnvironmentVersion)
		duplicate = append(duplicate, word[:]...)
		binary.BigEndian.PutUint32(word[:], 2) // entry count
		duplicate = append(duplicate, word[:]...)
		for range 2 {
			// Length prefix for "FIRST=one" (9 bytes) as big-endian uint32.
			duplicate = append(duplicate, 0, 0, 0, 9)
			duplicate = append(duplicate, "FIRST=one"...)
		}
		if _, err := decodeDeveloperEnvironment(duplicate); err == nil {
			t.Fatal("duplicate payload decoded successfully")
		}
	})

	t.Run("truncated", func(t *testing.T) {
		if _, err := decodeDeveloperEnvironment(payload[:len(payload)-1]); err == nil {
			t.Fatal("truncated payload decoded successfully")
		}
	})

	t.Run("oversize", func(t *testing.T) {
		over := make([]byte, developerEnvironmentMaxPayload+1)
		if _, err := decodeDeveloperEnvironment(over); err == nil {
			t.Fatal("oversize payload decoded successfully")
		}
	})

	for _, testCase := range []struct {
		name    string
		payload []byte
	}{
		{
			name:    "declared count exceeds payload",
			payload: []byte{'P', 'L', 'K', 'E', 0, 0, 0, 1, 0xff, 0xff, 0xff, 0xff},
		},
		{
			name:    "declared entry length exceeds payload",
			payload: []byte{'P', 'L', 'K', 'E', 0, 0, 0, 1, 0, 0, 0, 1, 0xff, 0xff, 0xff, 0xff},
		},
		{
			name:    "trailing bytes",
			payload: append(append([]byte(nil), payload...), 0),
		},
		{
			name:    "entry without equals",
			payload: []byte{'P', 'L', 'K', 'E', 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 3, 'k', 'e', 'y'},
		},
		{
			name:    "empty entry key",
			payload: []byte{'P', 'L', 'K', 'E', 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 6, '=', 'v', 'a', 'l', 'u', 'e'},
		},
		{
			name:    "NUL entry",
			payload: []byte{'P', 'L', 'K', 'E', 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 5, 'K', '=', 'v', 0, 'x'},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			if _, err := decodeDeveloperEnvironment(testCase.payload); err == nil {
				t.Fatal("malformed payload decoded successfully")
			}
		})
	}
}

func FuzzDeveloperEnvironmentDecoder(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{'P', 'L', 'K', 'E', 0, 0, 0, 1, 0, 0, 0, 0})
	payload, err := encodeDeveloperEnvironment([]string{"KEY=value"})
	if err != nil {
		f.Fatalf("encodeDeveloperEnvironment: %v", err)
	}
	f.Add(payload)

	f.Fuzz(func(t *testing.T, payload []byte) {
		_, _ = decodeDeveloperEnvironment(payload)
	})
}

func TestDeveloperEnvironmentControlDescriptorFailsClosed(t *testing.T) {
	for _, value := range []string{"", "2", "4", "not-a-descriptor"} {
		t.Run(value, func(t *testing.T) {
			if _, err := developerEnvironmentFDFromControl(value); err == nil {
				t.Fatal("invalid developer environment descriptor accepted")
			}
		})
	}

	fd, err := developerEnvironmentFDFromControl("3")
	if err != nil {
		t.Fatalf("developerEnvironmentFDFromControl(3): %v", err)
	}
	if fd != developerEnvironmentFD {
		t.Fatalf("descriptor = %d, want %d", fd, developerEnvironmentFD)
	}
}
