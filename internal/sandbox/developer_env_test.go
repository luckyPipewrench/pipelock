// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package sandbox

import (
	"encoding/binary"
	"strings"
	"testing"
)

func TestDeveloperEnvPreservesDeveloperVariablesAndForcesBridgeProxy(t *testing.T) {
	env, err := DeveloperEnv([]string{
		"OPENAI_API_KEY=recognizable-token",
		"PATH=/developer/toolchain/bin",
		"LD_PRELOAD=/developer/lib/instrument.so",
		"NODE_OPTIONS=--require=/developer/hook.js",
		"PYTHONPATH=/developer/python",
		"BASH_ENV=/developer/bashrc",
		"ENV=/developer/shenv",
		"__PIPELOCK_SANDBOX_POLICY=must-not-reach-agent",
		"__pipelock_private=must-not-reach-agent",
		"Http_Proxy=http://attacker.invalid",
		"ALL_proxy=socks5://attacker.invalid",
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
	want := []string{
		"API_TOKEN=before\x1fafter\nnext=equals",
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
		duplicate := make([]byte, 0, len(payload)+16)
		duplicate = append(duplicate, payload[:8]...)
		binary.BigEndian.PutUint32(duplicate[8:12], 2)
		duplicate = append(duplicate, payload[12:25]...)
		duplicate = append(duplicate, 0, 0, 0, 9)
		duplicate = append(duplicate, "FIRST=two"...)
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
}
