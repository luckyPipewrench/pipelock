// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package exec

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/launchcontract"
)

func TestPrintEnvironmentFormats(t *testing.T) {
	t.Parallel()
	vars := []launchcontract.Variable{{Name: "HTTP_PROXY", Value: "http://proxy.example:8888"}, {Name: "NO_PROXY", Value: ""}, {Name: "SSL_CERT_FILE", Value: "/path with spaces/ca.pem"}}
	for _, tt := range []struct{ format, want string }{
		{"sh", "unset CUSTOM_PROXY\nexport HTTP_PROXY='http://proxy.example:8888'\nexport NO_PROXY=''\nexport SSL_CERT_FILE='/path with spaces/ca.pem'\n"},
		{"pwsh", "Remove-Item Env:CUSTOM_PROXY -ErrorAction SilentlyContinue\n$env:HTTP_PROXY = 'http://proxy.example:8888'\n$env:NO_PROXY = ''\n$env:SSL_CERT_FILE = '/path with spaces/ca.pem'\n"},
		{"cmd", "set \"CUSTOM_PROXY=\"\r\nset \"HTTP_PROXY=http://proxy.example:8888\"\r\nset \"NO_PROXY=\"\r\nset \"SSL_CERT_FILE=/path with spaces/ca.pem\"\r\n"},
	} {
		t.Run(tt.format, func(t *testing.T) {
			t.Parallel()
			var b bytes.Buffer
			if err := printEnvironment(&b, tt.format, []string{"CUSTOM_PROXY=old", "SECRET=must-not-print"}, vars); err != nil || b.String() != tt.want {
				t.Fatalf("output=%q err=%v want=%q", b.String(), err, tt.want)
			}
		})
	}
	var b bytes.Buffer
	if err := printEnvironment(&b, "json", []string{"CUSTOM_PROXY=old", "SECRET=must-not-print"}, vars); err != nil {
		t.Fatal(err)
	}
	if !json.Valid(b.Bytes()) || strings.Contains(b.String(), "must-not-print") || !strings.Contains(b.String(), `"unset":["CUSTOM_PROXY"]`) {
		t.Fatalf("JSON=%s", b.String())
	}
}

func TestPrintQuotingAndRefusal(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		format, value, want string
		fail                bool
	}{
		{"sh", "a'b$(echo bad)`echo bad`", "'a'\"'\"'b$(echo bad)`echo bad`'", false},
		{"pwsh", "a'b$()", "'a''b$()'", false},
		{"cmd", "a%PATH%", "", true},
		{"cmd", "a!PATH!", "", true},
		{"cmd", "a\"&echo bad", "", true},
		{"cmd", "a\r\n", "", true},
		{"fish", "a", "", true},
	} {
		t.Run(tt.format+tt.value, func(t *testing.T) {
			t.Parallel()
			var b bytes.Buffer
			err := printEnvironment(&b, tt.format, nil, []launchcontract.Variable{{Name: "NO_PROXY", Value: tt.value}})
			if tt.fail {
				if err == nil || b.Len() != 0 {
					t.Fatalf("unsafe output=%q err=%v", b.String(), err)
				}
			} else if err != nil || !strings.Contains(b.String(), tt.want) {
				t.Fatalf("output=%q err=%v", b.String(), err)
			}
		})
	}
	var b bytes.Buffer
	if err := printEnvironment(&b, "sh", []string{"BAD;_PROXY=x"}, nil); err == nil || b.Len() != 0 {
		t.Fatalf("unsafe inherited name emitted: output=%q err=%v", b.String(), err)
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("write failure") }

func TestPrintWriteFailure(t *testing.T) {
	t.Parallel()
	for _, format := range []string{"sh", "json"} {
		if err := printEnvironment(failingWriter{}, format, nil, launchcontract.Vars(launchcontract.Exec, "proxy", "", "", "")); err == nil {
			t.Fatal("writer failure ignored")
		}
	}
}

func TestValidEnvironmentNames(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name string
		want bool
	}{
		{"", false}, {"1PROXY", false}, {"A_1", true}, {"A.B", false}, {"é_PROXY", false}, {"ALL_PROXY", true},
	} {
		if got := validEnvName(tt.name); got != tt.want {
			t.Errorf("validEnvName(%q)=%v", tt.name, got)
		}
	}
	var b bytes.Buffer
	if err := printEnvironment(&b, "invalid", []string{"CUSTOM_PROXY=x"}, nil); err == nil || b.Len() != 0 {
		t.Fatal("invalid format emitted unsets")
	}
}
