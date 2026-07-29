// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
)

// scriptedRun is an injectable runCommand whose output/exit/err are decided by
// inspecting the args, so each doctor check can be driven deterministically.
type scriptedRun func(args []string) (string, int, error)

func (s scriptedRun) cmd(_ context.Context, _ string, args ...string) (string, int, error) {
	return s(args)
}

func newDoctorEnv(t *testing.T, run scriptedRun) *doctorEnv {
	t.Helper()
	env := defaultDoctorEnv()
	env.runCmd = run.cmd
	counter := uint64(10)
	env.dropCounter = func(context.Context) (uint64, error) {
		counter++
		return counter, nil
	}
	env.dialCtx = func(_ context.Context, _, _ string, _ time.Duration) (net.Conn, error) {
		return &fakeConn{}, nil
	}
	env.readFile = func(string) ([]byte, error) { return nil, errors.New("no read") }
	env.stat = func(string) (os.FileInfo, error) { return nil, nil } // shim present
	return env
}

func TestDoctorCounterProbeEnvUsesLiveDoctorOverrides(t *testing.T) {
	base := &probeEnv{port: defaultProxyPort, agentUserName: defaultAgentUser}
	doctor := &doctorEnv{port: 9443, agentUserName: "custom-agent"}

	got := doctorCounterProbeEnv(base, doctor)
	if got.port != doctor.port {
		t.Fatalf("counter probe port = %d, want live doctor port %d", got.port, doctor.port)
	}
	if got.agentUserName != doctor.agentUserName {
		t.Fatalf("counter probe agent = %q, want live doctor agent %q", got.agentUserName, doctor.agentUserName)
	}
	if base.port != defaultProxyPort || base.agentUserName != defaultAgentUser {
		t.Fatalf("base probe env was mutated: port=%d agent=%q", base.port, base.agentUserName)
	}
}

func TestDoctorDropCounterReaderUsesLiveDoctorOverrides(t *testing.T) {
	base := &probeEnv{}
	doctor := &doctorEnv{port: 9443, agentUserName: "custom-agent"}
	base.dropCounter = func(_ context.Context, got *probeEnv) (uint64, error) {
		if got.port != doctor.port || got.agentUserName != doctor.agentUserName {
			t.Fatalf("counter env = port %d agent %q, want port %d agent %q",
				got.port, got.agentUserName, doctor.port, doctor.agentUserName)
		}
		return 42, nil
	}

	got, err := doctorDropCounterReader(base, doctor)(context.Background())
	if err != nil {
		t.Fatalf("counter read: %v", err)
	}
	if got != 42 {
		t.Fatalf("counter = %d, want 42", got)
	}
}

// argsContain reports whether the joined args contain every needle.
func argsContain(args []string, needles ...string) bool {
	joined := strings.Join(args, " ")
	for _, n := range needles {
		if !strings.Contains(joined, n) {
			return false
		}
	}
	return true
}

func TestCheckGatewayHealth(t *testing.T) {
	env := newDoctorEnv(t, func([]string) (string, int, error) { return "", 0, nil })
	if res := checkGatewayHealth(context.Background(), env); res.status != statusPass {
		t.Fatalf("healthy dial: got %q (%s)", res.status, res.detail)
	}

	env.dialCtx = func(context.Context, string, string, time.Duration) (net.Conn, error) {
		return nil, errors.New("connection refused")
	}
	res := checkGatewayHealth(context.Background(), env)
	if res.status != statusFail || res.class != classInfra {
		t.Fatalf("dead proxy: got status=%q class=%q", res.status, res.class)
	}
}

func TestCheckCurlThroughProxy(t *testing.T) {
	t.Run("pass on 200", func(t *testing.T) {
		env := newDoctorEnv(t, func(args []string) (string, int, error) {
			if !argsContain(args, "--proxy", "example.com") {
				t.Fatalf("unexpected args: %v", args)
			}
			return "200", 0, nil
		})
		if res := checkCurlThroughProxy(context.Background(), env); res.status != statusPass {
			t.Fatalf("got %q (%s)", res.status, res.detail)
		}
	})
	t.Run("CA error -> infra + ca-refresh", func(t *testing.T) {
		env := newDoctorEnv(t, func([]string) (string, int, error) { return "curl: (60) cert", 60, nil })
		res := checkCurlThroughProxy(context.Background(), env)
		if res.status != statusFail || res.class != classInfra || !strings.Contains(res.remediation, "ca-refresh") {
			t.Fatalf("got status=%q class=%q rem=%q", res.status, res.class, res.remediation)
		}
	})
	t.Run("proxy failure -> proxy-compat", func(t *testing.T) {
		env := newDoctorEnv(t, func([]string) (string, int, error) { return "curl: (7) refused", 7, nil })
		res := checkCurlThroughProxy(context.Background(), env)
		if res.status != statusFail || res.class != classProxyCompat {
			t.Fatalf("got status=%q class=%q", res.status, res.class)
		}
	})
	t.Run("non-2xx -> policy", func(t *testing.T) {
		env := newDoctorEnv(t, func([]string) (string, int, error) { return "403", 0, nil })
		res := checkCurlThroughProxy(context.Background(), env)
		if res.status != statusFail || res.class != classPolicy {
			t.Fatalf("got status=%q class=%q", res.status, res.class)
		}
	})
	t.Run("sudo refusal -> skip", func(t *testing.T) {
		env := newDoctorEnv(t, func([]string) (string, int, error) { return "sudo: a password is required", 1, nil })
		res := checkCurlThroughProxy(context.Background(), env)
		if res.status != statusSkip || !strings.Contains(res.remediation, "root") {
			t.Fatalf("got status=%q rem=%q", res.status, res.remediation)
		}
	})
	t.Run("agent missing -> skip install", func(t *testing.T) {
		env := newDoctorEnv(t, func([]string) (string, int, error) { return "sudo: unknown user: pipelock-agent", 1, nil })
		res := checkCurlThroughProxy(context.Background(), env)
		if res.status != statusSkip || !strings.Contains(res.remediation, "install") {
			t.Fatalf("got status=%q rem=%q", res.status, res.remediation)
		}
	})
}

func TestCheckPythonThroughProxy(t *testing.T) {
	t.Run("pass", func(t *testing.T) {
		env := newDoctorEnv(t, func(args []string) (string, int, error) {
			if !argsContain(args, "pipelock-python") {
				t.Fatalf("did not use wrapper: %v", args)
			}
			return "200", 0, nil
		})
		if res := checkPythonThroughProxy(context.Background(), env); res.status != statusPass {
			t.Fatalf("got %q (%s)", res.status, res.detail)
		}
	})
	t.Run("missing python -> skip", func(t *testing.T) {
		env := newDoctorEnv(t, func([]string) (string, int, error) { return "not found", 127, nil })
		if res := checkPythonThroughProxy(context.Background(), env); res.status != statusSkip {
			t.Fatalf("got %q", res.status)
		}
	})
	t.Run("failure -> proxy-compat", func(t *testing.T) {
		env := newDoctorEnv(t, func([]string) (string, int, error) { return "boom", 1, nil })
		res := checkPythonThroughProxy(context.Background(), env)
		if res.status != statusFail || res.class != classProxyCompat {
			t.Fatalf("got status=%q class=%q", res.status, res.class)
		}
	})
}

func TestCheckNodeThroughProxy(t *testing.T) {
	t.Run("pass", func(t *testing.T) {
		env := newDoctorEnv(t, func(args []string) (string, int, error) {
			if !argsContain(args, "pipelock-node") {
				t.Fatalf("did not use wrapper: %v", args)
			}
			return "200", 0, nil
		})
		if res := checkNodeThroughProxy(context.Background(), env); res.status != statusPass {
			t.Fatalf("got %q (%s)", res.status, res.detail)
		}
	})
	t.Run("missing shim -> skip", func(t *testing.T) {
		env := newDoctorEnv(t, func([]string) (string, int, error) { return "200", 0, nil })
		env.stat = func(string) (os.FileInfo, error) { return nil, os.ErrNotExist }
		res := checkNodeThroughProxy(context.Background(), env)
		if res.status != statusSkip || !strings.Contains(res.detail, "shim") {
			t.Fatalf("got status=%q detail=%q", res.status, res.detail)
		}
	})
	t.Run("missing node -> skip", func(t *testing.T) {
		env := newDoctorEnv(t, func([]string) (string, int, error) { return "", 127, nil })
		if res := checkNodeThroughProxy(context.Background(), env); res.status != statusSkip {
			t.Fatalf("got %q", res.status)
		}
	})
	t.Run("failure names the shim", func(t *testing.T) {
		env := newDoctorEnv(t, func([]string) (string, int, error) { return "fetch failed", 1, nil })
		res := checkNodeThroughProxy(context.Background(), env)
		if res.status != statusFail || res.class != classProxyCompat || !strings.Contains(res.remediation, "undici") {
			t.Fatalf("got status=%q class=%q rem=%q", res.status, res.class, res.remediation)
		}
	})
}

func TestCheckDNSFailure(t *testing.T) {
	t.Run("clean failure via Pipelock policy denial 403", func(t *testing.T) {
		env := newDoctorEnv(t, func(args []string) (string, int, error) {
			if !argsContain(args, dnsFailureHost, "%{http_connect}") {
				t.Fatalf("did not target nxdomain: %v", args)
			}
			return "curl: (56) CONNECT tunnel failed, response 403\n403", 56, nil
		})
		if res := checkDNSFailure(context.Background(), env); res.status != statusPass {
			t.Fatalf("got %q (%s)", res.status, res.detail)
		}
	})
	t.Run("clean failure via attributed proxy CONNECT 5xx", func(t *testing.T) {
		env := newDoctorEnv(t, func(args []string) (string, int, error) {
			if !argsContain(args, dnsFailureHost, "%{http_connect}") {
				t.Fatalf("did not target nxdomain: %v", args)
			}
			return "curl: (56) CONNECT tunnel failed, response 502\n502", 56, nil
		})
		if res := checkDNSFailure(context.Background(), env); res.status != statusPass {
			t.Fatalf("got %q (%s)", res.status, res.detail)
		}
	})
	t.Run("unattributed nonzero exits are unknown", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			out  string
			code int
		}{
			{name: "proxy unavailable", out: "curl: (7) Failed to connect\n000", code: 7},
			{name: "TLS failure after CONNECT", out: "curl: (35) TLS error\n200", code: 35},
			{name: "proxy authentication required", out: "curl: (56) CONNECT failed\n407", code: 56},
			{name: "unrelated client denial", out: "curl: (56) CONNECT failed\n404", code: 56},
			{name: "no status", out: "curl failed", code: 56},
		} {
			t.Run(tc.name, func(t *testing.T) {
				env := newDoctorEnv(t, func([]string) (string, int, error) {
					return tc.out, tc.code, nil
				})
				res := checkDNSFailure(context.Background(), env)
				if res.status != statusUnknown || res.class != classInfra {
					t.Fatalf("got status=%q class=%q detail=%q", res.status, res.class, res.detail)
				}
			})
		}
	})
	t.Run("bogus host resolved -> fail", func(t *testing.T) {
		env := newDoctorEnv(t, func([]string) (string, int, error) { return "200", 0, nil })
		res := checkDNSFailure(context.Background(), env)
		if res.status != statusFail || res.class != classInfra {
			t.Fatalf("got status=%q class=%q", res.status, res.class)
		}
	})
}

func TestCheckRawEgressBlocked(t *testing.T) {
	t.Run("blocked -> pass with proxy-compat remediation", func(t *testing.T) {
		env := newDoctorEnv(t, func(args []string) (string, int, error) {
			if !argsContain(args, "--noproxy", directEgressCanaryURL,
				"--connect-timeout", directCurlConnectTimeout,
				"--max-time", directCurlMaxTime,
				directCurlTimeConnectPrefix+"%{time_connect}") {
				t.Fatalf("did not attempt direct egress: %v", args)
			}
			return "curl: (7) refused\nPLK_TIME_CONNECT=0.000000\n000", 7, nil
		})
		res := checkRawEgressBlocked(context.Background(), env)
		if res.status != statusPass || res.class != classProxyCompat {
			t.Fatalf("got status=%q class=%q", res.status, res.class)
		}
		if !strings.Contains(res.remediation, "pipelock-curl") {
			t.Fatalf("remediation should name wrappers: %q", res.remediation)
		}
	})
	t.Run("direct success -> containment hole fail", func(t *testing.T) {
		env := newDoctorEnv(t, func([]string) (string, int, error) { return "200", 0, nil })
		res := checkRawEgressBlocked(context.Background(), env)
		if res.status != statusFail || !strings.Contains(res.detail, "CONTAINMENT HOLE") {
			t.Fatalf("got status=%q detail=%q", res.status, res.detail)
		}
	})
}

func TestTrailingHTTPCode(t *testing.T) {
	cases := []struct {
		in   string
		code int
		ok   bool
	}{
		{"200", 200, true},
		{"warning line\n302", 302, true},
		{"sudo: foo 404", 404, true},
		{"", 0, false},
		{"no code here", 0, false},
	}
	for _, c := range cases {
		code, ok := trailingHTTPCode(c.in)
		if code != c.code || ok != c.ok {
			t.Errorf("trailingHTTPCode(%q) = %d,%v want %d,%v", c.in, code, ok, c.code, c.ok)
		}
	}
}

func TestRunDoctor_TextAllPass(t *testing.T) {
	env := allPassDoctorEnv(t)
	var buf bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&buf)
	cmd.SetContext(context.Background())
	err := runDoctor(cmd, env, doctorOpts{})
	if err != nil {
		t.Fatalf("runDoctor: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "6 PASS") || !strings.Contains(out, "exit 0") {
		t.Fatalf("unexpected output:\n%s", out)
	}
}

func TestRunDoctor_JSONAllPass(t *testing.T) {
	env := allPassDoctorEnv(t)
	var buf bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&buf)
	cmd.SetContext(context.Background())
	if err := runDoctor(cmd, env, doctorOpts{jsonOutput: true}); err != nil {
		t.Fatalf("runDoctor: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, `"status":"pass"`) || !strings.Contains(out, `"exit_code":0`) {
		t.Fatalf("unexpected json:\n%s", out)
	}
}

func TestRunDoctor_JSONAndFailExit(t *testing.T) {
	// All checks fail/skip via a runner that succeeds at direct egress (the
	// raw-egress check then reports a containment hole = fail).
	env := newDoctorEnv(t, func([]string) (string, int, error) { return "200", 0, nil })
	var buf bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&buf)
	cmd.SetContext(context.Background())
	err := runDoctor(cmd, env, doctorOpts{jsonOutput: true})
	if err == nil {
		t.Fatalf("expected non-nil error on failing run")
	}
	out := buf.String()
	// Bind the class assertion to check 6's own record, not just anywhere in
	// the output, so an unrelated infra record can't mask a regression.
	idx := strings.Index(out, `"check":6`)
	if idx == -1 {
		t.Fatalf("json missing check 6 record:\n%s", out)
	}
	rec := out[idx:]
	if nl := strings.IndexByte(rec, '\n'); nl != -1 {
		rec = rec[:nl]
	}
	if !strings.Contains(rec, `"class":"infra"`) {
		t.Fatalf("check 6 record missing infra class:\n%s", rec)
	}
	if !strings.Contains(out, `"aggregate"`) {
		t.Fatalf("json missing aggregate:\n%s", out)
	}
}

func TestRunDoctor_UnknownIsIncompleteInTextAndJSON(t *testing.T) {
	for _, jsonOutput := range []bool{false, true} {
		t.Run(map[bool]string{false: "text", true: "json"}[jsonOutput], func(t *testing.T) {
			env := allPassDoctorEnv(t)
			env.dropCounter = func(context.Context) (uint64, error) { return 12, nil }

			var buf bytes.Buffer
			cmd := &cobra.Command{}
			cmd.SetOut(&buf)
			cmd.SetContext(context.Background())
			err := runDoctor(cmd, env, doctorOpts{jsonOutput: jsonOutput})
			if code := cliutil.ExitCodeOf(err); code != cliutil.ExitConfig {
				t.Fatalf("exit code = %d, want %d (err=%v)", code, cliutil.ExitConfig, err)
			}

			out := buf.String()
			if jsonOutput {
				if !strings.Contains(out, `"check":6`) ||
					!strings.Contains(out, `"status":"unknown"`) ||
					!strings.Contains(out, `"unknown":1`) ||
					!strings.Contains(out, `"exit_code":2`) {
					t.Fatalf("JSON did not preserve UNKNOWN as incomplete:\n%s", out)
				}
				return
			}
			if !strings.Contains(out, "[UNKNOWN]") ||
				!strings.Contains(out, "1 UNKNOWN") ||
				!strings.Contains(out, "exit 2") {
				t.Fatalf("text did not preserve UNKNOWN as incomplete:\n%s", out)
			}
		})
	}
}

func TestRunDoctor_MixedOutcomesPreserveWorstResultInTextAndJSON(t *testing.T) {
	for _, jsonOutput := range []bool{false, true} {
		t.Run(map[bool]string{false: "text", true: "json"}[jsonOutput], func(t *testing.T) {
			env := newDoctorEnv(t, func(args []string) (string, int, error) {
				switch {
				case argsContain(args, "--noproxy"):
					return "curl: (7) refused\nPLK_TIME_CONNECT=0.000000\n000", 7, nil
				case argsContain(args, dnsFailureHost):
					return "curl: (7) proxy unavailable\n000", 7, nil
				case argsContain(args, "pipelock-python"):
					return "not found", 127, nil
				case argsContain(args, "pipelock-node"):
					return "200", 0, nil
				default:
					return "curl: (60) certificate problem", 60, nil
				}
			})

			var buf bytes.Buffer
			cmd := &cobra.Command{}
			cmd.SetOut(&buf)
			cmd.SetContext(context.Background())
			err := runDoctor(cmd, env, doctorOpts{jsonOutput: jsonOutput})
			if code := cliutil.ExitCodeOf(err); code != cliutil.ExitGeneral {
				t.Fatalf("exit code = %d, want fail precedence %d (err=%v)", code, cliutil.ExitGeneral, err)
			}

			out := buf.String()
			if jsonOutput {
				lines := strings.Split(strings.TrimSpace(out), "\n")
				var agg aggregateRecord
				if err := json.Unmarshal([]byte(lines[len(lines)-1]), &agg); err != nil {
					t.Fatalf("decode aggregate: %v\n%s", err, out)
				}
				if agg.Aggregate.Pass != 3 || agg.Aggregate.Fail != 1 ||
					agg.Aggregate.Skip != 1 || agg.Aggregate.Unknown != 1 ||
					agg.Aggregate.ExitCode != cliutil.ExitGeneral {
					t.Fatalf("mixed aggregate = %+v, want 3 pass / 1 fail / 1 skip / 1 unknown / exit 1", agg.Aggregate)
				}
				return
			}
			if !strings.Contains(out, "3 PASS / 1 FAIL / 1 SKIP / 1 UNKNOWN — exit 1") {
				t.Fatalf("text lost a mixed outcome or fail precedence:\n%s", out)
			}
		})
	}
}

// errWriter fails every write, to exercise JSON-encode error paths.
type errWriter struct{}

func (errWriter) Write([]byte) (int, error) { return 0, errors.New("write blew up") }

func TestRunDoctor_NilContextAndEncodeError(t *testing.T) {
	env := allPassDoctorEnv(t)
	cmd := &cobra.Command{}
	cmd.SetOut(errWriter{}) // force enc.Encode to fail
	// Intentionally do NOT SetContext, exercising the ctx==nil fallback.
	if err := runDoctor(cmd, env, doctorOpts{jsonOutput: true}); err == nil {
		t.Fatalf("expected encode error to surface")
	}
}

func TestRunDoctor_TextWriteFailureFailsClosed(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.SetOut(errWriter{})
	if err := runDoctor(cmd, allPassDoctorEnv(t), doctorOpts{}); err == nil ||
		!strings.Contains(err.Error(), "writing doctor header") {
		t.Fatalf("text output failure = %v, want surfaced header write error", err)
	}

	jsonCmd := &cobra.Command{}
	jsonCmd.SetOut(errWriter{})
	if err := runDoctor(jsonCmd, allPassDoctorEnv(t), doctorOpts{jsonOutput: true}); err == nil ||
		!strings.Contains(err.Error(), "encoding check 1 JSON") {
		t.Fatalf("JSON output failure = %v, want surfaced check 1 encode error", err)
	}
}

func TestRunDoctor_RecordAndAggregateWriteFailuresFailClosed(t *testing.T) {
	tests := []struct {
		name             string
		jsonOutput       bool
		successfulWrites int
		want             string
	}{
		{name: "text check", successfulWrites: 1, want: "writing check 1 text"},
		{name: "text aggregate", successfulWrites: 8, want: "writing doctor aggregate"},
		{name: "JSON aggregate", jsonOutput: true, successfulWrites: 6, want: "encoding aggregate JSON"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cmd := &cobra.Command{}
			cmd.SetOut(&failAfterWriter{successfulWrites: tc.successfulWrites})
			err := runDoctor(cmd, allPassDoctorEnv(t), doctorOpts{jsonOutput: tc.jsonOutput})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("output failure = %v, want substring %q", err, tc.want)
			}
		})
	}
}

func TestDoctorCmd_RunEHappyPath(t *testing.T) {
	orig := doctorEnvFactory
	t.Cleanup(func() { doctorEnvFactory = orig })
	doctorEnvFactory = func() *doctorEnv { return allPassDoctorEnv(t) }

	cmd := doctorCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"--url", "https://example.com/", "--json"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !strings.Contains(buf.String(), `"exit_code":0`) {
		t.Fatalf("unexpected output:\n%s", buf.String())
	}
}

func TestDoctorCmd_RejectsBadPort(t *testing.T) {
	cmd := doctorCmd()
	cmd.SetArgs([]string{"--port", "0"})
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	if err := cmd.Execute(); err == nil {
		t.Fatalf("expected error for invalid port")
	}
}

func TestCheck_SkipOnCommandMissing(t *testing.T) {
	missing := func([]string) (string, int, error) { return "bash: curl: command not found", 1, nil }
	if res := checkCurlThroughProxy(context.Background(), newDoctorEnv(t, missing)); res.status != statusSkip {
		t.Errorf("curl missing: got %q", res.status)
	}
	if res := checkDNSFailure(context.Background(), newDoctorEnv(t, missing)); res.status != statusSkip {
		t.Errorf("dns missing: got %q", res.status)
	}
	if res := checkRawEgressBlocked(context.Background(), newDoctorEnv(t, missing)); res.status != statusSkip {
		t.Errorf("rawegress missing: got %q", res.status)
	}
}

func TestCheck_LaunchError(t *testing.T) {
	boom := func([]string) (string, int, error) { return "", -1, errors.New("exec failed") }
	if res := checkPythonThroughProxy(context.Background(), newDoctorEnv(t, boom)); res.status != statusSkip {
		t.Errorf("python launch err: got %q", res.status)
	}
}

func TestCheckCurl_NoHTTPCode(t *testing.T) {
	env := newDoctorEnv(t, func([]string) (string, int, error) { return "", 0, nil })
	res := checkCurlThroughProxy(context.Background(), env)
	if res.status != statusFail || res.class != classInfra {
		t.Fatalf("got status=%q class=%q", res.status, res.class)
	}
}

func TestCheckDNSFailure_NonSuccessFallback(t *testing.T) {
	env := newDoctorEnv(t, func([]string) (string, int, error) { return "404", 0, nil })
	if res := checkDNSFailure(context.Background(), env); res.status != statusUnknown {
		t.Fatalf("unattributed 404 on nxdomain should be unknown: got %q", res.status)
	}
}

func TestCheck_UnexpectedStatusIsPolicy(t *testing.T) {
	garbled := func([]string) (string, int, error) { return "weird-output", 0, nil }
	if res := checkPythonThroughProxy(context.Background(), newDoctorEnv(t, garbled)); res.status != statusFail || res.class != classPolicy {
		t.Errorf("python garbled: status=%q class=%q", res.status, res.class)
	}
	if res := checkNodeThroughProxy(context.Background(), newDoctorEnv(t, garbled)); res.status != statusFail || res.class != classPolicy {
		t.Errorf("node garbled: status=%q class=%q", res.status, res.class)
	}
}

func TestCheckRawEgress_CompletedRequestIsHole(t *testing.T) {
	// A completed HTTP request (even a 4xx) means the agent reached the host
	// directly, so it is a containment hole, not a pass.
	env := newDoctorEnv(t, func([]string) (string, int, error) { return "403", 0, nil })
	res := checkRawEgressBlocked(context.Background(), env)
	if res.status != statusFail || res.class != classInfra {
		t.Fatalf("403 over a completed connection must be a hole: status=%q class=%q", res.status, res.class)
	}
}

func TestCheckRawEgress_AttributedDialBlockedExitsPass(t *testing.T) {
	for _, code := range []int{7, 28} {
		t.Run(strconv.Itoa(code), func(t *testing.T) {
			env := newDoctorEnv(t, func([]string) (string, int, error) {
				return "curl error\nPLK_TIME_CONNECT=0.000000\n000", code, nil
			})
			if res := checkRawEgressBlocked(context.Background(), env); res.status != statusPass {
				t.Errorf("curl exit %d plus counter delta should prove a blocked dial: got %q", code, res.status)
			}
		})
	}
}

func TestCheckRawEgress_ProbeSpecificDialAttribution(t *testing.T) {
	tests := []struct {
		name       string
		out        string
		code       int
		wantStatus string
		wantDetail string
	}{
		{
			name:       "completed dial timeout fails despite UID-wide counter delta",
			out:        "curl: (28) Operation timed out\nPLK_TIME_CONNECT=0.125381\n000",
			code:       28,
			wantStatus: statusFail,
			wantDetail: "CONTAINMENT HOLE",
		},
		{
			name:       "unknown dial timing cannot pass from UID-wide counter delta",
			out:        "curl: (7) Failed to connect\nPLK_TIME_CONNECT=unparseable\n000",
			code:       7,
			wantStatus: statusUnknown,
			wantDetail: "time_connect was missing or unparseable",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			env := newDoctorEnv(t, func([]string) (string, int, error) {
				return tc.out, tc.code, nil
			})
			res := checkRawEgressBlocked(context.Background(), env)
			if res.status != tc.wantStatus {
				t.Fatalf("status = %q, want %q (detail=%q)", res.status, tc.wantStatus, res.detail)
			}
			if !strings.Contains(res.detail, tc.wantDetail) {
				t.Fatalf("detail = %q, want substring %q", res.detail, tc.wantDetail)
			}
		})
	}
}

func TestCheckRawEgress_PostConnectExitsFailClosed(t *testing.T) {
	tests := []struct {
		name string
		code int
	}{
		{name: "TLS handshake", code: 35},
		{name: "empty reply", code: 52},
		{name: "send error", code: 55},
		{name: "receive error", code: 56},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// newDoctorEnv supplies an increasing counter. A post-connect exit
			// must still FAIL; unrelated same-UID traffic cannot convert it to PASS.
			env := newDoctorEnv(t, func([]string) (string, int, error) {
				return "curl reached peer then failed", tc.code, nil
			})
			res := checkRawEgressBlocked(context.Background(), env)
			if res.status != statusFail || res.class != classInfra {
				t.Fatalf("post-connect exit %d = status %q class %q, want fail/infra", tc.code, res.status, res.class)
			}
			if !strings.Contains(res.detail, "CONTAINMENT HOLE") {
				t.Fatalf("post-connect detail = %q, want containment-hole evidence", res.detail)
			}
		})
	}
}

func TestCheckRawEgress_UnattributableFailuresAreUnknown(t *testing.T) {
	tests := []struct {
		name  string
		out   string
		code  int
		setup func(*doctorEnv)
		want  string
	}{
		{
			name: "DNS failure cannot match literal-IP canary",
			out:  "curl failed\nPLK_TIME_CONNECT=0.000000\n000",
			code: 6,
			want: "unexpected exit 6",
		},
		{
			name: "timeout without counter delta",
			out:  "curl failed\nPLK_TIME_CONNECT=0.000000\n000",
			code: 28,
			setup: func(env *doctorEnv) {
				env.dropCounter = func(context.Context) (uint64, error) { return 12, nil }
			},
			want: "did not increase",
		},
		{
			name: "no counter reader",
			out:  "curl failed\nPLK_TIME_CONNECT=0.000000\n000",
			code: 7,
			setup: func(env *doctorEnv) {
				env.dropCounter = nil
			},
			want: "no DROP counter reader",
		},
		{
			name: "counter read fails before probe",
			out:  "curl failed\nPLK_TIME_CONNECT=0.000000\n000",
			code: 7,
			setup: func(env *doctorEnv) {
				env.dropCounter = func(context.Context) (uint64, error) {
					return 0, errors.New("operation not permitted")
				}
			},
			want: "before the probe failed",
		},
		{
			name: "counter read fails after probe",
			out:  "curl failed\nPLK_TIME_CONNECT=0.000000\n000",
			code: 7,
			setup: func(env *doctorEnv) {
				reads := 0
				env.dropCounter = func(context.Context) (uint64, error) {
					reads++
					if reads == 1 {
						return 12, nil
					}
					return 0, errors.New("table disappeared")
				}
			},
			want: "after the probe failed",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			env := newDoctorEnv(t, func([]string) (string, int, error) {
				return tc.out, tc.code, nil
			})
			if tc.setup != nil {
				tc.setup(env)
			}
			res := checkRawEgressBlocked(context.Background(), env)
			if res.status != statusUnknown || res.class != classInfra {
				t.Fatalf("unattributable failure must be unknown: status=%q class=%q", res.status, res.class)
			}
			if !strings.Contains(res.detail, tc.want) {
				t.Fatalf("detail = %q, want substring %q", res.detail, tc.want)
			}
		})
	}
}

func TestPathOrDefault_Fallbacks(t *testing.T) {
	empty := &installEnv{}
	if got := undiciShimPathOrDefault(empty); got != defaultUndiciShimPath {
		t.Errorf("shim fallback = %q", got)
	}
	if got := profileScriptPathOrDefault(empty); got != defaultProfileScriptPath {
		t.Errorf("profile fallback = %q", got)
	}
}

func TestRunDoctor_TextWithRemediationLines(t *testing.T) {
	// all-200 env: checks 1-5 pass, check 6 (raw egress) fails with a class +
	// remediation, exercising writeDoctorLine's class branch.
	env := newDoctorEnv(t, func([]string) (string, int, error) { return "200", 0, nil })
	var buf bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&buf)
	cmd.SetContext(context.Background())
	_ = runDoctor(cmd, env, doctorOpts{})
	out := buf.String()
	if !strings.Contains(out, "[FAIL]") || !strings.Contains(out, "↳ [infra]") {
		t.Fatalf("expected class-tagged remediation line:\n%s", out)
	}
}

func TestRunDoctor_TextSkipRemediation(t *testing.T) {
	// sudo refusal makes every agent check skip; the gateway check still
	// passes (fake dialer). Exercises the no-class remediation branch.
	env := newDoctorEnv(t, func([]string) (string, int, error) { return "sudo: a password is required", 1, nil })
	var buf bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&buf)
	cmd.SetContext(context.Background())
	err := runDoctor(cmd, env, doctorOpts{})
	if err == nil {
		t.Fatalf("expected skip exit error")
	}
	out := buf.String()
	if !strings.Contains(out, "[SKIP]") || !strings.Contains(out, "re-run as root") {
		t.Fatalf("expected skip remediation:\n%s", out)
	}
}

// allPassDoctorEnv returns an env whose injected runner makes every check pass:
// proxied curl/python/node return 200, the dns check's nxdomain fails cleanly,
// and direct egress is refused.
func allPassDoctorEnv(t *testing.T) *doctorEnv {
	t.Helper()
	return newDoctorEnv(t, func(args []string) (string, int, error) {
		switch {
		case argsContain(args, "--noproxy"):
			return "curl: (7) refused\nPLK_TIME_CONNECT=0.000000\n000", 7, nil // direct egress blocked
		case argsContain(args, dnsFailureHost):
			return "curl: (56) CONNECT tunnel failed, response 502\n502", 56, nil // attributed proxy DNS failure
		default:
			return "200", 0, nil // proxied curl/python/node
		}
	})
}
