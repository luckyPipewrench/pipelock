// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
)

// Test helpers ---------------------------------------------------------------

const (
	testProxyUser    = "pipelock-proxy"
	testAgentUser    = "pipelock-agent"
	testTable        = "pipelock_containment"
	testChain        = "output_filter"
	testService      = "pipelock.service"
	testSudoCmd      = "sudo"
	testOperatorUser = "operator"
	testSystemctl    = "systemctl"
	testNFT          = "nft"
	testUserDel      = "userdel"
	testRustup       = "rustup"
	testSudoNeedsPwd = "sudo: a password is required"
)

const goodNFTContainmentOutput = `table inet pipelock_containment {
	chain output_filter {
		meta skuid 987 ip daddr 127.0.0.1 tcp dport 8888 accept
		meta skuid 987 drop
	}
}
`

// fakeRunResult is a canned subprocess response keyed by the leading
// argv element (the command name). Tests pre-populate the map with
// the expected calls; unexpected calls return an error.
type fakeRunResult struct {
	stdout string
	code   int
	err    error
}

// newFakeRun returns a runCommand that matches by command name and
// optionally by argv prefix. The first matching response wins. Empty
// match means "match any argv".
type fakeMatcher struct {
	cmd    string
	prefix []string
	result fakeRunResult
}

func newFakeRun(matchers ...fakeMatcher) (runCommand, *[]string) {
	var calls []string
	matched := make([]bool, len(matchers))
	run := func(_ context.Context, name string, args ...string) (string, int, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		for i, m := range matchers {
			if m.cmd != name {
				continue
			}
			if !prefixMatches(m.prefix, args) {
				continue
			}
			matched[i] = true
			return m.result.stdout, m.result.code, m.result.err
		}
		return "", -1, fmt.Errorf("unexpected call: %s %v", name, args)
	}
	return run, &calls
}

func prefixMatches(prefix, args []string) bool {
	if len(prefix) == 0 {
		return true
	}
	if len(args) < len(prefix) {
		return false
	}
	for i, p := range prefix {
		if args[i] != p {
			return false
		}
	}
	return true
}

// makeProbeEnv builds a probeEnv with sane defaults plus overrides.
// The pure-Go probes (1, 4, 5, 6, 7) get filesystem and lookup stubs;
// the shell-out probes (2, 3, 8, 9) get runCmd.
func makeProbeEnv(t *testing.T, opts ...func(*probeEnv)) *probeEnv {
	t.Helper()
	env := &probeEnv{
		port:          8888,
		operatorUser:  "",
		proxyUserName: testProxyUser,
		agentUserName: testAgentUser,
		wrapperDir:    t.TempDir(),
		toolWrappers:  []string{"plk-claude", "plk-codex"},
		caBundlePath:  filepath.Join(t.TempDir(), "combined-ca.pem"),
		launchPath:    "", // populated below
		nftTable:      testTable,
		nftChain:      testChain,
		nftPath:       testNFT,
		serviceName:   testService,
		pinPath:       filepath.Join(t.TempDir(), "binary-pin.sha256"),
		toolsListPath: filepath.Join(t.TempDir(), "tools.list"),
		runCmd:        rejectAllRun,
		dialCtx:       rejectAllDial,
		lookupUser:    rejectAllLookup,
		stat:          os.Stat,
		readFile:      rejectAllReadFile,
		selfPath:      rejectAllSelfPath,
		hashFile:      rejectAllHashFile,
	}
	env.launchPath = filepath.Join(env.wrapperDir, "plk-launch")
	for _, opt := range opts {
		opt(env)
	}
	return env
}

func rejectAllRun(_ context.Context, name string, args ...string) (string, int, error) {
	return "", -1, fmt.Errorf("unstubbed run: %s %v", name, args)
}

func rejectAllDial(_ context.Context, _, address string, _ time.Duration) (net.Conn, error) {
	return nil, fmt.Errorf("unstubbed dial: %s", address)
}

func rejectAllLookup(name string) (*user.User, error) {
	return nil, fmt.Errorf("unstubbed lookup: %s", name)
}

func rejectAllReadFile(path string) ([]byte, error) {
	return nil, fmt.Errorf("unstubbed readFile: %s", path)
}

func rejectAllSelfPath() (string, error) {
	return "", fmt.Errorf("unstubbed selfPath")
}

func rejectAllHashFile(path string) (string, error) {
	return "", fmt.Errorf("unstubbed hashFile: %s", path)
}

// Probe 1: system_users_exist ------------------------------------------------

func TestProbeSystemUsers(t *testing.T) {
	tests := []struct {
		name       string
		proxy      *user.User
		proxyErr   error
		agent      *user.User
		agentErr   error
		wantStatus string
		wantDetail string
	}{
		{
			name:       "both present",
			proxy:      &user.User{Uid: "988", Username: testProxyUser},
			agent:      &user.User{Uid: "987", Username: testAgentUser},
			wantStatus: statusPass,
			wantDetail: "pipelock-proxy uid=988, pipelock-agent uid=987",
		},
		{
			name:       "proxy missing",
			proxyErr:   user.UnknownUserError(testProxyUser),
			agent:      &user.User{Uid: "987", Username: testAgentUser},
			wantStatus: statusFail,
			wantDetail: "pipelock-proxy missing",
		},
		{
			name:       "agent missing",
			proxy:      &user.User{Uid: "988", Username: testProxyUser},
			agentErr:   user.UnknownUserError(testAgentUser),
			wantStatus: statusFail,
			wantDetail: "pipelock-agent missing",
		},
		{
			name:       "both missing",
			proxyErr:   user.UnknownUserError(testProxyUser),
			agentErr:   user.UnknownUserError(testAgentUser),
			wantStatus: statusFail,
			wantDetail: "neither",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			env := makeProbeEnv(t, func(e *probeEnv) {
				e.lookupUser = func(name string) (*user.User, error) {
					switch name {
					case testProxyUser:
						return tc.proxy, tc.proxyErr
					case testAgentUser:
						return tc.agent, tc.agentErr
					}
					return nil, fmt.Errorf("unexpected lookup %q", name)
				}
			})
			gotStatus, gotDetail := probeSystemUsers(context.Background(), env)
			if gotStatus != tc.wantStatus {
				t.Fatalf("status: got %q, want %q (detail=%q)", gotStatus, tc.wantStatus, gotDetail)
			}
			if !strings.Contains(gotDetail, tc.wantDetail) {
				t.Fatalf("detail: got %q, want substring %q", gotDetail, tc.wantDetail)
			}
		})
	}
}

// Probe 2: pipelock_systemd_unit ---------------------------------------------

func TestProbeSystemdUnit(t *testing.T) {
	const goodOutput = "ActiveState=active\nSubState=running\nUser=pipelock-proxy\nType=simple\n"

	tests := []struct {
		name       string
		stdout     string
		code       int
		runErr     error
		wantStatus string
		wantDetail string
	}{
		{
			name:       "happy path",
			stdout:     goodOutput,
			code:       0,
			wantStatus: statusPass,
			wantDetail: "User=pipelock-proxy",
		},
		{
			name:       "wrong user",
			stdout:     "ActiveState=active\nSubState=running\nUser=root\n",
			code:       0,
			wantStatus: statusFail,
			wantDetail: "want User=pipelock-proxy",
		},
		{
			name:       "service inactive",
			stdout:     "ActiveState=inactive\nSubState=dead\nUser=pipelock-proxy\n",
			code:       0,
			wantStatus: statusFail,
			wantDetail: "want active/running",
		},
		{
			name:       "systemctl missing",
			runErr:     errors.New("exec: \"systemctl\": executable file not found in $PATH"),
			wantStatus: statusSkip,
			wantDetail: "systemctl unavailable",
		},
		{
			name:       "non-zero exit",
			stdout:     "Unit pipelock.service could not be found.\n",
			code:       1,
			wantStatus: statusFail,
			wantDetail: "systemctl exit=1",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			env := makeProbeEnv(t, func(e *probeEnv) {
				e.runCmd = func(_ context.Context, name string, _ ...string) (string, int, error) {
					if name != testSystemctl {
						return "", -1, fmt.Errorf("unexpected cmd %q", name)
					}
					return tc.stdout, tc.code, tc.runErr
				}
			})
			gotStatus, gotDetail := probeSystemdUnit(context.Background(), env)
			if gotStatus != tc.wantStatus {
				t.Fatalf("status: got %q, want %q (detail=%q)", gotStatus, tc.wantStatus, gotDetail)
			}
			if !strings.Contains(gotDetail, tc.wantDetail) {
				t.Fatalf("detail: got %q, want substring %q", gotDetail, tc.wantDetail)
			}
		})
	}
}

func TestParseSystemdShow(t *testing.T) {
	out := "ActiveState=active\nSubState=running\n\nUser=pipelock-proxy\n# comment with no =\nType=simple\n"
	got := parseSystemdShow(out)
	want := map[string]string{
		"ActiveState": "active",
		"SubState":    "running",
		"User":        "pipelock-proxy",
		"Type":        "simple",
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("key %s: got %q, want %q", k, got[k], v)
		}
	}
}

// Probe 3: nftables_containment_ruleset --------------------------------------

func TestProbeNFTContainment(t *testing.T) {
	tests := []struct {
		name       string
		stdout     string
		code       int
		runErr     error
		wantStatus string
		wantDetail string
	}{
		{
			name:       "happy path",
			stdout:     goodNFTContainmentOutput,
			code:       0,
			wantStatus: statusPass,
			wantDetail: "skuid drop rule",
		},
		{
			name:       "permission denied",
			stdout:     "Error: Operation not permitted\n",
			code:       1,
			wantStatus: statusSkip,
			wantDetail: "requires root",
		},
		{
			name:       "table missing",
			stdout:     "Error: No such file or directory\n",
			code:       1,
			wantStatus: statusFail,
			wantDetail: "not loaded",
		},
		{
			name:       "nft missing",
			runErr:     errors.New("exec: \"nft\": executable file not found"),
			wantStatus: statusSkip,
			wantDetail: "nft unavailable",
		},
		{
			name:       "chain missing",
			stdout:     "table inet pipelock_containment {\n}\n",
			code:       0,
			wantStatus: statusFail,
			wantDetail: "chain output_filter missing",
		},
		{
			name: "no skuid drop rule",
			stdout: `table inet pipelock_containment {
		chain output_filter {
			meta skuid 987 ip daddr 127.0.0.1 tcp dport 8888 accept
		}
	}
	`,
			code:       0,
			wantStatus: statusFail,
			wantDetail: "skuid-drop rule missing",
		},
		{
			name: "broad loopback accept",
			stdout: `table inet pipelock_containment {
		chain output_filter {
			meta oif "lo" accept
			meta skuid 987 ip daddr 127.0.0.1 tcp dport 8888 accept
			meta skuid 987 drop
		}
	}
	`,
			code:       0,
			wantStatus: statusFail,
			wantDetail: "broad loopback accept",
		},
		{
			name: "missing proxy port allow",
			stdout: `table inet pipelock_containment {
		chain output_filter {
			meta skuid 987 drop
		}
	}
	`,
			code:       0,
			wantStatus: statusFail,
			wantDetail: "loopback allow",
		},
		{
			name: "skuid and drop outside target chain",
			stdout: `table inet pipelock_containment {
		chain output_filter {
			meta skuid 987 ip daddr 127.0.0.1 tcp dport 8888 accept
		}
		chain decoy {
			meta skuid 987 drop
	}
}
`,
			code:       0,
			wantStatus: statusFail,
			wantDetail: "skuid-drop rule missing",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			env := makeProbeEnv(t, func(e *probeEnv) {
				e.runCmd = func(_ context.Context, _ string, _ ...string) (string, int, error) {
					return tc.stdout, tc.code, tc.runErr
				}
			})
			gotStatus, gotDetail := probeNFTContainment(context.Background(), env)
			if gotStatus != tc.wantStatus {
				t.Fatalf("status: got %q, want %q (detail=%q)", gotStatus, tc.wantStatus, gotDetail)
			}
			if !strings.Contains(gotDetail, tc.wantDetail) {
				t.Fatalf("detail: got %q, want substring %q", gotDetail, tc.wantDetail)
			}
		})
	}
}

func TestProbeNFTContainment_ChecksPersistenceUnit(t *testing.T) {
	tests := []struct {
		name       string
		unitBody   func(string) string
		wantStatus string
		wantDetail string
	}{
		{
			name: "exec start points at managed rules",
			unitBody: func(rulesPath string) string {
				return "[Service]\nExecStart=/usr/sbin/nft -f " + rulesPath + "\n"
			},
			wantStatus: statusPass,
			wantDetail: "persistence unit",
		},
		{
			name: "exec start points elsewhere",
			unitBody: func(_ string) string {
				return "[Service]\nExecStart=/usr/sbin/nft -f /other/rules.nft\n"
			},
			wantStatus: statusFail,
			wantDetail: "missing ExecStart",
		},
		{
			name: "rules path outside exec start does not satisfy check",
			unitBody: func(rulesPath string) string {
				return "[Unit]\nConditionPathExists=" + rulesPath + "\n[Service]\nExecStart=/usr/sbin/nft -f /other/rules.nft\n"
			},
			wantStatus: statusFail,
			wantDetail: "missing ExecStart",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tmp := t.TempDir()
			unitPath := filepath.Join(tmp, "pipelock-containment-nft.service")
			rulesPath := filepath.Join(tmp, "50-pipelock-containment.nft")
			if err := os.WriteFile(unitPath, []byte(tc.unitBody(rulesPath)), 0o600); err != nil {
				t.Fatalf("write persistence unit: %v", err)
			}
			env := makeProbeEnv(t, func(e *probeEnv) {
				e.nftRulesPath = rulesPath
				e.nftPersistUnitPath = unitPath
				e.readFile = os.ReadFile
				e.runCmd = func(_ context.Context, _ string, _ ...string) (string, int, error) {
					return goodNFTContainmentOutput, 0, nil
				}
			})
			gotStatus, gotDetail := probeNFTContainment(context.Background(), env)
			if gotStatus != tc.wantStatus {
				t.Fatalf("status: got %q, want %q (detail=%q)", gotStatus, tc.wantStatus, gotDetail)
			}
			if !strings.Contains(gotDetail, tc.wantDetail) {
				t.Fatalf("detail: got %q, want substring %q", gotDetail, tc.wantDetail)
			}
		})
	}
}

// Probe 4: wrapper_scripts_installed -----------------------------------------

func TestProbeWrapperScripts(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		env := makeProbeEnv(t)
		writeFakeWrapper(t, env.launchPath, 0o755)
		writeFakeWrapper(t, filepath.Join(env.wrapperDir, "plk"), 0o755)
		writeFakeWrapper(t, filepath.Join(env.wrapperDir, "plk-claude"), 0o755)
		gotStatus, gotDetail := probeWrapperScripts(context.Background(), env)
		if gotStatus != statusPass {
			t.Fatalf("status: got %q, want pass (detail=%q)", gotStatus, gotDetail)
		}
		if !strings.Contains(gotDetail, "plk-claude") {
			t.Fatalf("detail: got %q, want substring plk-claude", gotDetail)
		}
	})

	t.Run("launcher missing", func(t *testing.T) {
		env := makeProbeEnv(t)
		gotStatus, gotDetail := probeWrapperScripts(context.Background(), env)
		if gotStatus != statusFail {
			t.Fatalf("status: got %q, want fail (detail=%q)", gotStatus, gotDetail)
		}
		if !strings.Contains(gotDetail, "plk-launch") {
			t.Fatalf("detail: got %q, want plk-launch", gotDetail)
		}
	})

	t.Run("launcher wrong mode", func(t *testing.T) {
		env := makeProbeEnv(t)
		writeFakeWrapper(t, env.launchPath, 0o600)
		gotStatus, gotDetail := probeWrapperScripts(context.Background(), env)
		if gotStatus != statusFail {
			t.Fatalf("status: got %q, want fail (detail=%q)", gotStatus, gotDetail)
		}
		if !strings.Contains(gotDetail, "perm") {
			t.Fatalf("detail: got %q, want substring perm", gotDetail)
		}
	})

	t.Run("meta wrapper missing", func(t *testing.T) {
		env := makeProbeEnv(t)
		writeFakeWrapper(t, env.launchPath, 0o755)
		writeFakeWrapper(t, filepath.Join(env.wrapperDir, "plk-claude"), 0o755)
		gotStatus, gotDetail := probeWrapperScripts(context.Background(), env)
		if gotStatus != statusFail {
			t.Fatalf("status: got %q, want fail (detail=%q)", gotStatus, gotDetail)
		}
		if !strings.Contains(gotDetail, filepath.Join(env.wrapperDir, "plk")) {
			t.Fatalf("detail: got %q, want plk meta wrapper", gotDetail)
		}
	})

	t.Run("no tool wrappers", func(t *testing.T) {
		env := makeProbeEnv(t)
		writeFakeWrapper(t, env.launchPath, 0o755)
		writeFakeWrapper(t, filepath.Join(env.wrapperDir, "plk"), 0o755)
		gotStatus, gotDetail := probeWrapperScripts(context.Background(), env)
		if gotStatus != statusFail {
			t.Fatalf("status: got %q, want fail (detail=%q)", gotStatus, gotDetail)
		}
		if !strings.Contains(gotDetail, "no tool wrappers") {
			t.Fatalf("detail: got %q, want substring 'no tool wrappers'", gotDetail)
		}
	})

	t.Run("tool wrapper wrong mode", func(t *testing.T) {
		env := makeProbeEnv(t)
		writeFakeWrapper(t, env.launchPath, 0o755)
		writeFakeWrapper(t, filepath.Join(env.wrapperDir, "plk"), 0o755)
		writeFakeWrapper(t, filepath.Join(env.wrapperDir, "plk-claude"), 0o644)
		gotStatus, gotDetail := probeWrapperScripts(context.Background(), env)
		if gotStatus != statusFail {
			t.Fatalf("status: got %q, want fail (detail=%q)", gotStatus, gotDetail)
		}
		if !strings.Contains(gotDetail, "want 0o755") {
			t.Fatalf("detail: got %q, want wrapper mode failure", gotDetail)
		}
	})

	t.Run("uses wrapper inventory when present", func(t *testing.T) {
		env := makeProbeEnv(t)
		env.wrapperInvPath = filepath.Join(t.TempDir(), "wrappers.json")
		env.readFile = os.ReadFile
		writeFakeWrapper(t, env.launchPath, 0o755)
		writeFakeWrapper(t, filepath.Join(env.wrapperDir, "plk"), 0o755)
		writeFakeWrapper(t, filepath.Join(env.wrapperDir, "plk-rustup"), 0o755)
		body, err := json.Marshal(wrapperInventory{Wrappers: []string{"plk-rustup"}})
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if err := os.WriteFile(env.wrapperInvPath, append(body, '\n'), 0o600); err != nil {
			t.Fatalf("write inventory: %v", err)
		}

		gotStatus, gotDetail := probeWrapperScripts(context.Background(), env)
		if gotStatus != statusPass {
			t.Fatalf("status: got %q, want pass (detail=%q)", gotStatus, gotDetail)
		}
		if !strings.Contains(gotDetail, "plk-rustup") {
			t.Fatalf("detail: got %q, want custom wrapper", gotDetail)
		}
	})

	t.Run("malformed wrapper inventory fails", func(t *testing.T) {
		env := makeProbeEnv(t)
		env.wrapperInvPath = filepath.Join(t.TempDir(), "wrappers.json")
		env.readFile = os.ReadFile
		writeFakeWrapper(t, env.launchPath, 0o755)
		writeFakeWrapper(t, filepath.Join(env.wrapperDir, "plk"), 0o755)
		if err := os.WriteFile(env.wrapperInvPath, []byte("{"), 0o600); err != nil {
			t.Fatalf("write inventory: %v", err)
		}

		gotStatus, gotDetail := probeWrapperScripts(context.Background(), env)
		if gotStatus != statusFail {
			t.Fatalf("status: got %q, want fail (detail=%q)", gotStatus, gotDetail)
		}
		if !strings.Contains(gotDetail, "parse wrapper inventory") {
			t.Fatalf("detail: got %q, want parse failure", gotDetail)
		}
	})

	t.Run("empty wrapper inventory entry fails", func(t *testing.T) {
		env := makeProbeEnv(t)
		env.wrapperInvPath = filepath.Join(t.TempDir(), "wrappers.json")
		env.readFile = os.ReadFile
		writeFakeWrapper(t, env.launchPath, 0o755)
		writeFakeWrapper(t, filepath.Join(env.wrapperDir, "plk"), 0o755)
		body, err := json.Marshal(wrapperInventory{Wrappers: []string{""}})
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if err := os.WriteFile(env.wrapperInvPath, append(body, '\n'), 0o600); err != nil {
			t.Fatalf("write inventory: %v", err)
		}

		gotStatus, gotDetail := probeWrapperScripts(context.Background(), env)
		if gotStatus != statusFail {
			t.Fatalf("status: got %q, want fail (detail=%q)", gotStatus, gotDetail)
		}
		if !strings.Contains(gotDetail, "empty wrapper name") {
			t.Fatalf("detail: got %q, want empty wrapper failure", gotDetail)
		}
	})

	t.Run("directory wrapper inventory entry fails", func(t *testing.T) {
		env := makeProbeEnv(t)
		env.wrapperInvPath = filepath.Join(t.TempDir(), "wrappers.json")
		env.readFile = os.ReadFile
		writeFakeWrapper(t, env.launchPath, 0o755)
		writeFakeWrapper(t, filepath.Join(env.wrapperDir, "plk"), 0o755)
		dirWrapper := filepath.Join(env.wrapperDir, "plk-dir")
		if err := os.Mkdir(dirWrapper, 0o750); err != nil {
			t.Fatalf("mkdir wrapper dir: %v", err)
		}
		body, err := json.Marshal(wrapperInventory{Wrappers: []string{"plk-dir"}})
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if err := os.WriteFile(env.wrapperInvPath, append(body, '\n'), 0o600); err != nil {
			t.Fatalf("write inventory: %v", err)
		}

		gotStatus, gotDetail := probeWrapperScripts(context.Background(), env)
		if gotStatus != statusFail {
			t.Fatalf("status: got %q, want fail (detail=%q)", gotStatus, gotDetail)
		}
		if !strings.Contains(gotDetail, "non-empty executable wrapper file") {
			t.Fatalf("detail: got %q, want regular-file failure", gotDetail)
		}
	})

	t.Run("empty wrapper file fails", func(t *testing.T) {
		env := makeProbeEnv(t)
		env.wrapperInvPath = filepath.Join(t.TempDir(), "wrappers.json")
		env.readFile = os.ReadFile
		writeFakeWrapper(t, env.launchPath, 0o755)
		writeFakeWrapper(t, filepath.Join(env.wrapperDir, "plk"), 0o755)
		emptyWrapper := filepath.Join(env.wrapperDir, "plk-empty")
		if err := os.WriteFile(emptyWrapper, nil, 0o755); err != nil { //nolint:gosec // executable mode mirrors production wrapper contract.
			t.Fatalf("write empty wrapper: %v", err)
		}
		body, err := json.Marshal(wrapperInventory{Wrappers: []string{"plk-empty"}})
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if err := os.WriteFile(env.wrapperInvPath, append(body, '\n'), 0o600); err != nil {
			t.Fatalf("write inventory: %v", err)
		}

		gotStatus, gotDetail := probeWrapperScripts(context.Background(), env)
		if gotStatus != statusFail {
			t.Fatalf("status: got %q, want fail (detail=%q)", gotStatus, gotDetail)
		}
		if !strings.Contains(gotDetail, "non-empty executable wrapper file") {
			t.Fatalf("detail: got %q, want empty wrapper failure", gotDetail)
		}
	})
}

func writeFakeWrapper(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	body := []byte("#!/bin/bash\nexit 0\n")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatalf("chmod %s: %v", path, err)
	}
}

// Probe 5: ca_bundle_present --------------------------------------------------

func TestProbeCABundle(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		env := makeProbeEnv(t)
		writeFakePEMBundle(t, env.caBundlePath, "Pipelock Test CA", "Some Other Root")
		gotStatus, gotDetail := probeCABundle(context.Background(), env)
		if gotStatus != statusPass {
			t.Fatalf("status: got %q, want pass (detail=%q)", gotStatus, gotDetail)
		}
		if !strings.Contains(gotDetail, "Pipelock Test CA") {
			t.Fatalf("detail: got %q, want substring 'Pipelock Test CA'", gotDetail)
		}
	})

	t.Run("file missing", func(t *testing.T) {
		env := makeProbeEnv(t)
		gotStatus, gotDetail := probeCABundle(context.Background(), env)
		if gotStatus != statusFail {
			t.Fatalf("status: got %q, want fail", gotStatus)
		}
		if !strings.Contains(gotDetail, "read") {
			t.Fatalf("detail: got %q, want substring 'read'", gotDetail)
		}
	})

	t.Run("no pipelock cert", func(t *testing.T) {
		env := makeProbeEnv(t)
		writeFakePEMBundle(t, env.caBundlePath, "Some Other Root")
		gotStatus, gotDetail := probeCABundle(context.Background(), env)
		if gotStatus != statusFail {
			t.Fatalf("status: got %q, want fail", gotStatus)
		}
		if !strings.Contains(gotDetail, "none match Pipelock") {
			t.Fatalf("detail: got %q, want substring 'none match Pipelock'", gotDetail)
		}
	})

	t.Run("empty file", func(t *testing.T) {
		env := makeProbeEnv(t)
		if err := os.WriteFile(env.caBundlePath, []byte{}, 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		gotStatus, _ := probeCABundle(context.Background(), env)
		if gotStatus != statusFail {
			t.Fatalf("status: got %q, want fail", gotStatus)
		}
	})

	t.Run("malformed pem", func(t *testing.T) {
		env := makeProbeEnv(t)
		// Wrap garbage in a PEM envelope so the decoder consumes a block
		// whose Bytes are not a valid DER certificate.
		bad := []byte("-----BEGIN CERTIFICATE-----\nbm90YWNlcnQ=\n-----END CERTIFICATE-----\n")
		if err := os.WriteFile(env.caBundlePath, bad, 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		gotStatus, gotDetail := probeCABundle(context.Background(), env)
		if gotStatus != statusFail {
			t.Fatalf("status: got %q, want fail (detail=%q)", gotStatus, gotDetail)
		}
		if !strings.Contains(gotDetail, "parse") {
			t.Fatalf("detail: got %q, want substring 'parse'", gotDetail)
		}
	})
}

// writeFakePEMBundle generates one self-signed cert per CN and writes
// the concatenated PEM to path.
func writeFakePEMBundle(t *testing.T, path string, commonNames ...string) {
	t.Helper()
	var buf bytes.Buffer
	for _, cn := range commonNames {
		buf.Write(makeFakeCertPEM(t, cn))
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
}

func makeFakeCertPEM(t *testing.T, commonName string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// Probe 6: pipelock_listening_loopback ---------------------------------------

func TestProbeLoopbackListen(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		env := makeProbeEnv(t, func(e *probeEnv) {
			e.dialCtx = func(_ context.Context, _, _ string, _ time.Duration) (net.Conn, error) {
				return &fakeConn{}, nil
			}
		})
		gotStatus, gotDetail := probeLoopbackListen(context.Background(), env)
		if gotStatus != statusPass {
			t.Fatalf("status: got %q, want pass (detail=%q)", gotStatus, gotDetail)
		}
		if !strings.Contains(gotDetail, "127.0.0.1:8888") {
			t.Fatalf("detail: got %q, want substring 127.0.0.1:8888", gotDetail)
		}
	})

	t.Run("dial refused", func(t *testing.T) {
		env := makeProbeEnv(t, func(e *probeEnv) {
			e.dialCtx = func(_ context.Context, _, _ string, _ time.Duration) (net.Conn, error) {
				return nil, errors.New("connection refused")
			}
		})
		gotStatus, gotDetail := probeLoopbackListen(context.Background(), env)
		if gotStatus != statusFail {
			t.Fatalf("status: got %q, want fail", gotStatus)
		}
		if !strings.Contains(gotDetail, "refused") {
			t.Fatalf("detail: got %q, want substring refused", gotDetail)
		}
	})
}

// fakeConn implements net.Conn for probe 6's dial stub.
type fakeConn struct{}

func (*fakeConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (*fakeConn) Write(b []byte) (int, error)      { return len(b), nil }
func (*fakeConn) Close() error                     { return nil }
func (*fakeConn) LocalAddr() net.Addr              { return nil }
func (*fakeConn) RemoteAddr() net.Addr             { return nil }
func (*fakeConn) SetDeadline(time.Time) error      { return nil }
func (*fakeConn) SetReadDeadline(time.Time) error  { return nil }
func (*fakeConn) SetWriteDeadline(time.Time) error { return nil }

// Probe 7: no_proxy_env_correct ----------------------------------------------

func TestProbeNoProxyEnv(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		env := makeProbeEnv(t)
		body := "#!/bin/bash\nexec env NO_PROXY=127.0.0.1,localhost,::1 HTTPS_PROXY=http://127.0.0.1:8888 sh\n"
		if err := os.WriteFile(env.launchPath, []byte(body), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		gotStatus, gotDetail := probeNoProxyEnv(context.Background(), env)
		if gotStatus != statusPass {
			t.Fatalf("status: got %q, want pass (detail=%q)", gotStatus, gotDetail)
		}
		if !strings.Contains(gotDetail, "127.0.0.1,localhost") {
			t.Fatalf("detail: got %q, want substring 127.0.0.1,localhost", gotDetail)
		}
	})

	t.Run("wrong value", func(t *testing.T) {
		env := makeProbeEnv(t)
		body := "#!/bin/bash\nexec env NO_PROXY=127.0.0.1,localhost,10.0.0.0/24 sh\n"
		if err := os.WriteFile(env.launchPath, []byte(body), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		gotStatus, gotDetail := probeNoProxyEnv(context.Background(), env)
		if gotStatus != statusFail {
			t.Fatalf("status: got %q, want fail (detail=%q)", gotStatus, gotDetail)
		}
		if !strings.Contains(gotDetail, "differs from policy") {
			t.Fatalf("detail: got %q, want substring 'differs from policy'", gotDetail)
		}
	})

	t.Run("no assignment", func(t *testing.T) {
		env := makeProbeEnv(t)
		body := "#!/bin/bash\nexec env HTTPS_PROXY=http://127.0.0.1:8888 sh\n"
		if err := os.WriteFile(env.launchPath, []byte(body), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		gotStatus, gotDetail := probeNoProxyEnv(context.Background(), env)
		if gotStatus != statusFail {
			t.Fatalf("status: got %q, want fail", gotStatus)
		}
		if !strings.Contains(gotDetail, "not found") {
			t.Fatalf("detail: got %q, want substring 'not found'", gotDetail)
		}
	})

	t.Run("file missing", func(t *testing.T) {
		env := makeProbeEnv(t)
		gotStatus, _ := probeNoProxyEnv(context.Background(), env)
		if gotStatus != statusFail {
			t.Fatalf("status: got %q, want fail", gotStatus)
		}
	})
}

func TestExtractNoProxy(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"NO_PROXY=127.0.0.1,localhost foo bar", "NO_PROXY=127.0.0.1,localhost"},
		{"    NO_PROXY=a,b \\", "NO_PROXY=a,b"},
		{"no NO_PROXY here\nHTTPS_PROXY=x", ""},
		{"first\nNO_PROXY=x\nNO_PROXY=y\n", "NO_PROXY=x"},
		{"# NO_PROXY=127.0.0.1,localhost\nHTTPS_PROXY=x", ""},
		{"OTHER_NO_PROXY=127.0.0.1,localhost\nNO_PROXY=x", "NO_PROXY=x"},
	}
	for _, c := range cases {
		got := extractNoProxy([]byte(c.in))
		if got != c.want {
			t.Errorf("extractNoProxy(%q): got %q, want %q", c.in, got, c.want)
		}
	}
}

// Probe 8 + 9: egress canary + operator reachability -------------------------

func TestProbeCCAgentEgressDenied(t *testing.T) {
	tests := []struct {
		name       string
		stdout     string
		code       int
		runErr     error
		curlPath   string
		wantStatus string
		wantDetail string
	}{
		{
			name:       "egress blocked (curl exit 7)",
			stdout:     "curl: (7) Failed to connect",
			code:       7,
			wantStatus: statusPass,
			wantDetail: "containment enforced",
		},
		{
			name:       "egress succeeded (regression)",
			stdout:     "200",
			code:       0,
			wantStatus: statusFail,
			wantDetail: "unexpected curl success",
		},
		{
			name:       "sudo no password",
			stdout:     testSudoNeedsPwd + "\n",
			code:       1,
			wantStatus: statusSkip,
			wantDetail: "configure NOPASSWD",
		},
		{
			name:       "sudo no tty",
			stdout:     "sudo: no tty present and no askpass program specified\n",
			code:       1,
			wantStatus: statusSkip,
			wantDetail: "configure NOPASSWD",
		},
		{
			name:       "sudo not in sudoers",
			stdout:     "user operator may not run sudo on host\n",
			code:       1,
			wantStatus: statusSkip,
			wantDetail: "configure NOPASSWD",
		},
		{
			name:       "binary missing",
			runErr:     errors.New("exec: \"sudo\": executable file not found"),
			wantStatus: statusSkip,
			wantDetail: "sudo/curl unavailable",
		},
		{
			name:       "pipelock-agent user missing",
			stdout:     "sudo: unknown user pipelock-agent\nsudo: error initializing audit plugin sudoers_audit\n",
			code:       1,
			wantStatus: statusSkip,
			wantDetail: "install containment model first",
		},
		{
			name:       "target curl missing",
			stdout:     "sudo: /custom/bin/curl: command not found\n",
			code:       1,
			curlPath:   "/custom/bin/curl",
			wantStatus: statusSkip,
			wantDetail: "sudo could not execute /custom/bin/curl",
		},
		{
			name:       "fallback curl missing",
			stdout:     "sudo: /usr/bin/curl: command not found\n",
			code:       1,
			curlPath:   "",
			wantStatus: statusSkip,
			wantDetail: "sudo could not execute /usr/bin/curl",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			env := makeProbeEnv(t, func(e *probeEnv) {
				e.curlPath = tc.curlPath
				e.runCmd = func(_ context.Context, name string, args ...string) (string, int, error) {
					if name != testSudoCmd {
						t.Fatalf("unexpected cmd %q", name)
					}
					// Sanity: confirm we drop to pipelock-agent.
					joined := strings.Join(args, " ")
					if !strings.Contains(joined, "-u "+testAgentUser) {
						t.Fatalf("argv missing -u %s: %v", testAgentUser, args)
					}
					return tc.stdout, tc.code, tc.runErr
				}
			})
			gotStatus, gotDetail := probeCCAgentEgressDenied(context.Background(), env)
			if gotStatus != tc.wantStatus {
				t.Fatalf("status: got %q, want %q (detail=%q)", gotStatus, tc.wantStatus, gotDetail)
			}
			if !strings.Contains(gotDetail, tc.wantDetail) {
				t.Fatalf("detail: got %q, want substring %q", gotDetail, tc.wantDetail)
			}
		})
	}
}

func TestProbeOperatorEgress(t *testing.T) {
	t.Run("operator reachable via sudo", func(t *testing.T) {
		env := makeProbeEnv(t, func(e *probeEnv) {
			e.operatorUser = testOperatorUser
			e.runCmd = func(_ context.Context, name string, args ...string) (string, int, error) {
				if name != testSudoCmd {
					t.Fatalf("unexpected cmd %q", name)
				}
				if !strings.Contains(strings.Join(args, " "), "-u "+testOperatorUser) {
					t.Fatalf("argv missing -u %s: %v", testOperatorUser, args)
				}
				return "200", 0, nil
			}
		})
		gotStatus, gotDetail := probeOperatorEgress(context.Background(), env)
		if gotStatus != statusPass {
			t.Fatalf("status: got %q, want pass (detail=%q)", gotStatus, gotDetail)
		}
		if !strings.Contains(gotDetail, "HTTP 200") {
			t.Fatalf("detail: got %q, want HTTP 200", gotDetail)
		}
	})

	t.Run("not running under sudo: invoke curl directly", func(t *testing.T) {
		env := makeProbeEnv(t, func(e *probeEnv) {
			e.operatorUser = ""
			e.runCmd = func(_ context.Context, name string, _ ...string) (string, int, error) {
				if name != curlPath {
					t.Fatalf("expected direct curl invoke, got %q", name)
				}
				return "200", 0, nil
			}
		})
		gotStatus, _ := probeOperatorEgress(context.Background(), env)
		if gotStatus != statusPass {
			t.Fatalf("status: got %q, want pass", gotStatus)
		}
	})

	t.Run("operator unreachable", func(t *testing.T) {
		env := makeProbeEnv(t, func(e *probeEnv) {
			e.operatorUser = testOperatorUser
			e.runCmd = func(_ context.Context, _ string, _ ...string) (string, int, error) {
				return "curl: (6) Could not resolve host", 6, nil
			}
		})
		gotStatus, gotDetail := probeOperatorEgress(context.Background(), env)
		if gotStatus != statusFail {
			t.Fatalf("status: got %q, want fail (detail=%q)", gotStatus, gotDetail)
		}
		if !strings.Contains(gotDetail, "operator curl failed") {
			t.Fatalf("detail: got %q, want 'operator curl failed'", gotDetail)
		}
	})

	t.Run("sudo refusal -> skip", func(t *testing.T) {
		env := makeProbeEnv(t, func(e *probeEnv) {
			e.operatorUser = testOperatorUser
			e.runCmd = func(_ context.Context, _ string, _ ...string) (string, int, error) {
				return testSudoNeedsPwd, 1, nil
			}
		})
		gotStatus, _ := probeOperatorEgress(context.Background(), env)
		if gotStatus != statusSkip {
			t.Fatalf("status: got %q, want skip", gotStatus)
		}
	})

	t.Run("operator user missing -> skip", func(t *testing.T) {
		env := makeProbeEnv(t, func(e *probeEnv) {
			e.operatorUser = "ghost"
			e.runCmd = func(_ context.Context, _ string, _ ...string) (string, int, error) {
				return "sudo: unknown user ghost", 1, nil
			}
		})
		gotStatus, gotDetail := probeOperatorEgress(context.Background(), env)
		if gotStatus != statusSkip {
			t.Fatalf("status: got %q, want skip (detail=%q)", gotStatus, gotDetail)
		}
		if !strings.Contains(gotDetail, "ghost") {
			t.Fatalf("detail: got %q, want substring 'ghost'", gotDetail)
		}
	})

	t.Run("operator sudo target curl missing -> skip", func(t *testing.T) {
		env := makeProbeEnv(t, func(e *probeEnv) {
			e.operatorUser = testOperatorUser
			e.runCmd = func(_ context.Context, _ string, _ ...string) (string, int, error) {
				return "sudo: /usr/bin/curl: No such file or directory", 1, nil
			}
		})
		gotStatus, gotDetail := probeOperatorEgress(context.Background(), env)
		if gotStatus != statusSkip {
			t.Fatalf("status: got %q, want skip (detail=%q)", gotStatus, gotDetail)
		}
		if !strings.Contains(gotDetail, "curl not executable") {
			t.Fatalf("detail: got %q, want curl not executable", gotDetail)
		}
	})

	t.Run("operator HTTP 503 -> fail", func(t *testing.T) {
		// curl with -w '%{http_code}' exits 0 even on 5xx; a captive
		// portal or carrier intercept must not look like
		// "operator reachable".
		env := makeProbeEnv(t, func(e *probeEnv) {
			e.operatorUser = testOperatorUser
			e.runCmd = func(_ context.Context, _ string, _ ...string) (string, int, error) {
				return "503", 0, nil
			}
		})
		gotStatus, gotDetail := probeOperatorEgress(context.Background(), env)
		if gotStatus != statusFail {
			t.Fatalf("status: got %q, want fail (detail=%q)", gotStatus, gotDetail)
		}
		if !strings.Contains(gotDetail, "non-2xx/3xx HTTP 503") {
			t.Fatalf("detail: got %q, want substring 'non-2xx/3xx HTTP 503'", gotDetail)
		}
	})

	t.Run("operator HTTP 301 -> pass (redirect counts as reachable)", func(t *testing.T) {
		env := makeProbeEnv(t, func(e *probeEnv) {
			e.operatorUser = testOperatorUser
			e.runCmd = func(_ context.Context, _ string, _ ...string) (string, int, error) {
				return "301", 0, nil
			}
		})
		gotStatus, gotDetail := probeOperatorEgress(context.Background(), env)
		if gotStatus != statusPass {
			t.Fatalf("status: got %q, want pass (detail=%q)", gotStatus, gotDetail)
		}
		if !strings.Contains(gotDetail, "HTTP 301") {
			t.Fatalf("detail: got %q, want HTTP 301", gotDetail)
		}
	})

	t.Run("operator empty output -> fail", func(t *testing.T) {
		env := makeProbeEnv(t, func(e *probeEnv) {
			e.operatorUser = testOperatorUser
			e.runCmd = func(_ context.Context, _ string, _ ...string) (string, int, error) {
				// Empty stdout but exit 0 - pathological but
				// catchable.
				return "", 0, nil
			}
		})
		gotStatus, gotDetail := probeOperatorEgress(context.Background(), env)
		if gotStatus != statusFail {
			t.Fatalf("status: got %q, want fail (detail=%q)", gotStatus, gotDetail)
		}
		if !strings.Contains(gotDetail, "no output") {
			t.Fatalf("detail: got %q, want substring 'no output'", gotDetail)
		}
	})

	t.Run("operator stderr noise prefix -> pass", func(t *testing.T) {
		// realRunCommand merges stdout+stderr; benign sudo/PAM warnings
		// can land in front of curl's HTTP code. The last whitespace-
		// separated token is what `-w '%{http_code}'` printed.
		env := makeProbeEnv(t, func(e *probeEnv) {
			e.operatorUser = testOperatorUser
			e.runCmd = func(_ context.Context, _ string, _ ...string) (string, int, error) {
				return "sudo: setrlimit(RLIMIT_CORE): Operation not permitted 200", 0, nil
			}
		})
		gotStatus, gotDetail := probeOperatorEgress(context.Background(), env)
		if gotStatus != statusPass {
			t.Fatalf("status: got %q, want pass (detail=%q)", gotStatus, gotDetail)
		}
		if !strings.Contains(gotDetail, "HTTP 200") {
			t.Fatalf("detail: got %q, want substring 'HTTP 200'", gotDetail)
		}
	})

	t.Run("operator non-numeric last token -> fail", func(t *testing.T) {
		env := makeProbeEnv(t, func(e *probeEnv) {
			e.operatorUser = testOperatorUser
			e.runCmd = func(_ context.Context, _ string, _ ...string) (string, int, error) {
				return "curl: warning something something garbage", 0, nil
			}
		})
		gotStatus, gotDetail := probeOperatorEgress(context.Background(), env)
		if gotStatus != statusFail {
			t.Fatalf("status: got %q, want fail (detail=%q)", gotStatus, gotDetail)
		}
		if !strings.Contains(gotDetail, "unparseable") {
			t.Fatalf("detail: got %q, want substring 'unparseable'", gotDetail)
		}
	})
}

func TestCappedBuffer(t *testing.T) {
	t.Run("under cap", func(t *testing.T) {
		b := newCappedBuffer(100)
		n, err := b.Write([]byte("hello"))
		if err != nil || n != 5 {
			t.Fatalf("Write returned n=%d err=%v", n, err)
		}
		if b.String() != "hello" {
			t.Errorf("got %q, want hello", b.String())
		}
	})

	t.Run("over cap silently drops, Write reports full length", func(t *testing.T) {
		b := newCappedBuffer(5)
		n, err := b.Write([]byte("hello world"))
		if err != nil {
			t.Fatalf("Write returned err=%v", err)
		}
		if n != 11 {
			t.Errorf("Write reported n=%d, want 11 (never backpressure subprocess)", n)
		}
		if b.String() != "hello" {
			t.Errorf("buffered %q, want first 5 bytes 'hello'", b.String())
		}
	})

	t.Run("multiple writes accumulate to cap", func(t *testing.T) {
		b := newCappedBuffer(7)
		_, _ = b.Write([]byte("abc"))
		_, _ = b.Write([]byte("defgh"))   // 5 bytes, only 4 fit
		_, _ = b.Write([]byte("ignored")) // cap is full, dropped
		if got := b.String(); got != "abcdefg" {
			t.Errorf("got %q, want abcdefg", got)
		}
	})

	t.Run("zero cap accumulates nothing", func(t *testing.T) {
		b := newCappedBuffer(0)
		n, _ := b.Write([]byte("noise"))
		if n != 5 {
			t.Errorf("Write reported n=%d, want 5", n)
		}
		if b.String() != "" {
			t.Errorf("got %q, want empty", b.String())
		}
	})
}

// Runner ---------------------------------------------------------------------

func TestRunVerify_TextOutput_AllPass(t *testing.T) {
	env := allPassEnv(t)
	cmd := newVerifyCmd(t)
	var buf bytes.Buffer
	cmd.SetOut(&buf)

	err := runVerify(cmd, env, verifyOpts{jsonOutput: false})
	if err != nil {
		t.Fatalf("runVerify returned err: %v", err)
	}

	out := buf.String()
	if !strings.HasPrefix(out, "pipelock contain verify") {
		t.Errorf("missing header: %q", out)
	}
	if strings.Count(out, "[PASS]") != 12 {
		t.Errorf("want 12 [PASS] lines, got %d in %q", strings.Count(out, "[PASS]"), out)
	}
	if !strings.Contains(out, "12 PASS / 0 FAIL / 0 SKIP") {
		t.Errorf("missing aggregate: %q", out)
	}
}

func TestRunVerify_JSONOutput_AllPass(t *testing.T) {
	env := allPassEnv(t)
	cmd := newVerifyCmd(t)
	var buf bytes.Buffer
	cmd.SetOut(&buf)

	err := runVerify(cmd, env, verifyOpts{jsonOutput: true})
	if err != nil {
		t.Fatalf("runVerify returned err: %v", err)
	}

	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != 13 {
		t.Fatalf("expected 13 JSON records (12 probes + aggregate), got %d: %q", len(lines), buf.String())
	}
	for i := 0; i < 12; i++ {
		var rec probeRecord
		if err := json.Unmarshal([]byte(lines[i]), &rec); err != nil {
			t.Fatalf("line %d: parse: %v (line=%q)", i, err, lines[i])
		}
		if rec.Probe != i+1 {
			t.Errorf("line %d: probe=%d, want %d", i, rec.Probe, i+1)
		}
		if rec.Status != statusPass {
			t.Errorf("line %d: status=%q, want pass", i, rec.Status)
		}
	}
	var agg aggregateRecord
	if err := json.Unmarshal([]byte(lines[12]), &agg); err != nil {
		t.Fatalf("aggregate: parse: %v (line=%q)", err, lines[12])
	}
	if agg.Aggregate.Pass != 12 || agg.Aggregate.Fail != 0 || agg.Aggregate.Skip != 0 {
		t.Errorf("aggregate counts: %+v", agg.Aggregate)
	}
	if agg.Aggregate.ExitCode != cliutil.ExitOK {
		t.Errorf("aggregate exit_code: got %d, want %d", agg.Aggregate.ExitCode, cliutil.ExitOK)
	}
}

func TestRunVerify_FailExitCode(t *testing.T) {
	env := allPassEnv(t)
	// Force the egress canary (probe 8) to fail by reporting curl success.
	// Probe 11 also uses sudo + pipelock-agent; distinguish by checking for the
	// curl path in argv. Without this guard, probe 11 would short-circuit
	// here and the test would observe an unrelated failure.
	env.runCmd = func(_ context.Context, name string, args ...string) (string, int, error) {
		if name == testSudoCmd && containsArg(args, testAgentUser) && containsArg(args, curlPath) {
			return "200", 0, nil
		}
		return defaultRunForAllPass(name, args)
	}

	cmd := newVerifyCmd(t)
	var buf bytes.Buffer
	cmd.SetOut(&buf)

	err := runVerify(cmd, env, verifyOpts{jsonOutput: false})
	if err == nil {
		t.Fatalf("expected error for fail exit, got nil")
	}
	if code := cliutil.ExitCodeOf(err); code != cliutil.ExitGeneral {
		t.Errorf("exit code: got %d, want %d", code, cliutil.ExitGeneral)
	}
	if !strings.Contains(buf.String(), "1 FAIL") {
		t.Errorf("missing fail in aggregate: %q", buf.String())
	}
}

func TestRunVerify_SkipExitCode(t *testing.T) {
	env := allPassEnv(t)
	// Force one probe to skip while leaving the rest green. A skipped
	// security canary must not return exit 0, or CI can mistake an
	// incomplete verification for a clean containment boundary.
	env.runCmd = func(_ context.Context, name string, args ...string) (string, int, error) {
		// Match probe 8 (curl) only - probe 11 (plk-launch) needs the
		// default canned response so it doesn't also skip.
		if name == testSudoCmd && containsArg(args, testAgentUser) && containsArg(args, curlPath) {
			return testSudoNeedsPwd, 1, nil
		}
		return defaultRunForAllPass(name, args)
	}

	cmd := newVerifyCmd(t)
	var buf bytes.Buffer
	cmd.SetOut(&buf)

	err := runVerify(cmd, env, verifyOpts{jsonOutput: false})
	if err == nil {
		t.Fatalf("expected error for skip exit, got nil")
	}
	if code := cliutil.ExitCodeOf(err); code != cliutil.ExitConfig {
		t.Errorf("exit code: got %d, want %d", code, cliutil.ExitConfig)
	}
	if !strings.Contains(buf.String(), "1 SKIP") {
		t.Errorf("missing skip in aggregate: %q", buf.String())
	}
}

func TestVerifyCmd_Wiring(t *testing.T) {
	root := Cmd()
	verify := findSubcmd(t, root, "verify")
	if verify == nil {
		t.Fatalf("verify subcommand not registered")
	}
	if !verify.HasFlags() {
		t.Fatalf("verify command exposes no flags")
	}
	if f := verify.Flag("json"); f == nil {
		t.Errorf("--json flag missing")
	}
	if f := verify.Flag("port"); f == nil {
		t.Errorf("--port flag missing")
	}
}

func TestVerifyCmd_InvalidPort(t *testing.T) {
	root := Cmd()
	root.SetArgs([]string{"verify", "--port", "0"})
	err := root.Execute()
	if err == nil {
		t.Fatalf("expected invalid port error, got nil")
	}
	if code := cliutil.ExitCodeOf(err); code != cliutil.ExitConfig {
		t.Errorf("exit code: got %d, want %d", code, cliutil.ExitConfig)
	}
	if !strings.Contains(err.Error(), "invalid --port") {
		t.Errorf("error: got %q, want invalid --port", err)
	}
}

// TestMutatingSubcommandsRequireRoot covers the precondition gate every
// mutating subcommand runs first: a non-root invocation must exit ExitConfig
// with a clear "must be run as root" message. This test exists so a future
// refactor can't accidentally turn the root gate into a no-op (which would
// let unprivileged callers attempt mutations and fail mid-step).
func TestMutatingSubcommandsRequireRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("test must run as non-root to exercise the precondition")
	}
	cases := []struct {
		subcmd string
		args   []string
	}{
		{"install", nil},
		{"rollback", nil},
		{"add-tool", []string{"validname"}},
		{"ca-refresh", nil},
	}
	root := Cmd()
	for _, tc := range cases {
		t.Run(tc.subcmd, func(t *testing.T) {
			sub := findSubcmd(t, root, tc.subcmd)
			if sub == nil {
				t.Fatalf("subcommand %s not registered", tc.subcmd)
			}
			err := sub.RunE(sub, tc.args)
			if err == nil {
				t.Fatalf("%s as non-root returned nil; want ExitError", tc.subcmd)
			}
			if code := cliutil.ExitCodeOf(err); code != cliutil.ExitConfig {
				t.Errorf("%s exit code: got %d, want %d (ExitConfig)", tc.subcmd, code, cliutil.ExitConfig)
			}
			if !strings.Contains(err.Error(), "must be run as root") {
				t.Errorf("%s error: got %q, want substring 'must be run as root'", tc.subcmd, err)
			}
		})
	}
}

func TestAddToolNameValidation(t *testing.T) {
	root := Cmd()
	addTool := findSubcmd(t, root, "add-tool")

	bad := []string{"", "Tool", "tool!", "../etc/passwd", strings.Repeat("a", 32)}
	for _, name := range bad {
		t.Run("invalid_"+name, func(t *testing.T) {
			err := addTool.RunE(addTool, []string{name})
			if err == nil {
				t.Fatalf("add-tool %q returned nil; want validation error", name)
			}
			if !strings.Contains(err.Error(), "invalid tool name") {
				t.Errorf("add-tool %q: got error %q, want 'invalid tool name'", name, err)
			}
		})
	}
}

// Helpers used by runner tests -----------------------------------------------

func newVerifyCmd(_ *testing.T) *cobra.Command {
	return &cobra.Command{Use: "verify"}
}

func findSubcmd(t *testing.T, root *cobra.Command, name string) *cobra.Command {
	t.Helper()
	for _, c := range root.Commands() {
		if c.Name() == name {
			return c
		}
	}
	return nil
}

func containsArg(args []string, needle string) bool {
	for _, a := range args {
		if a == needle {
			return true
		}
	}
	return false
}

// allPassEnv returns a probeEnv where every probe will pass. Used as
// the baseline for runner tests; individual tests override one field
// to introduce a fail/skip.
func allPassEnv(t *testing.T) *probeEnv {
	t.Helper()
	env := makeProbeEnv(t)
	env.operatorUser = testOperatorUser

	// Probe 1: both users present.
	env.lookupUser = func(name string) (*user.User, error) {
		switch name {
		case testProxyUser:
			return &user.User{Uid: "988", Username: testProxyUser}, nil
		case testAgentUser:
			return &user.User{Uid: "987", Username: testAgentUser}, nil
		}
		return nil, fmt.Errorf("unexpected lookup %q", name)
	}

	// Probe 6: dial succeeds.
	env.dialCtx = func(_ context.Context, _, _ string, _ time.Duration) (net.Conn, error) {
		return &fakeConn{}, nil
	}

	// Probes 2, 3, 8, 9: subprocess stubs.
	env.runCmd = func(_ context.Context, name string, args ...string) (string, int, error) {
		return defaultRunForAllPass(name, args)
	}

	// Filesystem state for probes 4, 5, 7, 12.
	writeFakeWrapper(t, env.launchPath, 0o755)
	writeFakeWrapper(t, filepath.Join(env.wrapperDir, "plk"), 0o755)
	writeFakeWrapper(t, filepath.Join(env.wrapperDir, "plk-claude"), 0o755)
	toolTarget := filepath.Join(t.TempDir(), "claude")
	writeFakeWrapper(t, toolTarget, 0o755)
	body := "#!/bin/bash\nexec env NO_PROXY=127.0.0.1,localhost,::1 HTTPS_PROXY=http://127.0.0.1:8888 sh\n"
	if err := os.WriteFile(env.launchPath, []byte(body), 0o755); err != nil { //nolint:gosec // wrapper script must be executable in test
		t.Fatalf("rewrite launch: %v", err)
	}
	writeFakePEMBundle(t, env.caBundlePath, "Pipelock Test CA")

	// Probe 10: binary integrity. allPassEnv emits matching pin + hash so
	// the probe returns pass. Tests that want to exercise mismatch override
	// hashFile or readFile after calling allPassEnv.
	const allPassHash = "abc123def456abc123def456abc123def456abc123def456abc123def456abcd"
	env.readFile = func(path string) ([]byte, error) {
		if path == env.pinPath {
			return []byte(allPassHash + "\n"), nil
		}
		if path == env.toolsListPath {
			return []byte("claude\t" + toolTarget + "\n"), nil
		}
		return nil, fmt.Errorf("unexpected readFile %s", path)
	}
	env.selfPath = func() (string, error) { return "/usr/local/bin/pipelock", nil }
	env.hashFile = func(path string) (string, error) {
		if path == "/usr/local/bin/pipelock" {
			return allPassHash, nil
		}
		return "", fmt.Errorf("unexpected hashFile %s", path)
	}

	return env
}

// defaultRunForAllPass is the canned subprocess response set when
// every probe should pass.
func defaultRunForAllPass(name string, args []string) (string, int, error) {
	switch name {
	case testSystemctl:
		return "ActiveState=active\nSubState=running\nUser=pipelock-proxy\nType=simple\n", 0, nil
	case testNFT:
		return goodNFTContainmentOutput, 0, nil
	case testSudoCmd:
		// Probe 11: plk-launch allow-list probe invokes plk-launch with a
		// sentinel tool name. Expect exit 5 = denial.
		if containsArg(args, "plk-launch") || containsArg(args, probe11Sentinel) {
			return "plk-launch: tool " + probe11Sentinel + " not in pipelock contain allow-list", 5, nil
		}
		// Either pipelock-agent (probe 8) or operator (probe 9). Match by argv.
		if containsArg(args, testAgentUser) {
			return "curl: (7) Failed to connect", 7, nil
		}
		return "200", 0, nil
	case curlPath:
		// Direct invoke for operator probe when env.operatorUser == "".
		return "200", 0, nil
	}
	return "", -1, fmt.Errorf("defaultRunForAllPass: unexpected cmd %q args=%v", name, args)
}

func TestOneLine(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"hello\nworld\r\n", "hello world"},
		{"  trim me\n", "trim me"},
		{"", ""},
	}
	for _, c := range cases {
		if got := oneLine(c.in); got != c.want {
			t.Errorf("oneLine(%q): got %q, want %q", c.in, got, c.want)
		}
	}
}

func TestIsSudoUserMissing(t *testing.T) {
	yes := []string{
		"sudo: unknown user pipelock-agent",
		"sudo: unknown user: pipelock-proxy",
		"SUDO: UNKNOWN USER FOO",
	}
	for _, s := range yes {
		if !isSudoUserMissing(s) {
			t.Errorf("isSudoUserMissing(%q) = false, want true", s)
		}
	}
	no := []string{
		testSudoNeedsPwd,
		"curl: (7) Failed to connect",
		"",
	}
	for _, s := range no {
		if isSudoUserMissing(s) {
			t.Errorf("isSudoUserMissing(%q) = true, want false", s)
		}
	}
}

func TestIsSudoTargetCommandMissing(t *testing.T) {
	yes := []string{
		"sudo: /usr/bin/curl: command not found",
		"sudo: /usr/bin/curl: No such file or directory",
	}
	for _, s := range yes {
		if !isSudoTargetCommandMissing(s) {
			t.Errorf("isSudoTargetCommandMissing(%q) = false, want true", s)
		}
	}
	no := []string{
		"curl: (7) Failed to connect",
		testSudoNeedsPwd,
		"",
	}
	for _, s := range no {
		if isSudoTargetCommandMissing(s) {
			t.Errorf("isSudoTargetCommandMissing(%q) = true, want false", s)
		}
	}
}

func TestFormatDialDuration(t *testing.T) {
	cases := []struct {
		in   time.Duration
		want string
	}{
		{500 * time.Microsecond, "<1ms"},
		{0, "<1ms"},
		{time.Millisecond, "1ms"},
		{17 * time.Millisecond, "17ms"},
		{2 * time.Second, "2s"},
	}
	for _, c := range cases {
		if got := formatDialDuration(c.in); got != c.want {
			t.Errorf("formatDialDuration(%s): got %q, want %q", c.in, got, c.want)
		}
	}
}

func TestDefaultProbeEnv(t *testing.T) {
	t.Setenv("SUDO_USER", "alice")
	env := defaultProbeEnv()
	if env.port != defaultProxyPort {
		t.Errorf("port: got %d, want %d", env.port, defaultProxyPort)
	}
	if env.operatorUser != "alice" {
		t.Errorf("operatorUser: got %q, want %q", env.operatorUser, "alice")
	}
	if env.proxyUserName != defaultProxyUser {
		t.Errorf("proxyUserName: got %q, want %q", env.proxyUserName, defaultProxyUser)
	}
	if env.launchPath != defaultLaunchScript {
		t.Errorf("launchPath: got %q, want %q", env.launchPath, defaultLaunchScript)
	}
	if len(env.toolWrappers) != len(defaultToolWrappers) {
		t.Errorf("toolWrappers: got %d, want %d", len(env.toolWrappers), len(defaultToolWrappers))
	}
	if env.wrapperInvPath != defaultWrapperInvPath {
		t.Errorf("wrapperInvPath: got %q, want %q", env.wrapperInvPath, defaultWrapperInvPath)
	}
	if env.nftRulesPath != defaultNFTRulesPath {
		t.Errorf("nftRulesPath: got %q, want %q", env.nftRulesPath, defaultNFTRulesPath)
	}
	if env.nftMainPath != "" {
		t.Errorf("nftMainPath: got %q, want empty legacy path", env.nftMainPath)
	}
	if env.nftPersistUnitPath != defaultNFTPersistUnitPath {
		t.Errorf("nftPersistUnitPath: got %q, want %q", env.nftPersistUnitPath, defaultNFTPersistUnitPath)
	}
	if env.runCmd == nil || env.dialCtx == nil || env.lookupUser == nil || env.readFile == nil {
		t.Errorf("hooks: runCmd=%v dialCtx=%v lookupUser=%v readFile=%v",
			env.runCmd != nil, env.dialCtx != nil, env.lookupUser != nil, env.readFile != nil)
	}
}

func TestRealDial_ConnRefused(t *testing.T) {
	// Dial a known-closed port on loopback. The kernel returns
	// ECONNREFUSED synchronously, so the test does not depend on
	// the dial timeout.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err := realDial(ctx, "tcp", "127.0.0.1:1", probeDialTimeout)
	if err == nil {
		t.Fatalf("dial to 127.0.0.1:1 succeeded, want refusal")
	}
}

func TestVerifyCmdExecute(t *testing.T) {
	root := Cmd()
	root.SetArgs([]string{"verify", "--json", "--port", "1"})
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetErr(&buf)

	// Running with the live environment will fail probes 1-7 on a
	// machine without the containment model. We only check the
	// command exits via ExitError, not the specific code (which
	// depends on whether sudo/systemctl/nft are even installed).
	err := root.Execute()
	if err == nil {
		t.Fatalf("expected error on uninstalled containment, got nil")
	}
	if code := cliutil.ExitCodeOf(err); code != cliutil.ExitGeneral && code != cliutil.ExitConfig && code != cliutil.ExitOK {
		t.Errorf("exit code: got %d, want 0, 1, or 2", code)
	}
	// Sanity: verify wrote JSON records to stdout (not the help text).
	if !strings.Contains(buf.String(), `"probe":1`) {
		t.Errorf("expected JSON output, got: %q", buf.String())
	}
}

func TestIsSudoRefusal(t *testing.T) {
	yes := []string{
		testSudoNeedsPwd,
		"User operator may not run sudo",
		"not allowed to execute",
		"sudo: no tty present and no askpass program specified",
		"SUDO: A PASSWORD IS REQUIRED",
	}
	for _, s := range yes {
		if !isSudoRefusal(s) {
			t.Errorf("isSudoRefusal(%q) = false, want true", s)
		}
	}
	no := []string{
		"curl: (7) Failed to connect",
		"200",
		"",
	}
	for _, s := range no {
		if isSudoRefusal(s) {
			t.Errorf("isSudoRefusal(%q) = true, want false", s)
		}
	}
}

func TestRealRunCommand_Roundtrip(t *testing.T) {
	// Use /bin/sh -c to avoid platform-specific binary discovery.
	out, code, err := realRunCommand(context.Background(), "/bin/sh", "-c", "echo hello && false")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if code != 1 {
		t.Errorf("exit code: got %d, want 1", code)
	}
	if !strings.Contains(out, "hello") {
		t.Errorf("output: got %q, want substring hello", out)
	}
}

func TestRealRunCommand_BinaryMissing(t *testing.T) {
	_, code, err := realRunCommand(context.Background(), "/nonexistent/binary", "arg")
	if err == nil {
		t.Fatalf("expected error for missing binary")
	}
	if code != -1 {
		t.Errorf("exit code: got %d, want -1", code)
	}
}

func TestNewFakeRunHelper(t *testing.T) {
	// Exercises the test helper itself so a failure isolates whether
	// the harness is the bug.
	run, _ := newFakeRun(fakeMatcher{cmd: "echo", result: fakeRunResult{stdout: "hi", code: 0}})
	out, code, err := run(context.Background(), "echo", "hello")
	if err != nil || code != 0 || out != "hi" {
		t.Fatalf("got out=%q code=%d err=%v", out, code, err)
	}
	_, _, err = run(context.Background(), "no-match")
	if err == nil {
		t.Fatalf("expected error for unstubbed call")
	}
}
