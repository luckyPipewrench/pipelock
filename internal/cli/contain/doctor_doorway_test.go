// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
)

const (
	testDoorwayProxySocket = "pipelock-agent-proxy.socket"
	testDoorwayProxyRelay  = "pipelock-agent-proxy.service"
)

// fakeUnitState is one unit's scripted systemctl answers.
type fakeUnitState struct {
	enabled string
	active  string
}

// doorwayReaderFor drives doctorDoorwaySocketReader against scripted
// systemctl state. Units not named in states read as enabled and active. It
// records every unit queried so tests can assert what doctor looked at.
func doorwayReaderFor(states map[string]fakeUnitState, runErr error) (func() doctorResult, *[]string) {
	var queried []string
	base := &probeEnv{
		configPath:               "/etc/pipelock/pipelock.yaml",
		proxyForwarderSocketPath: "/etc/systemd/system/" + testDoorwayProxySocket,
		readFile: func(string) ([]byte, error) {
			return nil, os.ErrNotExist
		},
		runCmd: func(_ context.Context, name string, args ...string) (string, int, error) {
			if runErr != nil {
				return "", -1, runErr
			}
			if name != "systemctl" || len(args) != 2 {
				return "", 1, errors.New("unexpected command")
			}
			if args[0] == "is-active" {
				queried = append(queried, args[1])
			}
			st, ok := states[args[1]]
			if !ok {
				st = fakeUnitState{enabled: systemctlEnabled, active: systemctlActive}
			}
			// systemctl exits 0 only for an enabled or active unit.
			state, ok := st.active, st.active == systemctlActive
			if args[0] == "is-enabled" {
				state, ok = st.enabled, st.enabled == systemctlEnabled
			}
			if !ok {
				return state + "\n", 1, nil
			}
			return state + "\n", 0, nil
		},
	}
	reader := doctorDoorwaySocketReader(base, &doctorEnv{port: defaultProxyPort, agentUserName: testAgentUser})
	return func() doctorResult { return reader(context.Background()) }, &queried
}

func TestDoctorNamespaceForwarderStates(t *testing.T) {
	for _, tc := range []struct {
		name        string
		state       fakeUnitState
		wantStatus  string
		wantRemedy  string
		wantDetails []string
	}{
		{"active and enabled", fakeUnitState{systemctlEnabled, systemctlActive}, statusPass, "", nil},
		{"inactive", fakeUnitState{systemctlEnabled, "inactive"}, statusFail, "systemctl restart " + containedNamespaceForwarderUnit, []string{containedNamespaceForwarderUnit, "inactive"}},
		{"inactive and disabled", fakeUnitState{"disabled", "inactive"}, statusFail, "systemctl enable --now " + containedNamespaceForwarderUnit, []string{"inactive", "disabled"}},
		{"failed", fakeUnitState{systemctlEnabled, systemctlFailed}, statusFail, "systemctl reset-failed " + containedNamespaceForwarderUnit + " && systemctl restart " + containedNamespaceForwarderUnit, []string{"failed"}},
		{"masked", fakeUnitState{systemctlMasked, "inactive"}, statusFail, "systemctl unmask " + containedNamespaceForwarderUnit + " && systemctl enable --now " + containedNamespaceForwarderUnit, []string{"masked"}},
		{"not found", fakeUnitState{systemctlNotFound, "inactive"}, statusFail, "pipelock contain install", []string{"not-found"}},
		{"active but not enabled", fakeUnitState{"disabled", systemctlActive}, statusFail, "systemctl enable --now " + containedNamespaceForwarderUnit, []string{"disabled"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			read, _ := doorwayReaderFor(map[string]fakeUnitState{containedNamespaceForwarderUnit: tc.state}, nil)
			got := read()
			if got.status != tc.wantStatus {
				t.Fatalf("status = %q, want %q (%+v)", got.status, tc.wantStatus, got)
			}
			if tc.wantStatus == statusPass {
				return
			}
			if !strings.Contains(got.remediation, tc.wantRemedy) {
				t.Fatalf("remediation = %q, want it to contain %q", got.remediation, tc.wantRemedy)
			}
			for _, want := range tc.wantDetails {
				if !strings.Contains(got.detail, want) {
					t.Fatalf("detail = %q, want it to contain %q", got.detail, want)
				}
			}
			if got.class != classInfra {
				t.Fatalf("class = %q, want %q", got.class, classInfra)
			}
		})
	}
}

func TestDoctorNamespaceForwarderSystemctlUnavailableIsUnknown(t *testing.T) {
	read, _ := doorwayReaderFor(nil, errors.New("exec: systemctl: not found"))
	if got := read(); got.status != statusUnknown {
		t.Fatalf("status = %q, want %q (%+v)", got.status, statusUnknown, got)
	}
}

func TestDoctorDoorwaySocketRemedyMatchesRelayState(t *testing.T) {
	for _, tc := range []struct {
		name        string
		socket      fakeUnitState
		relay       fakeUnitState
		wantRemedy  string
		notContains string
	}{
		{
			"stopped socket with live relay stops the relay first",
			fakeUnitState{"disabled", "inactive"},
			fakeUnitState{"static", systemctlActive},
			"systemctl stop " + testDoorwayProxyRelay + " && systemctl enable --now " + testDoorwayProxySocket,
			"",
		},
		{
			"stopped socket with stopped relay needs no stop",
			fakeUnitState{"disabled", "inactive"},
			fakeUnitState{"static", "inactive"},
			"systemctl enable --now " + testDoorwayProxySocket,
			"systemctl stop",
		},
		{
			"enabled but inactive socket with live relay",
			fakeUnitState{systemctlEnabled, "inactive"},
			fakeUnitState{"static", systemctlActive},
			"systemctl stop " + testDoorwayProxyRelay + " && systemctl start " + testDoorwayProxySocket,
			"",
		},
		{
			"enabled but inactive socket with stopped relay",
			fakeUnitState{systemctlEnabled, "inactive"},
			fakeUnitState{"static", "inactive"},
			"systemctl start " + testDoorwayProxySocket,
			"systemctl stop",
		},
		{
			"failed socket with live relay clears failure after stopping relay",
			fakeUnitState{systemctlEnabled, systemctlFailed},
			fakeUnitState{"static", systemctlActive},
			"systemctl stop " + testDoorwayProxyRelay + " && systemctl reset-failed " + testDoorwayProxySocket + " && systemctl start " + testDoorwayProxySocket,
			"",
		},
		{
			"masked socket is unmasked first",
			fakeUnitState{systemctlMasked, "inactive"},
			fakeUnitState{"static", "inactive"},
			"systemctl unmask " + testDoorwayProxySocket + " && systemctl enable --now " + testDoorwayProxySocket,
			"",
		},
		{
			"missing socket points at install",
			fakeUnitState{systemctlNotFound, "inactive"},
			fakeUnitState{systemctlNotFound, "inactive"},
			"pipelock contain install",
			"systemctl start",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			read, _ := doorwayReaderFor(map[string]fakeUnitState{
				testDoorwayProxySocket: tc.socket,
				testDoorwayProxyRelay:  tc.relay,
			}, nil)
			got := read()
			if got.status != statusFail {
				t.Fatalf("status = %q, want fail (%+v)", got.status, got)
			}
			if !strings.Contains(got.remediation, tc.wantRemedy) {
				t.Fatalf("remediation = %q, want it to contain %q", got.remediation, tc.wantRemedy)
			}
			if tc.notContains != "" && strings.Contains(got.remediation, tc.notContains) {
				t.Fatalf("remediation = %q, must not contain %q", got.remediation, tc.notContains)
			}
			if strings.Contains(got.detail, "run `systemctl") {
				t.Fatalf("detail repeats a command that may not work for this state: %q", got.detail)
			}
		})
	}
}

func TestDoctorDoorwayHealthyQueriesProxySocketAndForwarder(t *testing.T) {
	read, queried := doorwayReaderFor(nil, nil)
	got := read()
	if got.status != statusPass {
		t.Fatalf("status = %q, want pass (%+v)", got.status, got)
	}
	want := []string{testDoorwayProxySocket, containedNamespaceForwarderUnit}
	if strings.Join(*queried, ",") != strings.Join(want, ",") {
		t.Fatalf("units queried = %v, want %v", *queried, want)
	}
}
