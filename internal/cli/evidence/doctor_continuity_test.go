// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package evidence

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

// runDoctorChain records one real run chain in dir the way production does
// (a run session per recorder, a receipt emitter on it) and returns its
// session.
func runDoctorChain(t *testing.T, dir string, priv ed25519.PrivateKey, n int) string {
	t.Helper()
	rec, err := recorder.New(recorder.Config{Enabled: true, Dir: dir, CheckpointInterval: 1000}, nil, priv)
	if err != nil {
		t.Fatalf("recorder.New: %v", err)
	}
	session, err := recorder.AcquireRunSession(rec, recorder.DefaultSessionBase)
	if err != nil {
		t.Fatalf("AcquireRunSession: %v", err)
	}
	e := receipt.NewEmitter(receipt.EmitterConfig{Recorder: rec, PrivKey: priv, Principal: "doctor-test", Actor: "doctor-test", Session: session, Notices: io.Discard})
	if err := e.EmitSessionOpen(); err != nil {
		t.Fatalf("EmitSessionOpen: %v", err)
	}
	for i := 0; i < n; i++ {
		if err := e.Emit(receipt.EmitOpts{ActionID: receipt.NewActionID(), Target: "https://api.vendor.example/x", Verdict: config.ActionBlock, Transport: "fetch", Method: http.MethodGet}); err != nil {
			t.Fatalf("Emit: %v", err)
		}
	}
	if err := rec.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	return session
}

func doctorKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv
}

func runDoctorCmd(t *testing.T, dir string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	cmd := Cmd()
	cmd.SetOut(&out)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{"doctor", dir})
	err := cmd.Execute()
	return out.String(), err
}

func TestEvidenceDoctorContinuityLinkedPair(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	priv := doctorKey(t)
	a := runDoctorChain(t, dir, priv, 2)
	b := runDoctorChain(t, dir, priv, 1)

	out, err := runDoctorCmd(t, dir)
	if err != nil {
		t.Fatalf("a cleanly linked pair must pass: %v\n%s", err, out)
	}
	for _, want := range []string{
		"evidence doctor: healthy",
		"structure: no damage found",
		"restart continuity:",
		"2 chain(s), 1 linked, 1 unlinked, 0 link finding(s)",
		"unlinked: " + a,
		"structural checks do not establish restart continuity",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("output missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "unlinked: "+b) {
		t.Fatalf("the linked successor must not be listed unlinked:\n%s", out)
	}
}

// Deleting the link file is the documented undetected limit: the doctor
// still passes, but lists the successor as unlinked rather than hiding it.
func TestEvidenceDoctorContinuityDeletedLinkShowsUnlinked(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	priv := doctorKey(t)
	a := runDoctorChain(t, dir, priv, 1)
	b := runDoctorChain(t, dir, priv, 1)
	if err := os.Remove(filepath.Join(dir, receipt.ChainLinkFileName(a))); err != nil {
		t.Fatal(err)
	}
	out, err := runDoctorCmd(t, dir)
	if err != nil {
		t.Fatalf("an unlinked run is reported, not failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, "0 linked, 2 unlinked") || !strings.Contains(out, "unlinked: "+b) {
		t.Fatalf("the successor must be listed unlinked:\n%s", out)
	}
}

func TestEvidenceDoctorContinuityLinkFindingFails(t *testing.T) {
	t.Parallel()
	cases := map[string]func(t *testing.T, path string){
		"garbage": func(t *testing.T, path string) {
			if err := os.WriteFile(path, []byte("not json"), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"wrong tail": func(t *testing.T, path string) {
			raw, err := os.ReadFile(filepath.Clean(path))
			if err != nil {
				t.Fatal(err)
			}
			var m map[string]any
			if err := json.Unmarshal(raw, &m); err != nil {
				t.Fatal(err)
			}
			m["predecessor_tail_hash"] = strings.Repeat("ab", 32)
			altered, _ := json.Marshal(m)
			if err := os.WriteFile(path, altered, 0o600); err != nil {
				t.Fatal(err)
			}
		},
	}
	for label, mutate := range cases {
		t.Run(label, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			priv := doctorKey(t)
			a := runDoctorChain(t, dir, priv, 1)
			_ = runDoctorChain(t, dir, priv, 1)
			mutate(t, filepath.Join(dir, receipt.ChainLinkFileName(a)))
			out, err := runDoctorCmd(t, dir)
			if err == nil {
				t.Fatalf("a bad link file must exit nonzero:\n%s", out)
			}
			var exitErr *cliutil.ExitError
			if !errors.As(err, &exitErr) || !strings.Contains(err.Error(), "restart-continuity") {
				t.Fatalf("want a restart-continuity exit error, got %v", err)
			}
			if !strings.Contains(out, "evidence doctor: damaged") || !strings.Contains(out, "structure: no damage found") || !strings.Contains(out, receipt.FindingInvalidLink) {
				t.Fatalf("link findings must be reported apart from clean structure:\n%s", out)
			}
		})
	}
}

func TestEvidenceDoctorContinuityIncompleteIsNotHealthy(t *testing.T) {
	t.Parallel()
	report := evidenceDoctorReport{Dir: "d", Continuity: []doctorContinuity{{Dir: "d", Err: "boom"}}}
	if report.Conclusive() || report.Damaged() {
		t.Fatalf("an incomplete continuity check must be inconclusive, not damaged or healthy")
	}
	var out bytes.Buffer
	printDoctorContinuity(&out, report.Continuity)
	if !strings.Contains(out.String(), "check incomplete: boom") {
		t.Fatalf("output: %s", out.String())
	}
	if got := checkDoctorContinuity(filepath.Join(t.TempDir(), "absent")); len(got) != 1 || got[0].Err == "" {
		t.Fatalf("an unreadable directory must yield an incomplete continuity result: %+v", got)
	}
}
