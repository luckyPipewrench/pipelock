// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package guard

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	llsys "github.com/landlock-lsm/go-landlock/landlock/syscall"
)

// These cover Apply's decisions and setup failures without touching the kernel.
//
// Landlock is irreversible, so tests must not use the kernel operations in
// process. The rulesetOperations seam supplies every syscall below, including
// successful setup, while the manifest uses ordinary temporary directories for
// its post-apply reachability check.

func TestApply_RefusesWhenLandlockUnavailable(t *testing.T) {
	sentinel := errors.New("landlock syscall missing")
	p := &PreparedManifest{complete: true}

	record, err := p.apply(func() (int, error) { return 0, sentinel })

	if !errors.Is(err, ErrLandlockUnavailable) {
		t.Fatalf("err = %v, want ErrLandlockUnavailable", err)
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("err = %v, want the underlying cause wrapped", err)
	}
	if record.Enforced() || record.State != EnforcementRefused {
		t.Errorf("record = %+v, want refused", record)
	}
	// No reading was taken, which must stay distinguishable from a reading of
	// zero: a nil pointer says "unknown", a zero would say "ABI 0".
	if record.ObservedABI != nil {
		t.Errorf("ObservedABI = %v, want nil when the version could not be read", *record.ObservedABI)
	}
	if record.Coverage != CoverageUnknown {
		t.Errorf("Coverage = %q, want unknown", record.Coverage)
	}
}

func TestApply_RefusesBelowThreadSyncABI(t *testing.T) {
	p := &PreparedManifest{complete: true}

	record, err := p.apply(func() (int, error) { return ThreadSyncABI - 1, nil })

	if !errors.Is(err, ErrABITooOld) {
		t.Fatalf("err = %v, want ErrABITooOld", err)
	}
	if record.Enforced() {
		t.Error("a kernel without thread-synchronised restriction must not report enforced")
	}
	// The refusal has to name the alternative, or an operator on this kernel is
	// told no with nowhere to go. Applying the same ruleset in a single-threaded
	// child before exec needs only MinimumABI.
	if !strings.Contains(record.Reason, "single-threaded child") {
		t.Errorf("Reason = %q, want it to name the pre-exec alternative", record.Reason)
	}
	if record.ObservedABI == nil || *record.ObservedABI != ThreadSyncABI-1 {
		t.Errorf("ObservedABI = %v, want %d", record.ObservedABI, ThreadSyncABI-1)
	}
}

func TestApplyForExec_AcceptsBaseABIWithoutThreadSync(t *testing.T) {
	p := &PreparedManifest{complete: false}

	record, err := p.applyMode(func() (int, error) { return MinimumABI, nil }, false)

	if !errors.Is(err, ErrManifestIncomplete) {
		t.Fatalf("err = %v, want manifest refusal after the ABI check", err)
	}
	if errors.Is(err, ErrABITooOld) {
		t.Fatalf("pre-exec application incorrectly required thread sync: %v", err)
	}
	if record.RequiredABI != MinimumABI {
		t.Fatalf("RequiredABI = %d, want base ABI %d", record.RequiredABI, MinimumABI)
	}
	if record.ObservedABI == nil || *record.ObservedABI != MinimumABI {
		t.Fatalf("ObservedABI = %v, want %d", record.ObservedABI, MinimumABI)
	}
}

func TestApplyForExec_CompleteSequenceUsesBaseABIAndNoThreadSync(t *testing.T) {
	p := &PreparedManifest{complete: true}
	var sequence []string
	var restrictFlags uint32
	ops := rulesetOperations{
		getABI: func() (int, error) { return MinimumABI, nil },
		createRuleset: func(attr *llsys.RulesetAttr, flags int) (int, error) {
			sequence = append(sequence, "create")
			if flags != 0 || attr.HandledAccessFS != baseAccessFS || attr.Scoped != 0 {
				t.Fatalf("create flags=%d handled=%d scoped=%d, want 0/%d/0", flags, attr.HandledAccessFS, attr.Scoped, baseAccessFS)
			}
			return 42, nil
		},
		addPathRule: func(int, *llsys.PathBeneathAttr, int) error {
			t.Fatal("empty manifest unexpectedly added a path rule")
			return nil
		},
		restrictSelf: func(fd int, flags uint32) error {
			sequence = append(sequence, "restrict")
			restrictFlags = flags
			if fd != 42 {
				t.Fatalf("restrict fd=%d, want 42", fd)
			}
			return nil
		},
		setNoNewPrivs: func() error {
			sequence = append(sequence, "no_new_privs")
			return nil
		},
		closeFD: func(fd int) error {
			sequence = append(sequence, "close")
			if fd != 42 {
				t.Fatalf("close fd=%d, want 42", fd)
			}
			return nil
		},
	}

	record, err := p.applyWithOperations(ops, false)
	if err != nil {
		t.Fatalf("applyWithOperations: %v", err)
	}
	if !record.Enforced() || record.RequiredABI != MinimumABI {
		t.Fatalf("record = %+v, want enforced at base ABI", record)
	}
	if want := []string{"create", "no_new_privs", "restrict", "close"}; !slices.Equal(sequence, want) {
		t.Fatalf("operation sequence = %v, want %v", sequence, want)
	}
	if restrictFlags != 0 {
		t.Fatalf("pre-exec restrict flags=%d, want no thread-sync flag", restrictFlags)
	}
}

func TestApplyWithOperations_SetupFailuresRefuseAndCloseRuleset(t *testing.T) {
	tests := []struct {
		name              string
		abi               int
		threadSync        bool
		failStage         string
		closeError        bool
		wantReason        string
		wantSequence      []string
		wantRestrictArg   uint32
		wantHandledAccess uint64
		wantScope         uint64
		wantCoverage      Coverage
		wantUnmediated    []string
	}{
		{
			name:              "create_ruleset",
			abi:               MinimumABI,
			failStage:         "create",
			wantReason:        "creating landlock ruleset",
			wantSequence:      []string{"create"},
			wantHandledAccess: baseAccessFS,
		},
		{
			name:              "add_path_rule",
			abi:               MinimumABI,
			failStage:         "add",
			wantReason:        "adding rule",
			wantSequence:      []string{"create", "add", "close"},
			wantHandledAccess: baseAccessFS,
		},
		{
			name:              "set_no_new_privs",
			abi:               MinimumABI,
			failStage:         "no_new_privs",
			wantReason:        "setting no_new_privs",
			wantSequence:      []string{"create", "add", "no_new_privs", "close"},
			wantHandledAccess: baseAccessFS,
		},
		{
			name:              "restrict_self_with_thread_sync",
			abi:               ThreadSyncABI,
			threadSync:        true,
			failStage:         "restrict",
			wantReason:        "applying landlock restriction",
			wantSequence:      []string{"create", "add", "no_new_privs", "restrict", "close"},
			wantRestrictArg:   llsys.FlagRestrictSelfTSync,
			wantHandledAccess: baseAccessFS,
			wantScope:         scopedIPC,
		},
		{
			name:              "close_failure_preserves_restriction_failure",
			abi:               MinimumABI,
			failStage:         "restrict",
			closeError:        true,
			wantReason:        "applying landlock restriction",
			wantSequence:      []string{"create", "add", "no_new_privs", "restrict", "close"},
			wantHandledAccess: baseAccessFS,
		},
		{
			name:              "close_failure_preserves_applied_restriction",
			abi:               SocketMediationABI,
			threadSync:        true,
			closeError:        true,
			wantSequence:      []string{"create", "add", "no_new_privs", "restrict", "close"},
			wantRestrictArg:   llsys.FlagRestrictSelfTSync,
			wantHandledAccess: baseAccessFS | llsys.AccessFSResolveUnix,
			wantScope:         scopedIPC,
			wantCoverage:      CoverageFull,
		},
		{
			name:              "healthy_without_thread_sync",
			abi:               MinimumABI,
			wantSequence:      []string{"create", "add", "no_new_privs", "restrict", "close"},
			wantHandledAccess: baseAccessFS,
			wantCoverage:      CoveragePartial,
			wantUnmediated: []string{
				"connect(2) and sendmsg(2) on pathname unix sockets, including agent sockets",
				"abstract unix sockets and signals to processes outside the restriction",
			},
		},
		{
			name:              "healthy_with_thread_sync_and_socket_mediation",
			abi:               SocketMediationABI,
			threadSync:        true,
			wantSequence:      []string{"create", "add", "no_new_privs", "restrict", "close"},
			wantRestrictArg:   llsys.FlagRestrictSelfTSync,
			wantHandledAccess: baseAccessFS | llsys.AccessFSResolveUnix,
			wantScope:         scopedIPC,
			wantCoverage:      CoverageFull,
			wantUnmediated:    nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			state := filepath.Join(root, "state")
			if err := os.Mkdir(state, 0o750); err != nil {
				t.Fatalf("Mkdir state: %v", err)
			}
			p := &PreparedManifest{
				complete: true,
				rules: []preparedRule{{
					fd:       17,
					access:   rightsReadDir,
					declared: "state",
					resolved: state,
					isDir:    true,
					kind:     AccessReadDirectory,
				}},
			}
			sentinel := errors.New("injected ruleset operation failure")
			var sequence []string
			var restrictFlags uint32
			ops := rulesetOperations{
				getABI: func() (int, error) { return tc.abi, nil },
				createRuleset: func(attr *llsys.RulesetAttr, flags int) (int, error) {
					sequence = append(sequence, "create")
					if flags != 0 || attr.HandledAccessFS != tc.wantHandledAccess || attr.Scoped != tc.wantScope {
						t.Fatalf("create ruleset flags=%d handled=%d scoped=%d, want 0/%d/%d", flags, attr.HandledAccessFS, attr.Scoped, tc.wantHandledAccess, tc.wantScope)
					}
					if tc.failStage == "create" {
						return -1, sentinel
					}
					return 42, nil
				},
				addPathRule: func(fd int, attr *llsys.PathBeneathAttr, flags int) error {
					sequence = append(sequence, "add")
					if fd != 42 || flags != 0 || attr.ParentFd != 17 || attr.AllowedAccess != rightsReadDir {
						t.Fatalf("add rule fd=%d flags=%d parent=%d access=%d", fd, flags, attr.ParentFd, attr.AllowedAccess)
					}
					if tc.failStage == "add" {
						return sentinel
					}
					return nil
				},
				setNoNewPrivs: func() error {
					sequence = append(sequence, "no_new_privs")
					if tc.failStage == "no_new_privs" {
						return sentinel
					}
					return nil
				},
				restrictSelf: func(fd int, flags uint32) error {
					sequence = append(sequence, "restrict")
					restrictFlags = flags
					if fd != 42 {
						t.Fatalf("restrict fd=%d, want 42", fd)
					}
					if tc.failStage == "restrict" {
						return sentinel
					}
					return nil
				},
				closeFD: func(fd int) error {
					sequence = append(sequence, "close")
					if fd != 42 {
						t.Fatalf("close fd=%d, want 42", fd)
					}
					if tc.closeError {
						return errors.New("injected descriptor cleanup failure")
					}
					return nil
				},
			}

			record, err := p.applyWithOperations(ops, tc.threadSync)
			if tc.failStage == "" {
				if err != nil {
					t.Fatalf("applyWithOperations: %v", err)
				}
				if !record.Enforced() || !p.applied {
					t.Fatalf("record = %+v, applied=%v, want enforced", record, p.applied)
				}
				if record.Coverage != tc.wantCoverage {
					t.Fatalf("Coverage = %q, want %q", record.Coverage, tc.wantCoverage)
				}
				if !slices.Equal(record.Unmediated, tc.wantUnmediated) {
					t.Fatalf("Unmediated = %v, want %v", record.Unmediated, tc.wantUnmediated)
				}
			} else {
				if !errors.Is(err, sentinel) {
					t.Fatalf("error = %v, want injected error wrapped", err)
				}
				if record.State != EnforcementRefused || record.Enforced() || p.applied {
					t.Fatalf("record = %+v, applied=%v, want refused and unapplied", record, p.applied)
				}
				if !strings.Contains(record.Reason, tc.wantReason) {
					t.Fatalf("reason = %q, want %q", record.Reason, tc.wantReason)
				}
			}
			if !slices.Equal(sequence, tc.wantSequence) {
				t.Fatalf("operation sequence = %v, want %v", sequence, tc.wantSequence)
			}
			if slices.Contains(tc.wantSequence, "restrict") && restrictFlags != tc.wantRestrictArg {
				t.Fatalf("restrict flags=%d, want %d", restrictFlags, tc.wantRestrictArg)
			}
		})
	}
}

// TestApply_ReportsPartialCoverageBeforeRefusingIncompleteManifest exercises
// the coverage tiering at a supported ABI without reaching the syscalls.
//
// The incomplete manifest is the vehicle, not the subject: it forces an early
// return AFTER capabilities have been computed, which is the only way to
// observe the tiering in-process. The assertion that matters is that a kernel
// lacking socket mediation is recorded as partial with the gap named.
func TestApply_ReportsPartialCoverageBeforeRefusingIncompleteManifest(t *testing.T) {
	p := &PreparedManifest{complete: false}

	record, err := p.apply(func() (int, error) { return ThreadSyncABI, nil })

	if !errors.Is(err, ErrManifestIncomplete) {
		t.Fatalf("err = %v, want ErrManifestIncomplete", err)
	}
	if record.Enforced() {
		t.Error("an incomplete manifest must never report enforced")
	}
	if record.Coverage != CoveragePartial {
		t.Errorf("Coverage = %q, want partial below the socket-mediation ABI", record.Coverage)
	}
	if !containsSubstring(record.Unmediated, "unix socket") {
		t.Errorf("Unmediated = %v, want the socket gap named", record.Unmediated)
	}
	if record.ManifestComplete {
		t.Error("ManifestComplete must reflect the prepared state")
	}
}

// TestApply_FullCoverageAtSocketMediationABI is the counterpart: at the ABI
// that supplies every capability, nothing is reported as unmediated.
func TestApply_FullCoverageAtSocketMediationABI(t *testing.T) {
	p := &PreparedManifest{complete: false}

	record, err := p.apply(func() (int, error) { return SocketMediationABI, nil })

	// Pin the early return. If the incomplete-manifest check ever moved after
	// ruleset construction, this test would apply a real restriction to the test
	// binary for the rest of the run, and the resulting failures would point
	// everywhere except here.
	if !errors.Is(err, ErrManifestIncomplete) {
		t.Fatalf("err = %v, want ErrManifestIncomplete", err)
	}

	if record.Coverage != CoverageFull {
		t.Errorf("Coverage = %q, want full at ABI %d", record.Coverage, SocketMediationABI)
	}
	if len(record.Unmediated) != 0 {
		t.Errorf("Unmediated = %v, want empty at full coverage", record.Unmediated)
	}
}
