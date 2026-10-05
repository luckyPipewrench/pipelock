// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package contain

// containLifecycleRecord is a host-authored witness, never child output. An
// incomplete/missing record cannot establish cleanup. The hashes describe the
// candidate and loaded signing config, not an independent live-proxy attestation.
type containLifecycleRecord struct {
	Schema                      int               `json:"schema"`
	RunID                       string            `json:"run_id"`
	Unit                        string            `json:"unit"`
	Phase                       string            `json:"phase"`
	Final                       bool              `json:"final"`
	AdmissionObserved           bool              `json:"admission_observed"`
	ArgvObserved                bool              `json:"argv_observed"`
	InvocationID                string            `json:"invocation_id,omitempty"`
	ControlGroup                string            `json:"control_group,omitempty"`
	ArgvSHA256                  string            `json:"argv_sha256,omitempty"`
	BinarySHA256                string            `json:"binary_sha256,omitempty"`
	ConfigSHA256                string            `json:"config_sha256,omitempty"`
	PolicySHA256                string            `json:"policy_sha256,omitempty"`
	PostureCapsuleSHA256        string            `json:"posture_capsule_sha256,omitempty"`
	CleanupTimeoutSeconds       int               `json:"cleanup_timeout_seconds"`
	AdmissionTimeoutSeconds     int               `json:"admission_timeout_seconds"`
	ClientWaitTimeoutSeconds    int               `json:"client_wait_timeout_seconds"`
	CleanupComplete             bool              `json:"cleanup_complete"`
	CgroupEmpty                 bool              `json:"cgroup_empty"`
	StopRequested               bool              `json:"stop_requested"`
	KillRequested               bool              `json:"kill_requested"`
	Cancelled                   bool              `json:"cancelled"`
	Terminal                    map[string]string `json:"terminal,omitempty"`
	Failure                     string            `json:"failure,omitempty"`
	FilesystemMode              string            `json:"filesystem_mode,omitempty"`
	FilesystemBindPaths         []string          `json:"filesystem_bind_paths,omitempty"`
	FilesystemBindReadOnlyPaths []string          `json:"filesystem_bind_read_only_paths,omitempty"`
}

type containRunLifecycle struct {
	record containLifecycleRecord
	save   func(containLifecycleRecord) error
	close  func() error
	argv   []string
}

func (l *containRunLifecycle) write() error { return l.save(l.record) }

func boundedLifecycleError(err error) string {
	if err == nil {
		return "lifecycle did not reach a verified terminal state"
	}
	message := err.Error()
	if len(message) > 1024 {
		message = message[:1024]
	}
	return message
}
