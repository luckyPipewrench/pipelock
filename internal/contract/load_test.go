// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contract

import (
	"errors"
	"testing"
)

func TestDecodeStrictJSON_RejectsEmptyAndNull(t *testing.T) {
	t.Parallel()
	for _, raw := range []string{"", "null"} {
		var c Contract
		if err := DecodeStrictJSON([]byte(raw), &c); !errors.Is(err, ErrEmptyPayload) {
			t.Errorf("input %q: got %v, want ErrEmptyPayload", raw, err)
		}
	}
}

func TestDecodeStrictJSON_RejectsUnknownField(t *testing.T) {
	t.Parallel()
	raw := []byte(`{"schema_version":1,"contract_kind":"behavioral_contract","future_field":"sneaky"}`)
	var c Contract
	if err := DecodeStrictJSON(raw, &c); !errors.Is(err, ErrUnknownField) {
		t.Errorf("got %v, want ErrUnknownField", err)
	}
}

func TestDecodeStrictJSON_RejectsTrailingTokens(t *testing.T) {
	t.Parallel()
	raw := []byte(`{"schema_version":1,"contract_kind":"behavioral_contract"} junk`)
	var c Contract
	if err := DecodeStrictJSON(raw, &c); !errors.Is(err, ErrTrailingTokens) {
		t.Errorf("got %v, want ErrTrailingTokens", err)
	}
}

func TestDecodeStrictJSON_AcceptsValidShape(t *testing.T) {
	t.Parallel()
	raw := []byte(`{"schema_version":1,"contract_kind":"behavioral_contract","contract_hash":"","signer_key_id":"","key_purpose":"","data_class_root":"internal","field_data_classes":{},"selector":{"selector_id":""},"observation_window":{"start":"0001-01-01T00:00:00Z","end":"0001-01-01T00:00:00Z","event_count":0,"session_count":0,"observation_window_root":""},"compile":{"pipelock_version":"","pipelock_build_sha":"","go_version":"","module_digest_root":"","compile_config_hash":"","inference_algorithm":"","normalization_algorithm":""},"defaults":{"fidelity":"","confidence":null,"privacy":{"default_data_class":"","salt_epoch":0,"forbid_classes":null}},"rules":null}`)
	var c Contract
	if err := DecodeStrictJSON(raw, &c); err != nil {
		t.Errorf("got %v, want nil", err)
	}
}

func TestLoadContract_RejectsUnknownField(t *testing.T) {
	t.Parallel()
	raw := []byte(`{"schema_version":1,"contract_kind":"behavioral_contract","x_advisory_extension":"hidden"}`)
	if _, err := LoadContract(raw); !errors.Is(err, ErrUnknownField) {
		t.Errorf("got %v, want ErrUnknownField wrapped", err)
	}
}

func TestLoadKeyRoster_RejectsUnknownField(t *testing.T) {
	t.Parallel()
	raw := []byte(`{"schema_version":1,"roster_signed_by":"x","keys":[],"data_class_root":"internal","extra":"x"}`)
	if _, err := LoadKeyRoster(raw); !errors.Is(err, ErrUnknownField) {
		t.Errorf("got %v, want ErrUnknownField wrapped", err)
	}
}

func TestLoadTombstone_RejectsUnknownField(t *testing.T) {
	t.Parallel()
	raw := []byte(`{"schema_version":1,"tombstone":true,"surplus":"yes"}`)
	if _, err := LoadTombstone(raw); !errors.Is(err, ErrUnknownField) {
		t.Errorf("got %v, want ErrUnknownField wrapped", err)
	}
}

func TestLoadVerificationMetadata_RejectsUnknownField(t *testing.T) {
	t.Parallel()
	raw := []byte(`{"schema_version":1,"bundle_kind":"public_proof_bundle","extra":1}`)
	if _, err := LoadVerificationMetadata(raw); !errors.Is(err, ErrUnknownField) {
		t.Errorf("got %v, want ErrUnknownField wrapped", err)
	}
}

func TestLoadCompileManifest_RejectsUnknownField(t *testing.T) {
	t.Parallel()
	raw := []byte(`{"schema_version":1,"contract_hash":"","compile_started_at":"0001-01-01T00:00:00Z","compile_finished_at":"0001-01-01T00:00:00Z","x":"y"}`)
	if _, err := LoadCompileManifest(raw); !errors.Is(err, ErrUnknownField) {
		t.Errorf("got %v, want ErrUnknownField wrapped", err)
	}
}

func TestLoadActiveManifest_RejectsUnknownField(t *testing.T) {
	t.Parallel()
	raw := []byte(`{"schema_version":1,"manifest_kind":"activation_manifest","sneak":"in"}`)
	if _, err := LoadActiveManifest(raw); !errors.Is(err, ErrUnknownField) {
		t.Errorf("got %v, want ErrUnknownField wrapped", err)
	}
}
