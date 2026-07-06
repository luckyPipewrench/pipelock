package receipt

import (
	"bytes"
	"strings"
	"testing"
)

// goldenSessionOpenGenesis locks the length-framed session_open genesis
// preimage. If this value changes, the on-wire genesis format changed and
// every deployed verifier must be updated — that is a breaking change, not a
// refactor. Do not "fix" this constant to match new output without treating it
// as a wire-format break.
const goldenSessionOpenGenesis = "g1:4e3d35d36683d6d5c65e427b447ada0d2e9098befff7caad954972bdadd405ec"

func fixedSessionOpen() SessionOpen {
	return SessionOpen{
		RunNonce:             "run-nonce-aaaa",
		OpenNonce:            "open-nonce-bbbb",
		RecorderSession:      "rec-sess-cccc",
		PolicyHash:           "policy-hash-dddd",
		SignerKeyEpoch:       "epoch-3",
		HeartbeatSeconds:     60,
		ChainOpenSeq:         0,
		GenesisAnchorHead:    "anchor-head-eeee",
		GenesisAnchorLog:     "anchor-log-ffff",
		PostureCapsuleSHA256: "capsule-sha-0000",
		ContainmentNonce:     "contain-nonce-1111",
		ContainedUID:         "966",
	}
}

func TestComputeSessionOpenGenesis_Golden(t *testing.T) {
	got := ComputeSessionOpenGenesis(fixedSessionOpen())

	if !strings.HasPrefix(got, genesisSessionOpenPrefix) {
		t.Fatalf("genesis missing %q prefix: %q", genesisSessionOpenPrefix, got)
	}
	// prefix + 64 hex chars.
	if len(got) != len(genesisSessionOpenPrefix)+64 {
		t.Fatalf("genesis wrong length: got %d, want %d (%q)",
			len(got), len(genesisSessionOpenPrefix)+64, got)
	}
	if got != goldenSessionOpenGenesis {
		t.Fatalf("session_open genesis drifted from golden.\n got=%q\nwant=%q\n"+
			"If this is an intentional wire-format change, update the golden AND "+
			"every deployed verifier.", got, goldenSessionOpenGenesis)
	}
}

func TestComputeSessionOpenGenesis_Deterministic(t *testing.T) {
	o := fixedSessionOpen()
	if a, b := ComputeSessionOpenGenesis(o), ComputeSessionOpenGenesis(o); a != b {
		t.Fatalf("genesis not deterministic: %q != %q", a, b)
	}
}

func TestComputeSessionOpenGenesis_FieldSensitivity(t *testing.T) {
	base := ComputeSessionOpenGenesis(fixedSessionOpen())

	mutators := map[string]func(*SessionOpen){
		"run_nonce":         func(o *SessionOpen) { o.RunNonce += "x" },
		"open_nonce":        func(o *SessionOpen) { o.OpenNonce += "x" },
		"recorder_session":  func(o *SessionOpen) { o.RecorderSession += "x" },
		"policy_hash":       func(o *SessionOpen) { o.PolicyHash += "x" },
		"signer_key_epoch":  func(o *SessionOpen) { o.SignerKeyEpoch += "x" },
		"heartbeat_seconds": func(o *SessionOpen) { o.HeartbeatSeconds++ },
		"anchor_head":       func(o *SessionOpen) { o.GenesisAnchorHead += "x" },
		"anchor_log":        func(o *SessionOpen) { o.GenesisAnchorLog += "x" },
		"posture_capsule":   func(o *SessionOpen) { o.PostureCapsuleSHA256 += "x" },
		"containment_nonce": func(o *SessionOpen) { o.ContainmentNonce += "x" },
		"contained_uid":     func(o *SessionOpen) { o.ContainedUID += "x" },
	}
	for name, mut := range mutators {
		t.Run(name, func(t *testing.T) {
			o := fixedSessionOpen()
			mut(&o)
			if got := ComputeSessionOpenGenesis(o); got == base {
				t.Fatalf("mutating %s did not change the genesis hash — field not bound", name)
			}
		})
	}
}

// TestComputeSessionOpenGenesis_NoBoundaryCollision proves the length-framing
// defeats concatenation ambiguity: two SessionOpens whose adjacent fields
// share the same concatenation but split at a different byte boundary MUST
// produce different genesis values. Without length framing these collide.
func TestComputeSessionOpenGenesis_NoBoundaryCollision(t *testing.T) {
	a := SessionOpen{RunNonce: "ab", OpenNonce: "c"}
	b := SessionOpen{RunNonce: "a", OpenNonce: "bc"}
	if ComputeSessionOpenGenesis(a) == ComputeSessionOpenGenesis(b) {
		t.Fatal("boundary collision: ('ab','c') and ('a','bc') hashed equal — length framing is broken")
	}
}

// TestCanonicalActionRecordV1_SessionControlOmitted proves an ordinary receipt
// (no SessionControl) canonicalizes with NO session_control key — existing
// receipts and their signatures are unaffected by this additive field.
func TestCanonicalActionRecordV1_SessionControlOmitted(t *testing.T) {
	ar := ActionRecord{Version: 1, ActionID: "a1"}
	b, err := canonicalActionRecordV1(ar)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	if bytes.Contains(b, []byte("session_control")) {
		t.Fatalf("bare record leaked a session_control key: %s", b)
	}
}

// TestCanonicalActionRecordV1_SessionControlPresent proves a session-control
// receipt canonicalizes deterministically and carries the nested open shape.
func TestCanonicalActionRecordV1_SessionControlPresent(t *testing.T) {
	o := fixedSessionOpen()
	ar := ActionRecord{
		Version:        1,
		ActionID:       "open-1",
		SessionControl: &SessionControl{Kind: SessionControlOpen, Open: &o},
	}
	first, err := canonicalActionRecordV1(ar)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	second, err := canonicalActionRecordV1(ar)
	if err != nil {
		t.Fatalf("canonicalize (2): %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Fatalf("canonical projection not byte-stable:\n%s\n%s", first, second)
	}
	for _, want := range []string{`"session_control"`, `"kind":"session_open"`, `"open"`, `"run_nonce":"run-nonce-aaaa"`} {
		if !bytes.Contains(first, []byte(want)) {
			t.Fatalf("canonical projection missing %s: %s", want, first)
		}
	}
	// Heartbeat/Close were not set — they must be omitted, not rendered null.
	if bytes.Contains(first, []byte(`"heartbeat"`)) || bytes.Contains(first, []byte(`"close"`)) {
		t.Fatalf("unset session-control variants not omitted: %s", first)
	}
}
