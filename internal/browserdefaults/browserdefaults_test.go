// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package browserdefaults

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func argsOf(t *testing.T, data []byte) (string, bool) {
	t.Helper()
	obj, err := Parse(data)
	if err != nil {
		t.Fatalf("parse %q: %v", data, err)
	}
	if _, ok := obj["args"]; !ok {
		return "", false
	}
	args, err := Args(obj)
	if err != nil {
		t.Fatalf("args: %v", err)
	}
	return args, true
}

func TestMergeRemoveRoundTrip(t *testing.T) {
	tests := []struct {
		name     string
		in       string
		existed  bool
		wantArgs string
		// after removal: file deleted, or the exact args value restored
		wantRemoved bool
		wantBack    string
		wantHasArgs bool
	}{
		{name: "no file", in: "", existed: false, wantArgs: Flag, wantRemoved: true},
		{name: "empty file", in: "  \n", existed: true, wantArgs: Flag, wantBack: "", wantHasArgs: false},
		{name: "other keys", in: `{"headed":true}`, existed: true, wantArgs: Flag, wantHasArgs: false},
		{name: "comma args", in: `{"args":"--a,--b"}`, existed: true, wantArgs: "--a,--b," + Flag, wantBack: "--a,--b", wantHasArgs: true},
		{name: "newline args", in: `{"args":"--a\n--b"}`, existed: true, wantArgs: "--a\n--b," + Flag, wantBack: "--a\n--b", wantHasArgs: true},
		{name: "explicit empty args", in: `{"args":""}`, existed: true, wantArgs: Flag, wantBack: "", wantHasArgs: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, rec, already, err := Merge([]byte(tt.in), tt.existed)
			if err != nil || already {
				t.Fatalf("merge: already=%v err=%v", already, err)
			}
			if rec.Created != !tt.existed {
				t.Fatalf("record created=%v, want %v", rec.Created, !tt.existed)
			}
			got, _ := argsOf(t, out)
			if got != tt.wantArgs {
				t.Fatalf("merged args %q, want %q", got, tt.wantArgs)
			}
			if tt.in != "" && strings.Contains(tt.in, "headed") && !strings.Contains(string(out), `"headed": true`) {
				t.Fatalf("other key dropped: %s", out)
			}
			// Re-merge is a no-op.
			if _, _, again, err := Merge(out, true); err != nil || !again {
				t.Fatalf("second merge: already=%v err=%v", again, err)
			}
			// Record survives a stored round trip.
			decoded, err := DecodeRecord(rec.Marshal())
			if err != nil || decoded != rec {
				t.Fatalf("record round trip: %+v vs %+v err=%v", decoded, rec, err)
			}
			back, remove, changed, err := Remove(out, decoded)
			if err != nil || !changed {
				t.Fatalf("remove: changed=%v err=%v", changed, err)
			}
			if remove != tt.wantRemoved {
				t.Fatalf("remove=%v, want %v", remove, tt.wantRemoved)
			}
			if remove {
				return
			}
			args, has := argsOf(t, back)
			if has != tt.wantHasArgs || args != tt.wantBack {
				t.Fatalf("restored args %q (present=%v), want %q (present=%v)", args, has, tt.wantBack, tt.wantHasArgs)
			}
		})
	}
}

func TestMergeAlreadyPresent(t *testing.T) {
	for _, in := range []string{
		`{"args":"` + Flag + `"}`,
		`{"args":"--a,` + Flag + `"}`,
		`{"args":"--a\n ` + Flag + `"}`,
	} {
		out, rec, already, err := Merge([]byte(in), true)
		if err != nil || !already || out != nil || rec != (Record{}) {
			t.Fatalf("%s: already=%v out=%q rec=%+v err=%v", in, already, out, rec, err)
		}
		present, err := Inspect([]byte(in))
		if err != nil || !present {
			t.Fatalf("inspect %s: present=%v err=%v", in, present, err)
		}
	}
}

func TestMergeRefusesBadInput(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want error
	}{
		{"malformed", `{"args":`, ErrMalformed},
		{"array", `[]`, ErrMalformed},
		{"null", `null`, ErrMalformed},
		{"number args", `{"args":1}`, ErrArgsNotString},
		{"null args", `{"args":null}`, ErrArgsNotString},
		{"list args", `{"args":["--a"]}`, ErrArgsNotString},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, _, _, err := Merge([]byte(tt.in), true); !errors.Is(err, tt.want) {
				t.Fatalf("merge err=%v, want %v", err, tt.want)
			}
			if _, err := Inspect([]byte(tt.in)); !errors.Is(err, tt.want) {
				t.Fatalf("inspect err=%v, want %v", err, tt.want)
			}
			if _, _, _, err := Remove([]byte(tt.in), Record{}); !errors.Is(err, tt.want) {
				t.Fatalf("remove err=%v, want %v", err, tt.want)
			}
		})
	}
}

func TestRemoveKeepsLaterEditsAndOperatorCopy(t *testing.T) {
	out, rec, _, err := Merge([]byte(`{"args":"--a"}`), true)
	if err != nil {
		t.Fatal(err)
	}
	// The agent adds its own argument after install.
	obj, _ := Parse(out)
	obj["args"], _ = json.Marshal("--a," + Flag + ",--later")
	edited, _ := Encode(obj)
	back, _, changed, err := Remove(edited, rec)
	if err != nil || !changed {
		t.Fatalf("remove: changed=%v err=%v", changed, err)
	}
	if args, _ := argsOf(t, back); args != "--a,--later" {
		t.Fatalf("args %q", args)
	}

	// An operator copy before Pipelock's appended one survives removal.
	dup := []byte(`{"args":"` + Flag + `,` + Flag + `"}`)
	back, _, _, err = Remove(dup, Record{OriginalArgs: Flag, HadArgs: true})
	if err != nil {
		t.Fatal(err)
	}
	if args, _ := argsOf(t, back); args != Flag {
		t.Fatalf("args %q", args)
	}

	// Flag already gone: nothing to write.
	if _, remove, changed, err := Remove([]byte(`{"args":"--a"}`), rec); err != nil || changed || remove {
		t.Fatalf("absent flag: remove=%v changed=%v err=%v", remove, changed, err)
	}

	// Created file with another key added later is kept.
	out, rec, _, _ = Merge(nil, false)
	obj, _ = Parse(out)
	obj["headed"] = json.RawMessage("true")
	edited, _ = Encode(obj)
	back, remove, _, err := Remove(edited, rec)
	if err != nil || remove {
		t.Fatalf("created+edited: remove=%v err=%v", remove, err)
	}
	if strings.Contains(string(back), Flag) || !strings.Contains(string(back), "headed") {
		t.Fatalf("unexpected %s", back)
	}
}

func TestDecodeRecordStrict(t *testing.T) {
	tests := []string{
		``,
		`{}`,
		`{"created":null,"original_args":"","had_args":false}`,
		`{"created":true,"had_args":false}`,
		`{"created":true,"original_args":"","had_args":null}`,
		`{"created":"yes","original_args":"","had_args":false}`,
		`{"created":true,"original_args":"","had_args":false,"path":null}`,
	}
	for _, in := range tests {
		if _, err := DecodeRecord([]byte(in)); err == nil {
			t.Fatalf("expected refusal for %q", in)
		}
	}
	// A record from before the path field existed still decodes.
	rec, err := DecodeRecord([]byte(`{"created":false,"original_args":"--a","had_args":true}`))
	if err != nil || rec.Path != "" || rec.OriginalArgs != "--a" || !rec.HadArgs {
		t.Fatalf("legacy record: %+v err=%v", rec, err)
	}
}
