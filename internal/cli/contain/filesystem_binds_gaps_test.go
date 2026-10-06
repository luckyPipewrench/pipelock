// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"strings"
	"testing"
)

func TestParseTypedSystemdBindsRejectsMalformedBodies(t *testing.T) {
	oversized := `{"type":"a(ssbt)","data":["` + strings.Repeat("x", maxCmdOutputBytes) + `"]}`
	tests := []struct {
		name string
		body string
		want string
	}{
		{name: "empty", body: " \n", want: "empty"},
		{name: "oversize", body: oversized, want: "exceeds bound"},
		{name: "duplicate type", body: `{"type":"a(ssbt)","data":[],"type":"a(ssbt)"}`, want: "invalid typed systemd bind JSON"},
		{name: "folded alias", body: `{"Type":"a(ssbt)","data":[]}`, want: "invalid typed systemd bind fields"},
		{name: "not json", body: `{"type"`, want: "invalid typed systemd bind JSON"},
		{name: "wrong signature", body: `{"type":"as","data":[]}`, want: `signature "as"`},
		{name: "short entry", body: `{"type":"a(ssbt)","data":[["/src","/src",false]]}`, want: "four fields"},
		{name: "wrong field type", body: `{"type":"a(ssbt)","data":[[1,"/src",false,0]]}`, want: "decode typed systemd bind entry"},
		{name: "blank source", body: `{"type":"a(ssbt)","data":[["","/src",false,0]]}`, want: "missing a path"},
		{name: "ignore missing", body: `{"type":"a(ssbt)","data":[["/src","/src",true,0]]}`, want: "ignores a missing path"},
		{name: "unexpected flags", body: `{"type":"a(ssbt)","data":[["/src","/src",false,1]]}`, want: "unexpected flags"},
		{name: "unknown field", body: `{"type":"a(ssbt)","data":[],"extra":true}`, want: "decode typed systemd binds"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseTypedSystemdBinds([]byte(tt.body))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestMatchTypedBindEntriesRejectsRecordedShape(t *testing.T) {
	got := []systemdBindEntry{{Source: "/src", Destination: "/src"}}
	tests := []struct {
		name string
		want []string
		msg  string
	}{
		{name: "not a triple", want: []string{"nosep"}, msg: "not src:dest:option"},
		{name: "missing option", want: []string{"/src:/src"}, msg: "not src:dest:option"},
		{name: "extra colon", want: []string{"/src:/a:/b:norbind"}, msg: "differ from managed launch"},
		{name: "unknown option", want: []string{canonicalBind("/src", "/src", "maybe")}, msg: "not norbind or rbind"},
		{name: "different path", want: []string{canonicalBind("/other", "/other", "norbind")}, msg: "differ from managed launch"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := matchTypedBindEntries(got, tt.want)
			if err == nil || !strings.Contains(err.Error(), tt.msg) {
				t.Fatalf("err = %v, want %q", err, tt.msg)
			}
		})
	}
	if sameBindList([]string{"/a:/a:norbind"}, []string{"/a:/a:norbind", "/b:/b:rbind"}) {
		t.Fatal("different lengths compared equal")
	}
}

func TestParseSystemdBindShowRejectsQuotedAndTupleShapes(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  string
	}{
		{name: "token error", value: `"unterminated`, want: "unbalanced quote"},
		{name: "empty quoted", value: `""`, want: "empty"},
		{name: "bad colon option", value: "/src:/src:maybe", want: "not norbind or rbind"},
		{name: "blank tuple path", value: `"" /src false 0`, want: "incomplete entry"},
		{name: "quoted escape", value: `"/sr\"c\\dir" "/sr\"c\\dir" false 0`, want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseSystemdBindShow(tt.value)
			if tt.want == "" {
				if err != nil || len(got) != 1 || !strings.Contains(got[0], `/sr"c\dir`) {
					t.Fatalf("got %v err %v", got, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v, want %q", err, tt.want)
			}
		})
	}
	if _, ok := parseSpacedColonBind(`"/src":"/src":norbind`); ok {
		t.Fatal("quoted spaced form was accepted")
	}
	if _, ok := parseSpacedColonBind("not-absolute:norbind"); ok {
		t.Fatal("relative spaced form was accepted")
	}
	if got := unquoteSystemdPath(`"/sr\"c\\dir"`); got != `/sr"c\dir` {
		t.Fatalf("unquote = %q", got)
	}
	if got := unquoteSystemdPath(`/plain`); got != "/plain" {
		t.Fatalf("plain unquote = %q", got)
	}
	if _, _, ok := splitAbsoluteColon("relative"); ok {
		t.Fatal("relative colon split")
	}
	if _, err := parseTupleBind("", "/dest", "false", "0"); err == nil {
		t.Fatal("accepted an empty source")
	}
}
