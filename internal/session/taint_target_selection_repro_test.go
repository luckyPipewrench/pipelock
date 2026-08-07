// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package session_test

import (
	"slices"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/session"
)

func TestClassifyMCPToolCall_TargetSelection(t *testing.T) {
	tests := []struct {
		name             string
		args             string
		wantClass        session.ActionClass
		wantSensitivity  session.ActionSensitivity
		wantRef          string
		wantOverrideRefs []string
		wantConfident    bool
	}{
		{
			name:             "most restrictive target wins despite key order",
			args:             `{"path":"/srv/prod/db.conf","archive_path":"/tmp/notes.txt"}`,
			wantClass:        session.ActionClassWrite,
			wantSensitivity:  session.SensitivityProtected,
			wantRef:          "/srv/prod/db.conf",
			wantOverrideRefs: []string{"/srv/prod/db.conf"},
			wantConfident:    true,
		},
		{
			name:             "renamed keys do not change sensitivity",
			args:             `{"a_path":"/srv/prod/db.conf","z_path":"/tmp/notes.txt"}`,
			wantClass:        session.ActionClassWrite,
			wantSensitivity:  session.SensitivityProtected,
			wantRef:          "/srv/prod/db.conf",
			wantOverrideRefs: []string{"/srv/prod/db.conf"},
			wantConfident:    true,
		},
		{
			name:             "secret-looking prose is not a target",
			args:             `{"path":"/tmp/notes.txt","note":"do not touch ~/.ssh/id_rsa"}`,
			wantClass:        session.ActionClassWrite,
			wantSensitivity:  session.SensitivityNormal,
			wantRef:          "/tmp/notes.txt",
			wantOverrideRefs: []string{"/tmp/notes.txt"},
			wantConfident:    true,
		},
		{
			name:            "secret-looking prose alone is low confidence",
			args:            `{"note":"do not touch ~/.ssh/id_rsa"}`,
			wantClass:       session.ActionClassWrite,
			wantSensitivity: session.SensitivityNormal,
			wantRef:         "",
			wantConfident:   false,
		},
		{
			name:             "all secret targets constrain overrides",
			args:             `{"path":"/home/developer/.ssh/id_rsa","archive_path":"/home/developer/.aws/credentials"}`,
			wantClass:        session.ActionClassSecret,
			wantSensitivity:  session.SensitivityProtected,
			wantRef:          "/home/developer/.aws/credentials",
			wantOverrideRefs: []string{"/home/developer/.aws/credentials", "/home/developer/.ssh/id_rsa"},
			wantConfident:    true,
		},
		{
			name:             "prose-like key cannot hide standalone protected path",
			args:             `{"payload":"/srv/prod/db archive.conf","note":"ordinary prose"}`,
			wantClass:        session.ActionClassWrite,
			wantSensitivity:  session.SensitivityProtected,
			wantRef:          "/srv/prod/db archive.conf",
			wantOverrideRefs: []string{"/srv/prod/db archive.conf"},
			wantConfident:    true,
		},
		{
			name:             "target role admits path containing spaces",
			args:             `{"destinationPath":"srv/prod config.conf"}`,
			wantClass:        session.ActionClassWrite,
			wantSensitivity:  session.SensitivityProtected,
			wantRef:          "srv/prod config.conf",
			wantOverrideRefs: []string{"srv/prod config.conf"},
			wantConfident:    true,
		},
		{
			name:             "target array uses most restrictive member",
			args:             `{"paths":["/tmp/notes.txt","/srv/prod/db.conf"]}`,
			wantClass:        session.ActionClassWrite,
			wantSensitivity:  session.SensitivityProtected,
			wantRef:          "/srv/prod/db.conf",
			wantOverrideRefs: []string{"/srv/prod/db.conf"},
			wantConfident:    true,
		},
		{
			name:             "equally sensitive target preserves legacy reference",
			args:             `{"path":"/tmp/current.txt","archive_path":"/tmp/archive.txt"}`,
			wantClass:        session.ActionClassWrite,
			wantSensitivity:  session.SensitivityNormal,
			wantRef:          "/tmp/archive.txt",
			wantOverrideRefs: []string{"/tmp/archive.txt", "/tmp/current.txt"},
			wantConfident:    true,
		},
		{
			name:             "malformed arguments preserve legacy reference",
			args:             `/tmp/legacy.txt`,
			wantClass:        session.ActionClassWrite,
			wantSensitivity:  session.SensitivityNormal,
			wantRef:          "/tmp/legacy.txt",
			wantOverrideRefs: []string{"/tmp/legacy.txt"},
			wantConfident:    true,
		},
		{
			name:             "write URL preserves legacy target reference",
			args:             `{"url":"https://api.vendor.example/resource"}`,
			wantClass:        session.ActionClassWrite,
			wantSensitivity:  session.SensitivityNormal,
			wantRef:          "https://api.vendor.example/resource",
			wantOverrideRefs: []string{"https://api.vendor.example/resource"},
			wantConfident:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := session.ClassifyMCPToolCallWithOptions(
				"write_file",
				tt.args,
				[]string{"/srv/prod/*", "srv/*"},
				nil,
				session.ClassificationOptions{},
			)
			if got.Class != tt.wantClass || got.Sensitivity != tt.wantSensitivity || got.ActionRef != tt.wantRef || got.Confident != tt.wantConfident {
				t.Fatalf("classification = %+v, want class=%s sensitivity=%s actionRef=%q confident=%v",
					got, tt.wantClass, tt.wantSensitivity, tt.wantRef, tt.wantConfident)
			}
			if !slices.Equal(got.OverrideRefs, tt.wantOverrideRefs) {
				t.Fatalf("override refs = %q, want %q", got.OverrideRefs, tt.wantOverrideRefs)
			}
		})
	}
}
