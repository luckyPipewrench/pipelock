// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receipt

import "testing"

func TestIsGracefulSessionCloseSeal(t *testing.T) {
	tests := []struct {
		name    string
		control *SessionControl
		want    bool
	}{
		{name: "missing control"},
		{
			name: "wrong kind",
			control: &SessionControl{
				Kind:  SessionControlOpen,
				Close: &SessionClose{CloseReason: gracefulSessionCloseReason},
			},
		},
		{name: "missing close", control: &SessionControl{Kind: SessionControlClose}},
		{
			name: "non-graceful close",
			control: &SessionControl{
				Kind:  SessionControlClose,
				Close: &SessionClose{CloseReason: "crash_recovery"},
			},
		},
		{
			name: "graceful close",
			control: &SessionControl{
				Kind:  SessionControlClose,
				Close: &SessionClose{CloseReason: gracefulSessionCloseReason},
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := Receipt{}
			r.ActionRecord.SessionControl = tt.control
			if got := IsGracefulSessionCloseSeal(r); got != tt.want {
				t.Fatalf("IsGracefulSessionCloseSeal() = %t, want %t", got, tt.want)
			}
		})
	}
}
