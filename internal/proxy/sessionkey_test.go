package proxy

import "testing"

func TestSessionKeyFor(t *testing.T) {
	tests := []struct {
		name     string
		agent    string
		clientIP string
		want     string
	}{
		{
			name:     "named agent namespaces ahead of ip",
			agent:    "agent-a",
			clientIP: "10.0.0.1",
			want:     "agent-a|10.0.0.1",
		},
		{
			name:     "empty agent keys on ip alone",
			agent:    "",
			clientIP: "10.0.0.1",
			want:     "10.0.0.1",
		},
		{
			name:     "anonymous agent keys on ip alone",
			agent:    agentAnonymous,
			clientIP: "10.0.0.1",
			want:     "10.0.0.1",
		},
		{
			name:     "two named agents on same ip stay distinct",
			agent:    "agent-b",
			clientIP: "10.0.0.1",
			want:     "agent-b|10.0.0.1",
		},
		{
			name:     "named agent with empty ip",
			agent:    "agent-a",
			clientIP: "",
			want:     "agent-a|",
		},
		{
			name:     "empty agent and empty ip",
			agent:    "",
			clientIP: "",
			want:     "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := sessionKeyFor(tt.agent, tt.clientIP); got != tt.want {
				t.Errorf("sessionKeyFor(%q, %q) = %q, want %q", tt.agent, tt.clientIP, got, tt.want)
			}
		})
	}
}
