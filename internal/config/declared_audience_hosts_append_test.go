package config

import (
	"slices"
	"testing"
)

// TestAppendDeclaredCredentialAudienceHosts pins which declared host list
// joins which pattern, that a host already compiled or declared twice appears
// once, and that the result never aliases the compiled slice.
func TestAppendDeclaredCredentialAudienceHosts(t *testing.T) {
	compiled := []string{"github.com"}
	ghe := []string{"git.corp.example", "github.com", "git.corp.example"}
	gl := []string{"gitlab.corp.example"}
	for _, tc := range []struct {
		name string
		want []string
	}{
		{"GitHub Token", []string{"github.com", "git.corp.example"}},
		{"github fine-grained pat", []string{"github.com", "git.corp.example"}},
		{"GitLab PAT", []string{"github.com", "gitlab.corp.example"}},
		{"Slack Bot Token", []string{"github.com"}},
	} {
		got := AppendDeclaredCredentialAudienceHosts(tc.name, compiled, ghe, gl)
		if !slices.Equal(got, tc.want) {
			t.Errorf("%s: got %q, want %q", tc.name, got, tc.want)
		}
		got[0] = "mutated.example"
		if compiled[0] != "github.com" {
			t.Fatalf("%s: result aliases the compiled slice", tc.name)
		}
	}
	if got := AppendDeclaredCredentialAudienceHosts("GitHub Token", compiled, nil, gl); !slices.Equal(got, compiled) {
		t.Errorf("no declared GitHub hosts: got %q, want the compiled list", got)
	}
}
