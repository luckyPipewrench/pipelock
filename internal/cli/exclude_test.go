package cli

import "testing"

func TestShouldExclude(t *testing.T) {
	tests := []struct {
		name     string
		file     string
		patterns []string
		want     bool
	}{
		{
			name:     "no patterns",
			file:     "main.go",
			patterns: nil,
			want:     false,
		},
		{
			name:     "exact match",
			file:     "vendor/lib.go",
			patterns: []string{"vendor/lib.go"},
			want:     true,
		},
		{
			name:     "no match",
			file:     "main.go",
			patterns: []string{"vendor/lib.go"},
			want:     false,
		},
		{
			name:     "directory prefix",
			file:     "vendor/pkg/lib.go",
			patterns: []string{"vendor/"},
			want:     true,
		},
		{
			name:     "directory prefix no match",
			file:     "src/vendor.go",
			patterns: []string{"vendor/"},
			want:     false,
		},
		{
			name:     "glob on full path",
			file:     "pkg/gen.pb.go",
			patterns: []string{"pkg/*.pb.go"},
			want:     true,
		},
		{
			name:     "glob on basename",
			file:     "deep/nested/file.generated.go",
			patterns: []string{"*.generated.go"},
			want:     true,
		},
		{
			name:     "glob basename no match",
			file:     "deep/nested/file.go",
			patterns: []string{"*.generated.go"},
			want:     false,
		},
		{
			name:     "multiple patterns first matches",
			file:     "vendor/foo.go",
			patterns: []string{"vendor/", "test/"},
			want:     true,
		},
		{
			name:     "multiple patterns second matches",
			file:     "test/helper.go",
			patterns: []string{"vendor/", "test/"},
			want:     true,
		},
		{
			name:     "empty pattern ignored",
			file:     "main.go",
			patterns: []string{"", "vendor/"},
			want:     false,
		},
		{
			name:     "empty file never excluded",
			file:     "",
			patterns: []string{"vendor/"},
			want:     false,
		},
		{
			name:     "backslash path normalized",
			file:     "vendor\\pkg\\lib.go",
			patterns: []string{"vendor/"},
			want:     true,
		},
		{
			name:     "backslash pattern normalized",
			file:     "vendor/pkg/lib.go",
			patterns: []string{"vendor\\"},
			want:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := shouldExclude(tt.file, tt.patterns)
			if got != tt.want {
				t.Errorf("shouldExclude(%q, %v) = %v, want %v", tt.file, tt.patterns, got, tt.want)
			}
		})
	}
}
