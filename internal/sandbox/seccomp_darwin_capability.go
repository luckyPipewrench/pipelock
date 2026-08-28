//go:build darwin

package sandbox

// seccompFilterSupportedByBuild reports whether this binary contains
// Pipelock's seccomp filter implementation. seccomp is a Linux facility, so a
// darwin build never carries one.
//
// This definition exists for build-tag symmetry rather than for a current
// caller: today the only caller is Detect in detect_linux.go. Without it,
// darwin is the one target that gets neither the linux/amd64 nor the
// seccomp_other.go definition, so the first cross-platform caller would break
// the darwin build rather than get an honest answer.
func seccompFilterSupportedByBuild() bool {
	return false
}
