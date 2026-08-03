// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"path/filepath"
	"strings"
)

// resolveGuardPath resolves symlinks in a guard path as far as the filesystem
// allows.
//
// filepath.EvalSymlinks fails outright when the final component does not exist
// yet, which is the normal case for a declared writable state path. Treating
// that failure as "use the literal path" is a fail-OPEN: an operator, or an
// attacker who can create one intermediate directory, can point
// /tmp/alias/.ssh/newfile at a real trust-bearing directory through a symlinked
// ANCESTOR, and the literal string reveals nothing. So when full resolution
// fails, walk up to the deepest ancestor that does exist, resolve THAT, and
// re-append the not-yet-existing remainder.
//
// This narrows but cannot close the check-to-use race: a path validated here
// can be replaced with a symlink before a runtime grant is created. The runtime
// evaluator must re-check using descriptor-based operations rather than
// trusting this load-time result.
func resolveGuardPath(rawPath string) string {
	cleaned := filepath.Clean(rawPath)
	if resolved, err := filepath.EvalSymlinks(cleaned); err == nil {
		return filepath.Clean(resolved)
	}

	remainder := ""
	current := cleaned
	for {
		parent := filepath.Dir(current)
		if parent == current {
			// Reached the filesystem root without finding an existing
			// ancestor; the literal cleaned path is all we have.
			return cleaned
		}
		remainder = filepath.Join(filepath.Base(current), remainder)
		current = parent
		if resolved, err := filepath.EvalSymlinks(current); err == nil {
			return filepath.Clean(filepath.Join(resolved, remainder))
		}
	}
}

// validateGuardROPath rejects read grants on secret-bearing locations.
//
// Read-only is NOT safe for this material under an agent threat model. A
// private SSH key, a GPG secret keyring, or a stored credential does not need
// to be modified to be lost: reading it is the exfiltration, and the copy
// leaves through any destination the workload is otherwise permitted to reach.
// Granting read on these paths would quietly undo the isolation the manifest
// exists to provide.
//
// Non-secret files that happen to live near this material can still be granted
// individually; what is refused here is the directory that holds keys.
func validateGuardROPath(label string, idx int, rawPath string) error {
	field := fmt.Sprintf("%s.read_only[%d]", label, idx)
	resolved := resolveGuardPath(rawPath)

	if comp := guardForbiddenComponent(resolved); comp != "" {
		return fmt.Errorf("%s: read access to secret-bearing path %q is not allowed (contains %q); reading a private key is exfiltration, not merely inspection", field, rawPath, comp)
	}
	// A grant on an entire home reads through to every credential beneath it,
	// which would defeat every rule in this file by granting the parent
	// instead of the target. The write side has always refused this; the read
	// side did not, so `read_only: [/home/someoperator]` was accepted and
	// carried ~/.ssh with it.
	if guardIsHomeRoot(resolved) {
		return fmt.Errorf("%s: read access to the entire home directory %q is not allowed; it reads through to every credential beneath it", field, rawPath)
	}
	if reason := guardSecretMaterialReason(resolved); reason != "" {
		return fmt.Errorf("%s: read access to %q is not allowed (%s); reading a credential is exfiltration, not merely inspection", field, rawPath, reason)
	}
	// Pipelock config and state directories contain credential material
	// (license_key, kill_switch.api_token, secrets_file) that a read grant
	// would expose. The suffix check covers every user's home, not just this
	// process's, matching the write-side guard in validateGuardRWPath.
	if suffix := guardForbiddenSuffix(resolved); suffix != "" {
		if strings.Contains(suffix, "pipelock") {
			return fmt.Errorf("%s: read access to %s %q is not allowed; it may contain credential material", field, suffix, rawPath)
		}
	}
	return nil
}

// guardSecretShapes are paths that hold credential material, expressed as
// shapes rather than as one operator's concrete paths.
//
// Each entry is matched relative to a home root detected by SHAPE (see
// guardHomeRootOf), never against os.UserHomeDir(). Pipelock commonly runs as
// a system service, so a home-derived list would protect /root while leaving
// every real operator's home unguarded -- the same reasoning that made
// guardForbiddenComponents component-matched.
//
// The list is deliberately static rather than a live filesystem probe. A probe
// would make validation machine-dependent (a manifest that loads on the build
// host fails on the deploy host) and, worse, fail OPEN for the ordinary case
// where the credential file simply has not been created yet.
var guardSecretShapes = []struct {
	shape  string // path relative to a home root, POSIX separators
	reason string
}{
	{".aws/credentials", "AWS credentials file"},
	{".kube/config", "kubeconfig, which embeds client certificates and tokens"},
	{".docker/config.json", "docker registry auth file"},
	{".npmrc", "npm config, which holds registry auth tokens"},
	{".pypirc", "PyPI config, which holds upload tokens"},
	{".netrc", "netrc, which holds plaintext machine credentials"},
	{".config/gh/hosts.yml", "GitHub CLI credential file"},
	{".config/gcloud/credentials.db", "gcloud credential database"},
	{".config/gcloud/application_default_credentials.json", "gcloud application default credentials"},
	{".git-credentials", "git credential store"},
	{".config/pip/pip.conf", "pip config, which may hold index credentials"},
	{".claude.json", "Claude Code config, which holds MCP server credentials"},
	{".codex/auth.json", "Codex CLI credential file"},
	{".config/anthropic", "Anthropic tooling credential directory"},
}

// guardSecretAbsolutePaths are absolute locations holding credential material
// that is not relative to any user home.
var guardSecretAbsolutePaths = []struct {
	path   string
	reason string
}{
	{"/etc/shadow", "the shadow password database"},
	{"/etc/gshadow", "the shadow group database"},
}

// guardHomeRootOf returns the user home directory that contains resolved, or
// "" when the path is not under a recognizable home.
//
// POSIX-only, matching guardIsHomeRoot: the function hardcodes "/" as the
// separator and knows the /home, /Users and /root layouts. Windows path
// handling is an open product decision tracked in ops (AF-264).
func guardHomeRootOf(resolved string) string {
	if resolved == "/root" || strings.HasPrefix(resolved, "/root/") {
		return "/root"
	}
	for _, root := range []string{"/home", "/Users"} {
		if !strings.HasPrefix(resolved, root+"/") {
			continue
		}
		rest := strings.TrimPrefix(resolved, root+"/")
		user, _, _ := strings.Cut(rest, "/")
		if user == "" {
			continue
		}
		return root + "/" + user
	}
	return ""
}

// guardMultiHomeRoots are directories that sit ABOVE every user home, so a
// grant on one reads through to every operator's credentials at once.
var guardMultiHomeRoots = []string{"/", "/home", "/Users"}

// guardSecretMaterialReason reports why the resolved path exposes credential
// material, or "" when it does not.
//
// A path is refused when it IS a secret path, is BENEATH one, or is a strict
// ANCESTOR of one. The ancestor case is the load-bearing one and is easy to
// leave out: Landlock grants an access right to an entire directory SUBTREE,
// so a rule permitting ~/.aws permits ~/.aws/credentials with it. Without the
// ancestor arm, every entry in guardSecretShapes is decorative -- an operator
// (or an attacker editing a manifest) reaches the credential by naming the
// parent instead of the file.
//
// The cost is deliberate and falls on availability: ~/.aws, ~/.docker, ~/.kube
// and ~/.config cannot be granted as whole directories. The operator names the
// specific non-secret path instead (~/.aws/config, ~/.config/myapp), which is
// the explicit, no-inference model GuardManifest already commits to.
func guardSecretMaterialReason(resolved string) string {
	for _, root := range guardMultiHomeRoots {
		if resolved == root {
			return "it sits above every user home and reads through to every credential beneath it"
		}
	}
	for _, entry := range guardSecretAbsolutePaths {
		if r := guardSecretRelation(resolved, entry.path, entry.reason); r != "" {
			return r
		}
	}
	home := guardHomeRootOf(resolved)
	if home == "" {
		return ""
	}
	for _, entry := range guardSecretShapes {
		secret := home + "/" + entry.shape
		if r := guardSecretRelation(resolved, secret, entry.reason); r != "" {
			return r
		}
	}
	return ""
}

// guardSecretRelation reports how resolved relates to a known secret path, or
// "" when the two are unrelated.
func guardSecretRelation(resolved, secret, reason string) string {
	switch {
	case resolved == secret:
		return "it is " + reason
	case strings.HasPrefix(resolved, secret+"/"):
		return "it is inside " + reason
	case strings.HasPrefix(secret, resolved+"/"):
		// Strict ancestor: granting this directory grants everything under it,
		// including the secret.
		return "it contains " + reason + " (" + secret + "), and a directory grant reaches everything beneath it"
	}
	return ""
}

// guardForbiddenComponents are directory names that must never appear anywhere
// in a read-write grant, whichever user owns them.
var guardForbiddenComponents = map[string]struct{}{
	".ssh":   {},
	".gnupg": {},
	".gpg":   {},
}

// guardForbiddenComponent reports the first trust-bearing path component in the
// resolved path, or "" when none is present.
//
// Matching on components rather than on a prefix derived from this process's
// home directory is deliberate. Pipelock commonly runs as a system service, so
// os.UserHomeDir() returns /root; a home-derived list would protect /root/.ssh
// while leaving every real operator's ~/.ssh unguarded.
func guardForbiddenComponent(resolved string) string {
	for _, part := range strings.Split(resolved, string(filepath.Separator)) {
		if _, bad := guardForbiddenComponents[part]; bad {
			return part
		}
	}
	return ""
}

// guardForbiddenSuffixes are trailing path shapes identifying Pipelock's own
// state, autostart locations, and other write-sensitive directories under ANY
// user's home rather than only this process's home.
var guardForbiddenSuffixes = []struct {
	suffix string
	reason string
}{
	{filepath.Join(".local", "share", "pipelock"), "pipelock state directory"},
	{filepath.Join(".config", "pipelock"), "pipelock config directory"},
	{".pipelock", "pipelock directory"},
	{filepath.Join(".config", "autostart"), "autostart directory"},
	{filepath.Join("Library", "LaunchAgents"), "autostart directory"},
	{filepath.Join("Library", "LaunchDaemons"), "autostart directory"},
	{filepath.Join("etc", "pipelock"), "pipelock config directory"},
}

// guardForbiddenSuffix reports why the resolved path is write-sensitive, or ""
// when it is not. A match is the directory itself or anything beneath it.
func guardForbiddenSuffix(resolved string) string {
	for _, entry := range guardForbiddenSuffixes {
		marker := string(filepath.Separator) + entry.suffix
		if strings.HasSuffix(resolved, marker) || strings.Contains(resolved, marker+string(filepath.Separator)) {
			return entry.reason
		}
	}
	return ""
}

// guardIsHomeRoot reports whether the resolved path is an entire user home
// directory on a supported platform layout, without depending on which user
// this process runs as.
//
// POSIX-only: the function hardcodes "/" as the separator and checks the
// /home and /Users roots. On Windows, resolved paths use "\" and neither
// root applies, so the check silently passes. Windows path handling is an
// open product decision tracked in ops (AF-264).
func guardIsHomeRoot(resolved string) bool {
	// Homes that are a fixed path rather than a directory under a parent.
	// /root is the home of the account Pipelock most often runs as when it runs
	// as a system service, and "/" is the effective home in many containers.
	// Both were previously covered only by the os.UserHomeDir()-derived block
	// that was deleted as "fully shadowed" by these helpers. That claim was
	// wrong for exactly this case: when the process runs as root, the deleted
	// block did catch /root and nothing here replaced it, so a whole-/root
	// read-write grant was accepted. Handle them explicitly.
	for _, fixed := range []string{"/root", "/"} {
		if resolved == fixed {
			return true
		}
	}
	for _, root := range []string{"/home", "/Users"} {
		if !strings.HasPrefix(resolved, root+"/") {
			continue
		}
		rest := strings.TrimPrefix(resolved, root+"/")
		if rest != "" && !strings.Contains(rest, "/") {
			return true
		}
	}
	return false
}
