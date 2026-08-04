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
func validateGuardROPath(label, fieldName string, idx int, rawPath string) error {
	field := fmt.Sprintf("%s.%s[%d]", label, fieldName, idx)
	resolved := resolveGuardPath(rawPath)

	if comp, reason := guardForbiddenComponent(resolved); comp != "" {
		return fmt.Errorf("%s: read access to secret-bearing path %q is not allowed (contains %q, which is %s); reading credential material is exfiltration, not merely inspection", field, rawPath, comp, reason)
	}
	// A grant on an entire home reads through to every credential beneath it,
	// which would defeat every rule in this file by granting the parent
	// instead of the target. The write side has always refused this; the read
	// side did not, so `read_only: [/home/someoperator]` was accepted and
	// carried ~/.ssh with it.
	if guardIsHomeRoot(resolved) {
		return fmt.Errorf("%s: read access to the entire home directory %q is not allowed; it reads through to every credential beneath it", field, rawPath)
	}
	if reason := guardDeclaredPathSecretMaterialReason(rawPath, resolved); reason != "" {
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

// guardDeclaredPathSecretMaterialReason evaluates both the declared spelling
// and its current symlink-resolved target. The declared spelling is itself a
// security boundary: a ~/.aws symlink may resolve outside a recognized home,
// but granting it still grants the credential location the manifest named.
// Conversely, checking the resolved path preserves the existing protection
// against an innocuous-looking alias that points into credential material.
func guardDeclaredPathSecretMaterialReason(rawPath, resolved string) string {
	for _, candidate := range []string{filepath.Clean(rawPath), resolved} {
		if reason := guardSecretMaterialReason(candidate); reason != "" {
			return reason
		}
	}
	return ""
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
	// Cloud provider credential state. The whole of .aws is listed rather than
	// only the credentials file: .aws/config carries SSO settings and
	// credential_process directives, and the sso and cli cache directories
	// hold live session tokens, so the non-secret remainder is not worth
	// carving out.
	{".aws", "the AWS credential directory, including SSO and CLI session caches"},
	{".azure", "the Azure credential directory"},
	{".config/gcloud/credentials.db", "the gcloud credential database"},
	{".config/gcloud/access_tokens.db", "the gcloud access token database"},
	{".config/gcloud/application_default_credentials.json", "gcloud application default credentials"},
	{".config/gcloud/legacy_credentials", "legacy gcloud credentials"},

	// Cluster and container registry auth, refused whole rather than by
	// filename. Carving out the non-secret siblings (a discovery cache, buildx
	// builder state) is what lets a renamed credential through, and both
	// siblings are regenerable caches rather than irreplaceable state, so the
	// carve-out buys little and costs the variant case below.
	{".kube", "the kubeconfig directory, whose files embed client certificates and tokens"},
	{".docker", "the docker credential directory"},
	{".config/containers/auth.json", "the containers registry auth file"},
	{".config/helm/registry/config.json", "the helm registry auth file"},

	// Package index and version control credentials.
	{".npmrc", "the npm config, which holds registry auth tokens"},
	{".pypirc", "the PyPI config, which holds upload tokens"},
	{".config/pip/pip.conf", "the pip config, which may hold index credentials"},
	{".config/pypoetry/auth.toml", "the poetry auth file"},
	{".cargo/credentials", "the cargo registry credential file"},
	{".cargo/credentials.toml", "the cargo registry credential file"},
	{".netrc", "the netrc, which holds plaintext machine credentials"},
	{".git-credentials", "the git credential store"},
	{".config/gh/hosts.yml", "the GitHub CLI credential file"},

	// Infrastructure-as-code tokens.
	{".terraform.d/credentials.tfrc.json", "the Terraform credential file"},
	{".pulumi/credentials.json", "the Pulumi credential file"},

	// AI agent and MCP state. MCP configuration counts as credential-bearing
	// whether or not a given file currently holds a secret: the format carries
	// per-server env, headers and command arguments, which is where API keys
	// for every downstream tool end up.
	{".claude.json", "the Claude Code config, which carries MCP server credentials"},
	{".claude/.credentials.json", "the Claude Code credential file"},
	{".claude/settings.json", "the Claude Code settings file, which carries MCP server credentials"},
	{".codex/auth.json", "the Codex CLI credential file"},
	{".codex/config.toml", "the Codex CLI config, which carries MCP server credentials"},
	{".gemini/oauth_creds.json", "the Gemini CLI credential file"},
	{".cursor/mcp.json", "the Cursor MCP config, which carries server credentials"},
	{".config/Claude/claude_desktop_config.json", "the Claude Desktop MCP config"},
	{"Library/Application Support/Claude/claude_desktop_config.json", "the Claude Desktop MCP config"},
	{".config/anthropic", "the Anthropic tooling credential directory"},
}

// guardSecretAbsolutePaths are absolute locations holding credential material
// that is not relative to any user home.
var guardSecretAbsolutePaths = []struct {
	path   string
	reason string
}{
	{"/etc/shadow", "the shadow password database"},
	{"/etc/gshadow", "the shadow group database"},
	// Per-user runtime state holds agent sockets and keyrings.
	// guardDangerousRWRoots already refused these for WRITE as "socket path";
	// the read side did not.
	//
	// This is defense in depth, NOT a solution to the SSH-agent problem, and
	// the distinction matters because the stronger claim is tempting and
	// false. Reaching an agent socket would be full use of every loaded key
	// with no key file ever read -- but a path grant does not currently confer
	// that: Landlock's RWDirs does not permit connect(2) on a pathname Unix
	// socket without WithResolveUnix, and the sandbox adapter uses plain
	// RWDirs (internal/sandbox/landlock_linux.go). A static path list also
	// cannot enumerate agent sockets in general, since SSH_AUTH_SOCK is
	// arbitrary. The real control is a runtime one -- refuse to grant a path
	// whose object is a socket unless it is an explicit, typed capability --
	// and it belongs with the evaluator, not here.
	{"/run/user", "per-user runtime state, which holds agent sockets and keyrings"},
	// Container secret mounts.
	{"/run/secrets", "the container secret mount point"},
}

// guardHomeRootOf returns the user home directory that contains resolved, or
// "" when the path is not under a recognizable home.
//
// POSIX-only, matching guardIsHomeRoot: the function hardcodes "/" as the
// separator and knows the /home, /var/home, /Users, /root, and /app layouts. Windows path
// handling is an open product decision tracked in ops (AF-264).
// Home-root DETECTION is case-insensitive for the same reason the shape
// comparison is: on a case-insensitive volume /users/operator reaches the very
// same directory as /Users/operator. Detection has to fold too, not just the
// comparison downstream of it, because an unrecognized root returns "" and
// silently switches off every home-relative rule rather than loosening one.
// The ORIGINAL spelling is returned so the caller composes secret paths from
// the path as written and the reported reason quotes what the operator typed.
func guardHomeRootOf(resolved string) string {
	lower := strings.ToLower(resolved)
	for _, root := range guardFixedHomeRoots {
		if lower == root || strings.HasPrefix(lower, root+"/") {
			return resolved[:len(root)]
		}
	}
	for _, root := range []string{"/home", "/var/home", "/Users"} {
		prefix := strings.ToLower(root) + "/"
		if !strings.HasPrefix(lower, prefix) {
			continue
		}
		user, _, _ := strings.Cut(resolved[len(prefix):], "/")
		if user == "" {
			continue
		}
		return resolved[:len(prefix)+len(user)]
	}
	return ""
}

// guardFixedHomeRoots are home layouts that are not a child directory of a
// multi-user home root. /app is common in minimal container images that set
// HOME=/app for a non-root workload.
var guardFixedHomeRoots = []string{"/root", "/app"}

// guardMultiHomeRoots are directories that sit ABOVE every user home, so a
// grant on one reads through to every operator's credentials at once.
var guardMultiHomeRoots = []string{"/", "/home", "/var/home", "/Users"}

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
	lowerResolved := strings.ToLower(resolved)
	for _, root := range guardMultiHomeRoots {
		if lowerResolved == strings.ToLower(root) {
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
	// Compare case-folded. A case-insensitive volume reaches the same file
	// under a different spelling, so a case-exact comparison is bypassable by
	// writing .AWS instead of .aws. macOS is case-insensitive by default and
	// Linux can mount case-insensitive filesystems; since the manifest is a
	// lexical declaration that never stats the target, there is no reliable
	// way to know which semantics apply. Folding both sides at the COMPARISON
	// keeps home-root detection case-exact, which matters because lowering the
	// whole path first stops /Users from being recognized as a home at all and
	// silently disables every rule below it. Worst case this refuses a path a
	// case-sensitive volume would treat as unrelated, which fails closed.
	resolved, secret = strings.ToLower(resolved), strings.ToLower(secret)
	switch {
	case resolved == secret:
		return "it is " + reason
	case strings.HasPrefix(resolved, secret+"/"):
		return "it is inside " + reason
	case strings.HasPrefix(secret, resolved+"/"):
		// Strict ancestor: granting this directory grants everything under it,
		// including the secret.
		return "it contains " + reason + " (" + secret + "), and a directory grant reaches everything beneath it"
	case guardIsSecretVariantName(resolved, secret):
		return "it is a renamed copy of " + reason
	}
	return ""
}

// guardVariantSeparators are the characters a backup or variant filename uses
// to extend the original name.
var guardVariantSeparators = []string{".", "-", "_", "~"}

// guardIsSecretVariantName reports whether resolved is a renamed copy of a
// known credential file, such as config.bak beside config.
//
// Credential files are routinely duplicated rather than moved: an installer
// writes config.pre-upgrade-<timestamp>, an operator keeps .npmrc.old, a
// migration leaves config.orig. Each copy carries the full credential while
// having a filename no static list can predict, so matching only the exact
// name protects the original and nothing else. This was not hypothetical --
// it was found as a real kubeconfig backup holding client-certificate-data and
// client-key-data, sitting beside a config the floor already refused.
//
// The extension must begin with a separator so that an unrelated file whose
// name merely starts with the same letters is not caught.
func guardIsSecretVariantName(resolved, secret string) bool {
	if filepath.Dir(resolved) != filepath.Dir(secret) {
		return false
	}
	base, secretBase := filepath.Base(resolved), filepath.Base(secret)
	if !strings.HasPrefix(base, secretBase) || base == secretBase {
		return false
	}
	rest := strings.TrimPrefix(base, secretBase)
	for _, sep := range guardVariantSeparators {
		if strings.HasPrefix(rest, sep) {
			return true
		}
	}
	return false
}

// guardForbiddenComponents are directory names that must never appear anywhere
// in a read-write grant, whichever user owns them.
// Matched case-insensitively, and independently of any home root, because an
// enumerated list of home layouts cannot be complete: HOME is arbitrary, and a
// container that sets it to /workspace or /srv/agent would otherwise leave the
// entire credential floor inert for that deployment. These directory names are
// credential stores by convention wherever they appear, so a component match is
// both sound and the idiom this file already used for .ssh.
//
// Only whole DIRECTORIES that are credential state through and through belong
// here. Credential FILE names stay home-relative on purpose: a project-local
// .npmrc is ordinary build configuration, and refusing every one of them would
// break real workloads with no way to narrow the grant.
var guardForbiddenComponents = map[string]string{
	".ssh":    "an SSH key directory",
	".gnupg":  "a GnuPG secret keyring directory",
	".gpg":    "a GPG secret keyring directory",
	".aws":    "an AWS credential directory, including SSO and CLI session caches",
	".azure":  "an Azure credential directory",
	".kube":   "a kubeconfig directory, whose files embed client certificates and tokens",
	".docker": "a docker credential directory",
}

// guardForbiddenComponent reports the first trust-bearing path component in the
// resolved path, or "" when none is present.
//
// Matching on components rather than on a prefix derived from this process's
// home directory is deliberate. Pipelock commonly runs as a system service, so
// os.UserHomeDir() returns /root; a home-derived list would protect /root/.ssh
// while leaving every real operator's ~/.ssh unguarded.
func guardForbiddenComponent(resolved string) (component, reason string) {
	for _, part := range strings.Split(resolved, string(filepath.Separator)) {
		if r, bad := guardForbiddenComponents[strings.ToLower(part)]; bad {
			return part, r
		}
	}
	return "", ""
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
// POSIX-only: the function hardcodes "/" as the separator and delegates home
// layouts to guardHomeRootOf. On Windows, resolved paths use "\" and neither
// root applies, so the check silently passes. Windows path handling is an
// open product decision tracked in ops (AF-264).
func guardIsHomeRoot(resolved string) bool {
	return resolved == "/" || guardHomeRootOf(resolved) == resolved
}
