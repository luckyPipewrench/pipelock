// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"path/filepath"
	"strings"
)

// GuardAccess identifies the filesystem operation evaluated against the
// compiled guard floor.
type GuardAccess string

const (
	GuardAccessRead  GuardAccess = "read"
	GuardAccessWrite GuardAccess = "write"
)

// GuardFloorDecision explains whether the compiled guard floor refuses one
// path. It is exported so read-only operator surfaces can report the exact same
// decision as config validation instead of maintaining a second matcher.
type GuardFloorDecision struct {
	Access       GuardAccess
	Path         string
	ResolvedPath string
	Refused      bool
	Rule         string
	Matched      string
	Reason       string
}

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
	decision, err := ExplainGuardPathFloor(rawPath, GuardAccessRead)
	if err != nil {
		return fmt.Errorf("%s: %w", field, err)
	}
	if decision.Refused {
		return fmt.Errorf("%s: %s", field, decision.Reason)
	}
	return nil
}

// ExplainGuardPathFloor evaluates one absolute path using the same compiled
// floor consumed by guard config validation. Operator-declared grants are not
// considered here because they can be narrowed while this floor cannot.
func ExplainGuardPathFloor(rawPath string, access GuardAccess) (GuardFloorDecision, error) {
	decision := GuardFloorDecision{Access: access, Path: rawPath}
	if !filepath.IsAbs(rawPath) {
		return decision, fmt.Errorf("path must be absolute (got %q)", rawPath)
	}
	if access != GuardAccessRead && access != GuardAccessWrite {
		return decision, fmt.Errorf("unsupported guard access %q", access)
	}

	resolved := resolveGuardPath(rawPath)
	decision.ResolvedPath = resolved
	// The component check runs against the DECLARED spelling as well as the
	// resolved target, matching what the credential-shape check already does.
	// Resolving first and checking only the result is a fail-open: a path
	// declared as a key directory that symlinks somewhere innocuous resolves to
	// a name with no forbidden component, so the floor saw nothing and allowed
	// it, for read and for write alike. Naming a key directory in a manifest is
	// the thing being refused; where the link happens to point today does not
	// make that declaration safe, and the link can be repointed afterwards.
	if comp, reason := guardForbiddenComponentIn(rawPath, resolved); comp != "" {
		decision.Refused = true
		decision.Rule = "forbidden_component"
		decision.Matched = comp
		if access == GuardAccessRead {
			decision.Reason = fmt.Sprintf("read access to secret-bearing path %q is not allowed (contains %q, which is %s); reading credential material is exfiltration, not merely inspection", rawPath, comp, reason)
		} else {
			decision.Reason = fmt.Sprintf("read-write on trust-bearing path %q is not allowed (contains %q, which is %s)", rawPath, comp, reason)
		}
		return decision, nil
	}

	if access == GuardAccessRead {
		if guardIsHomeRoot(resolved) {
			decision.Refused = true
			decision.Rule = "whole_home"
			decision.Matched = resolved
			decision.Reason = fmt.Sprintf("read access to the entire home directory %q is not allowed; it reads through to every credential beneath it", rawPath)
			return decision, nil
		}
		if match := guardDeclaredPathSecretMaterialMatch(rawPath, resolved); match.reason != "" {
			decision.Refused = true
			decision.Rule = "credential_path"
			decision.Matched = match.matched
			decision.Reason = fmt.Sprintf("read access to %q is not allowed (%s); reading a credential is exfiltration, not merely inspection", rawPath, match.reason)
			return decision, nil
		}
		if suffix, reason, secretBearing := guardForbiddenSuffix(resolved); suffix != "" && secretBearing {
			decision.Refused = true
			decision.Rule = "forbidden_path_shape"
			decision.Matched = suffix
			decision.Reason = fmt.Sprintf("read access to %s %q is not allowed; it may contain credential material", reason, rawPath)
			return decision, nil
		}
		return decision, nil
	}

	if suffix, reason, _ := guardForbiddenSuffix(resolved); suffix != "" {
		decision.Refused = true
		decision.Rule = "forbidden_path_shape"
		decision.Matched = suffix
		decision.Reason = fmt.Sprintf("read-write on %s %q is not allowed", reason, rawPath)
		return decision, nil
	}
	if guardIsHomeRoot(resolved) {
		decision.Refused = true
		decision.Rule = "whole_home"
		decision.Matched = resolved
		decision.Reason = "read-write on the entire home directory is not allowed"
		return decision, nil
	}
	for _, root := range guardDangerousRWRoots {
		clean := filepath.Clean(root.prefix)
		if resolved == clean || strings.HasPrefix(resolved, clean+string(filepath.Separator)) {
			decision.Refused = true
			decision.Rule = "dangerous_write_root"
			decision.Matched = clean
			decision.Reason = fmt.Sprintf("read-write on %s %q is not allowed", root.reason, rawPath)
			return decision, nil
		}
	}
	if match := guardDeclaredPathSecretMaterialMatch(rawPath, resolved); match.reason != "" {
		decision.Refused = true
		decision.Rule = "credential_path"
		decision.Matched = match.matched
		decision.Reason = fmt.Sprintf("read-write on %q is not allowed (%s); writing a credential file redirects the workload's identity", rawPath, match.reason)
		return decision, nil
	}
	return decision, nil
}

// guardDeclaredPathSecretMaterialReason evaluates both the declared spelling
// and its current symlink-resolved target. The declared spelling is itself a
// security boundary: a ~/.aws symlink may resolve outside a recognized home,
// but granting it still grants the credential location the manifest named.
// Conversely, checking the resolved path preserves the existing protection
// against an innocuous-looking alias that points into credential material.
func guardDeclaredPathSecretMaterialReason(rawPath, resolved string) string {
	return guardDeclaredPathSecretMaterialMatch(rawPath, resolved).reason
}

type guardSecretMatch struct {
	matched string
	reason  string
}

func guardDeclaredPathSecretMaterialMatch(rawPath, resolved string) guardSecretMatch {
	for _, candidate := range []string{filepath.Clean(rawPath), resolved} {
		if match := guardSecretMaterialMatch(candidate); match.reason != "" {
			return match
		}
	}
	return guardSecretMatch{}
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
	// This is defense in depth, NOT a solution to the SSH-agent problem.
	// Reaching an agent socket would be full use of every loaded key with no
	// key file ever read.
	//
	// An earlier version of this comment argued the risk was already bounded,
	// on the grounds that "Landlock's RWDirs does not permit connect(2) on a
	// pathname Unix socket without WithResolveUnix." That is true only from
	// ABI 9, and it was measured false for the code as it actually shipped.
	// Reproduced on Linux 7.1.5 against a V5 ruleset (which is what
	// internal/sandbox/landlock_linux.go builds): connect(2) to a socket in a
	// directory that was never granted SUCCEEDED, while a read of a file in
	// that same directory was correctly denied. Below ABI 9 a filesystem
	// ruleset does not mediate pathname-socket connections at all, so a path
	// grant neither permits nor denies them -- they are simply outside the
	// model, granted or not.
	//
	// The lesson generalizes past this entry: a guard whose justification
	// depends on a kernel feature must name the ABI that provides it, because
	// the version actually requested is where the claim lives or dies.
	//
	// A static path list also cannot enumerate agent sockets in general, since
	// SSH_AUTH_SOCK is arbitrary. The real controls are runtime ones and belong
	// with the evaluator, not here: internal/guard handles the resolve-unix
	// right without granting it to any path from ABI 9 onward, reports partial
	// mediation below that ABI, and refuses to grant a path whose pinned object
	// is a socket.
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

// guardSecretMaterialMatch reports which credential shape a path exposes and
// why. A path is refused when it is the shape, is beneath it, or is a strict
// ancestor whose directory grant would reach it.
func guardSecretMaterialMatch(resolved string) guardSecretMatch {
	lowerResolved := strings.ToLower(resolved)
	for _, root := range guardMultiHomeRoots {
		if lowerResolved == strings.ToLower(root) {
			return guardSecretMatch{matched: root, reason: "it sits above every user home and reads through to every credential beneath it"}
		}
	}
	for _, entry := range guardSecretAbsolutePaths {
		if r := guardSecretRelation(resolved, entry.path, entry.reason); r != "" {
			return guardSecretMatch{matched: entry.path, reason: r}
		}
	}
	home := guardHomeRootOf(resolved)
	if home == "" {
		return guardSecretMatch{}
	}
	for _, entry := range guardSecretShapes {
		secret := home + "/" + entry.shape
		if r := guardSecretRelation(resolved, secret, entry.reason); r != "" {
			return guardSecretMatch{matched: entry.shape, reason: r}
		}
	}
	return guardSecretMatch{}
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
// guardForbiddenComponentIn reports the first forbidden component in either the
// declared spelling or the resolved target, checking the declared form first so
// the refusal names what the operator actually wrote.
func guardForbiddenComponentIn(rawPath, resolved string) (component, reason string) {
	if comp, r := guardForbiddenComponent(filepath.Clean(rawPath)); comp != "" {
		return comp, r
	}
	return guardForbiddenComponent(resolved)
}

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
	// secretBearing marks a suffix that may hold credential material, so READ
	// is refused as well as write. Autostart locations are execution
	// persistence only: writing one is refused, reading one is not.
	//
	// This is a table field rather than a test on the reason text. The read
	// side previously decided by matching the word "pipelock" inside the
	// operator-facing prose, which fails in the OPEN direction: adding a
	// secret-bearing suffix whose wording happened not to contain that word
	// would have silently allowed read access, with no code change and no test
	// failing to say so.
	secretBearing bool
}{
	{filepath.Join(".local", "share", "pipelock"), "pipelock state directory", true},
	{filepath.Join(".config", "pipelock"), "pipelock config directory", true},
	{".pipelock", "pipelock directory", true},
	{filepath.Join(".config", "autostart"), "autostart directory", false},
	{filepath.Join("Library", "LaunchAgents"), "autostart directory", false},
	{filepath.Join("Library", "LaunchDaemons"), "autostart directory", false},
	{filepath.Join("etc", "pipelock"), "pipelock config directory", true},
}

// guardForbiddenSuffix reports why the resolved path is write-sensitive, or ""
// when it is not. A match is the directory itself or anything beneath it.
func guardForbiddenSuffix(resolved string) (suffix, reason string, secretBearing bool) {
	for _, entry := range guardForbiddenSuffixes {
		marker := string(filepath.Separator) + entry.suffix
		if strings.HasSuffix(resolved, marker) || strings.Contains(resolved, marker+string(filepath.Separator)) {
			return entry.suffix, entry.reason, entry.secretBearing
		}
	}
	return "", "", false
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
