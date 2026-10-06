// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/posturebinding"
)

// filesystemProfile is the systemd property set shared by contain run and the
// installed launch wrapper. Mode off carries no filesystem properties; the
// caller keeps the existing PrivateTmp and display-socket behavior.
type filesystemProfile struct {
	Mode              string
	Properties        []string
	BindPaths         []string
	BindReadOnlyPaths []string
}

// filesystemProfileInput is the pure input to the profile builder. Eval and
// Exists are injectable so the path policy can be tested without a Linux
// filesystem. Nil uses filepath.EvalSymlinks and os.Stat.
type filesystemProfileInput struct {
	Mode                string
	AgentUser           string
	AgentHome           string
	OperatorHome        string
	DisplaySocket       string
	Grants              []workspaceGrant
	Now                 time.Time
	PostureProofPath    string
	ConfigDir           string
	DataDir             string
	RequiredSecretPaths []string
	// OptionalSecretPaths are configured secret locations. A missing path is
	// skipped. A path that is or contains something the agent must read is
	// refused, because InaccessiblePaths on a parent cannot be punched through.
	OptionalSecretPaths []string
	// ReadablePaths are files the agent must still be able to read. A secret
	// path that is equal to or a parent of one of these cannot be hidden.
	ReadablePaths []string
	Exists        func(string) (bool, error)
	Eval          func(string) (resolved string, isDir bool, err error)
}

// filesystemProfileProperties returns the enforce-mode property list, or an
// empty list when mode is off. Unknown modes and unsafe bind paths fail closed.
func filesystemProfileProperties(in filesystemProfileInput) (filesystemProfile, error) {
	switch strings.TrimSpace(in.Mode) {
	case "", config.ContainmentFilesystemModeOff:
		return filesystemProfile{Mode: config.ContainmentFilesystemModeOff}, nil
	case config.ContainmentFilesystemModeEnforce:
	default:
		return filesystemProfile{}, fmt.Errorf("containment.filesystem.mode %q must be off or enforce", in.Mode)
	}
	if strings.TrimSpace(in.OperatorHome) == "" {
		return filesystemProfile{}, errors.New(operatorHomeRequired)
	}
	operatorHome, err := cleanLinuxPath(in.OperatorHome)
	if err != nil {
		return filesystemProfile{}, fmt.Errorf("operator home: %w", err)
	}
	if err := refuseUnsupportedOperatorHome(operatorHome); err != nil {
		return filesystemProfile{}, err
	}
	in.OperatorHome = operatorHome
	if strings.TrimSpace(in.AgentHome) == "" {
		return filesystemProfile{}, errors.New("agent home is required to build the filesystem profile")
	}
	agentHome, err := in.resolveBindDir("agent home", in.AgentHome)
	if err != nil {
		return filesystemProfile{}, err
	}
	now := in.Now
	if now.IsZero() {
		now = time.Now()
	}
	properties := []string{
		"ProtectSystem=strict",
		"ProtectHome=tmpfs",
		bindTriple("BindPaths", agentHome, "norbind"),
	}
	bindPaths := []string{canonicalBind(agentHome, agentHome, "norbind")}
	var bindReadOnly []string
	seen := map[string]string{agentHome: workspaceModeReadWrite}
	for _, grant := range grantsForAgent(in.Grants, in.AgentUser) {
		expired, expErr := grant.expired(now)
		if expErr != nil {
			return filesystemProfile{}, expErr
		}
		if expired {
			continue
		}
		mode := strings.TrimSpace(grant.Mode)
		switch mode {
		case workspaceModeReadWrite, workspaceModeReadOnly:
		default:
			return filesystemProfile{}, fmt.Errorf("workspace grant %q: mode %q must be read-only or read-write", grant.Path, grant.Mode)
		}
		resolved, resolveErr := in.resolveBindDir("workspace grant", grant.Path)
		if resolveErr != nil {
			return filesystemProfile{}, resolveErr
		}
		if previous, ok := seen[resolved]; ok {
			if previous != mode {
				return filesystemProfile{}, fmt.Errorf("workspace grant %q: %s is already bound %s", grant.Path, resolved, previous)
			}
			continue
		}
		seen[resolved] = mode
		opt := "norbind"
		if mode == workspaceModeReadWrite {
			properties = append(properties, bindTriple("BindPaths", resolved, opt))
			bindPaths = append(bindPaths, canonicalBind(resolved, resolved, opt))
			continue
		}
		properties = append(properties, bindTriple("BindReadOnlyPaths", resolved, opt))
		bindReadOnly = append(bindReadOnly, canonicalBind(resolved, resolved, opt))
	}
	if socket := strings.TrimSpace(in.DisplaySocket); socket != "" {
		if strings.ContainsAny(socket, "\x00\r\n:") {
			return filesystemProfile{}, fmt.Errorf("display socket %q cannot be represented safely in a systemd bind path", socket)
		}
		properties = append(properties, "BindReadOnlyPaths="+socket)
		bindReadOnly = append(bindReadOnly, canonicalBind(socket, socket, "rbind"))
	}
	properties = append(properties, "NoNewPrivileges=true")
	in.ReadablePaths = append(append([]string{}, in.ReadablePaths...), agentHome)
	for resolved := range seen {
		in.ReadablePaths = append(in.ReadablePaths, resolved)
	}
	hidden, err := in.inaccessiblePaths()
	if err != nil {
		return filesystemProfile{}, err
	}
	for _, hiddenPath := range hidden {
		properties = append(properties, "InaccessiblePaths="+systemdPathToken(hiddenPath))
	}
	properties = append(properties,
		"TemporaryFileSystem=/dev/shm",
		"ProtectKernelTunables=true",
		"ProtectKernelModules=true",
		"ProtectControlGroups=true",
	)
	sort.Strings(bindPaths)
	sort.Strings(bindReadOnly)
	return filesystemProfile{
		Mode:              config.ContainmentFilesystemModeEnforce,
		Properties:        properties,
		BindPaths:         bindPaths,
		BindReadOnlyPaths: bindReadOnly,
	}, nil
}

// containLaunchPropertyLines is what the installed wrapper captures. Enforce
// mode returns the profile, which already includes the display socket. Off
// mode returns only that socket line so a reinstall does not drop it.
func containLaunchPropertyLines(in filesystemProfileInput) ([]string, error) {
	profile, err := filesystemProfileProperties(in)
	if err != nil {
		return nil, err
	}
	if profile.Mode == config.ContainmentFilesystemModeEnforce {
		return profile.Properties, nil
	}
	if socket := strings.TrimSpace(in.DisplaySocket); socket != "" {
		if strings.ContainsAny(socket, "\x00\r\n:") {
			return nil, fmt.Errorf("display socket %q cannot be represented safely in a systemd bind path", socket)
		}
		return []string{"BindReadOnlyPaths=" + socket}, nil
	}
	return nil, nil
}

func (in filesystemProfileInput) resolveBindDir(kind, original string) (string, error) {
	cleaned, err := cleanLinuxPath(original)
	if err != nil {
		return "", fmt.Errorf("%s %q: %w", kind, original, err)
	}
	if err := refuseFilesystemBind(kind, original, cleaned, in.OperatorHome); err != nil {
		return "", err
	}
	resolved, isDir, err := in.eval(cleaned)
	if err != nil {
		return "", fmt.Errorf("%s %q: %w", kind, original, err)
	}
	if !isDir {
		return "", fmt.Errorf("%s %q is not a directory", kind, original)
	}
	resolved, err = cleanLinuxPath(resolved)
	if err != nil {
		return "", fmt.Errorf("%s %q: %w", kind, original, err)
	}
	if err := refuseFilesystemBind(kind, original, resolved, in.OperatorHome); err != nil {
		return "", err
	}
	return resolved, nil
}

func (in filesystemProfileInput) eval(p string) (string, bool, error) {
	if in.Eval != nil {
		return in.Eval(p)
	}
	resolved, err := filepath.EvalSymlinks(p)
	if err != nil {
		return "", false, err
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return "", false, err
	}
	return resolved, info.IsDir(), nil
}

func (in filesystemProfileInput) exists(p string) (bool, error) {
	if in.Exists != nil {
		return in.Exists(p)
	}
	_, err := os.Stat(p)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return false, err
}

func (in filesystemProfileInput) inaccessiblePaths() ([]string, error) {
	configDir := in.ConfigDir
	if strings.TrimSpace(configDir) == "" {
		configDir = defaultConfigDir
	}
	dataDir := in.DataDir
	if strings.TrimSpace(dataDir) == "" {
		dataDir = defaultDataDir
	}
	configDir, err := cleanLinuxPath(configDir)
	if err != nil {
		return nil, fmt.Errorf("config dir: %w", err)
	}
	dataDir, err = cleanLinuxPath(dataDir)
	if err != nil {
		return nil, fmt.Errorf("data dir: %w", err)
	}
	proof := strings.TrimSpace(in.PostureProofPath)
	if proof == "" {
		proof = posturebinding.DefaultContainRunProofPath
	}
	proof, err = cleanLinuxPath(proof)
	if err != nil {
		return nil, fmt.Errorf("posture proof path: %w", err)
	}
	candidates := []string{
		path.Join(configDir, "integrity"),
		path.Join(configDir, "tls"),
		path.Join(configDir, "keys", "flight-recorder-signing.key"),
		path.Join(configDir, "keys", "mediation-envelope-signing.key"),
		path.Join(configDir, "learn-privacy-salt"),
		path.Join(dataDir, "recorder"),
		path.Join(dataDir, "captures"),
		path.Join(dataDir, "baselines"),
		path.Join(dataDir, "contracts"),
		path.Join(dataDir, "quarantine"),
		path.Join(dataDir, "logs"),
		path.Join(dataDir, "rules"),
	}
	for _, extra := range in.OptionalSecretPaths {
		cleaned, cleanErr := cleanLinuxPath(extra)
		if cleanErr != nil {
			return nil, fmt.Errorf("secret path %q: %w", extra, cleanErr)
		}
		if !slices.Contains(candidates, cleaned) {
			candidates = append(candidates, cleaned)
		}
	}
	required := map[string]string{}
	for _, extra := range in.RequiredSecretPaths {
		cleaned, cleanErr := cleanLinuxPath(extra)
		if cleanErr != nil {
			return nil, fmt.Errorf("signing key %q: %w", extra, cleanErr)
		}
		required[cleaned] = extra
		if !slices.Contains(candidates, cleaned) {
			candidates = append(candidates, cleaned)
		}
	}
	readable := []string{
		proof,
		path.Join(configDir, "ca.pem"),
		path.Join(configDir, "combined-ca.pem"),
		path.Join(configDir, "contain", "tools.list"),
	}
	for _, extra := range in.ReadablePaths {
		cleaned, cleanErr := cleanLinuxPath(extra)
		if cleanErr != nil {
			return nil, fmt.Errorf("readable path %q: %w", extra, cleanErr)
		}
		readable = append(readable, cleaned)
	}
	out := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		if blocked, ok := filesystemPathBlocks(candidate, readable); ok {
			label := candidate
			if original, must := required[candidate]; must {
				label = original
			}
			return nil, fmt.Errorf("secret path %s cannot be hidden because it contains readable path %s", label, blocked)
		}
		ok, statErr := in.exists(candidate)
		if statErr != nil {
			return nil, fmt.Errorf("stat inaccessible path %s: %w", candidate, statErr)
		}
		if !ok {
			if original, must := required[candidate]; must {
				return nil, fmt.Errorf("signing key %s is missing", original)
			}
			continue
		}
		out = append(out, candidate)
	}
	return out, nil
}

// ProtectHome=tmpfs hides /home and /root only. An operator home anywhere
// else stays readable under ProtectSystem=strict, so enforce refuses it
// instead of launching a profile that does not hide that home.
func refuseUnsupportedOperatorHome(home string) error {
	if home == "/root" || linuxPathContains("/root", home) || linuxPathContains("/home", home) {
		return nil
	}
	return fmt.Errorf("operator home %s is not hidden by enforce; enforce supports operator homes under /home or /root", home)
}

func refuseFilesystemBind(kind, original, resolved, operatorHome string) error {
	switch resolved {
	case "/", "/home", "/root", "/run/user":
		return fmt.Errorf("%s %q resolves to %s, which cannot be bound into a contained agent", kind, original, resolved)
	}
	if resolved == operatorHome || linuxPathContains(resolved, operatorHome) {
		return fmt.Errorf("%s %q resolves to %s, which contains operator home %s", kind, original, resolved, operatorHome)
	}
	return nil
}

func cleanLinuxPath(p string) (string, error) {
	if strings.TrimSpace(p) == "" {
		return "", errors.New("path is empty")
	}
	if strings.ContainsAny(p, "\x00\r\n:") {
		return "", errors.New("cannot be represented safely in a systemd bind path")
	}
	if !strings.HasPrefix(p, "/") {
		return "", fmt.Errorf("path %q must be absolute", p)
	}
	cleaned := path.Clean(p)
	if !strings.HasPrefix(cleaned, "/") {
		return "", fmt.Errorf("path %q must be absolute", p)
	}
	if strings.ContainsAny(cleaned, "\x00\r\n:") {
		return "", errors.New("cannot be represented safely in a systemd bind path")
	}
	return cleaned, nil
}

func linuxPathContains(parent, child string) bool {
	if parent == "" || child == "" || parent == child {
		return false
	}
	return strings.HasPrefix(child, parent+"/")
}

func bindTriple(key, dir, opt string) string {
	token := systemdPathToken(dir)
	return key + "=" + token + ":" + token + ":" + opt
}

func canonicalBind(src, dest, opt string) string {
	return src + ":" + dest + ":" + opt
}

func filesystemInaccessiblePaths(properties []string) []string {
	out := make([]string, 0)
	for _, prop := range properties {
		rest, ok := strings.CutPrefix(prop, "InaccessiblePaths=")
		if !ok || rest == "" {
			continue
		}
		out = append(out, unquoteSystemdPath(rest))
	}
	return out
}

func systemdPathToken(p string) string {
	if !strings.ContainsAny(p, " \t\"'\\") {
		return p
	}
	escaped := strings.ReplaceAll(p, `\`, `\\`)
	escaped = strings.ReplaceAll(escaped, `"`, `\"`)
	return `"` + escaped + `"`
}

func filesystemPathBlocks(candidate string, readable []string) (string, bool) {
	for _, needed := range readable {
		if candidate == needed || linuxPathContains(candidate, needed) {
			return needed, true
		}
	}
	return "", false
}

// filesystemBindsDigest is the sha256 of the canonical sorted bind list.
// Read-write and read-only entries stay distinct. An off profile has no digest.
func filesystemBindsDigest(profile filesystemProfile) string {
	if profile.Mode != config.ContainmentFilesystemModeEnforce {
		return ""
	}
	lines := make([]string, 0, len(profile.BindPaths)+len(profile.BindReadOnlyPaths))
	for _, bind := range profile.BindPaths {
		lines = append(lines, "BindPaths="+bind)
	}
	for _, bind := range profile.BindReadOnlyPaths {
		lines = append(lines, "BindReadOnlyPaths="+bind)
	}
	sort.Strings(lines)
	sum := sha256.Sum256([]byte(strings.Join(lines, "\n")))
	return hex.EncodeToString(sum[:])
}

func filesystemProfileForProbe(env *probeEnv, agentHome string) (filesystemProfile, error) {
	in, err := filesystemProfileInputForProbe(env, agentHome)
	if err != nil {
		return filesystemProfile{}, err
	}
	return filesystemProfileProperties(in)
}

func filesystemProfileInputForProbe(env *probeEnv, agentHome string) (filesystemProfileInput, error) {
	if env == nil {
		return filesystemProfileInput{}, errors.New("probe environment is missing")
	}
	cfg, err := loadProbeConfig(env)
	if err != nil {
		return filesystemProfileInput{}, err
	}
	mode := ""
	var required, optional []string
	configDir := env.configDir
	if strings.TrimSpace(configDir) == "" {
		configDir = defaultConfigDir
	}
	if cfg != nil {
		mode = cfg.Containment.Filesystem.Mode
		required, optional = configuredSecretPaths(cfg)
	}
	// The same resolver contain run uses. IsEnabled(true) would require an
	// X socket on a headless host that launch correctly leaves unset.
	display := resolveLaunchDisplay(cfg, env.display, probeXvfbPresent(env))
	if env.workspaceGrants == nil && env.workspaceInvPath != "" && env.readFile != nil {
		inv, invErr := loadWorkspaceInventoryFrom(env.readFile, env.workspaceInvPath)
		if invErr != nil {
			return filesystemProfileInput{}, fmt.Errorf("read workspace inventory: %w", invErr)
		}
		env.workspaceGrants = inv.Workspaces
	}
	operatorHome, err := filesystemOperatorHome(env, mode)
	if err != nil {
		return filesystemProfileInput{}, err
	}
	socket := ""
	if resolved, ok := localDisplaySocket(display); ok {
		socket = resolved
	}
	readable := []string{}
	if env.caExportPath != "" {
		readable = append(readable, env.caExportPath)
	}
	if env.caBundlePath != "" {
		readable = append(readable, env.caBundlePath)
	}
	if env.toolsListPath != "" {
		readable = append(readable, env.toolsListPath)
	}
	if env.postureProofPath != "" {
		readable = append(readable, env.postureProofPath)
	}
	now := time.Time{}
	if env.now != nil {
		now = env.now()
	}
	return filesystemProfileInput{
		Mode:                mode,
		AgentUser:           env.agentUserName,
		AgentHome:           agentHome,
		OperatorHome:        operatorHome,
		DisplaySocket:       socket,
		Grants:              env.workspaceGrants,
		Now:                 now,
		PostureProofPath:    env.postureProofPath,
		ConfigDir:           configDir,
		DataDir:             defaultDataDir,
		RequiredSecretPaths: required,
		OptionalSecretPaths: optional,
		ReadablePaths:       readable,
	}, nil
}

// operatorHomeRequired names the control contain run, verify, doctor, and the
// plk-* wrappers actually read. Those commands have no operator flag; sudo
// sets SUDO_USER to the invoking account.
const operatorHomeRequired = "operator home is required to validate filesystem binds; run this command through sudo from the operator account"

func filesystemOperatorHome(env *probeEnv, mode string) (string, error) {
	if strings.TrimSpace(env.operatorUser) == "" || env.operatorUser == "root" {
		if mode == config.ContainmentFilesystemModeEnforce {
			return "", errors.New(operatorHomeRequired)
		}
		return "", nil
	}
	if env.lookupUser == nil {
		if mode == config.ContainmentFilesystemModeEnforce {
			return "", errors.New(operatorHomeRequired)
		}
		return "", nil
	}
	user, err := env.lookupUser(env.operatorUser)
	if err != nil {
		if mode == config.ContainmentFilesystemModeEnforce {
			return "", fmt.Errorf("lookup operator home for %s: %w", env.operatorUser, err)
		}
		return "", nil
	}
	if strings.TrimSpace(user.HomeDir) == "" && mode == config.ContainmentFilesystemModeEnforce {
		return "", fmt.Errorf("operator %s has no home directory", env.operatorUser)
	}
	return user.HomeDir, nil
}

func missingManagedConfigError(path string) error {
	return fmt.Errorf("managed config %s is missing; run `pipelock contain install` to restore the managed config", path)
}

func loadProbeConfig(env *probeEnv) (*config.Config, error) {
	path := ""
	if env != nil {
		path = env.configPath
	}
	if strings.TrimSpace(path) == "" {
		path = filepath.Join(defaultConfigDir, "pipelock.yaml")
	}
	read := os.ReadFile
	if env != nil && env.readFile != nil {
		read = env.readFile
	}
	data, err := read(path)
	if err != nil {
		// A missing or unreadable file is not mode off. Off is only a
		// successfully parsed config that says off or omits the key.
		// Empty configPath still names the default file; there is no test
		// seam that turns a missing file into off.
		if errors.Is(err, os.ErrNotExist) {
			return nil, missingManagedConfigError(path)
		}
		return nil, fmt.Errorf("read containment config %s: %w", path, err)
	}
	cfg := &config.Config{}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(cfg); err != nil {
		return nil, fmt.Errorf("parse containment config %s: %w", path, err)
	}
	if err := cfg.Containment.Filesystem.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func configuredSecretPaths(cfg *config.Config) (required, optional []string) {
	if cfg == nil {
		return nil, nil
	}
	if p := strings.TrimSpace(cfg.FlightRecorder.SigningKeyPath); p != "" {
		required = append(required, p)
	}
	if p := strings.TrimSpace(cfg.MediationEnvelope.SigningKeyPath); p != "" {
		required = append(required, p)
	}
	add := func(p string) {
		if strings.TrimSpace(p) != "" {
			optional = append(optional, strings.TrimSpace(p))
		}
	}
	add(cfg.FlightRecorder.Dir)
	add(cfg.Learn.CaptureDir)
	add(cfg.BehavioralBaseline.ProfileDir)
	add(cfg.LearnLock.StoreDir)
	add(cfg.Rules.RulesDir)
	if rest, ok := strings.CutPrefix(strings.TrimSpace(cfg.Learn.Privacy.SaltSource), "file:"); ok {
		add(rest)
	}
	if file := strings.TrimSpace(cfg.Logging.File); file != "" {
		add(path.Dir(file))
	}
	if dir := strings.TrimSpace(cfg.MCPToolPolicy.QuarantineDir); strings.HasPrefix(dir, "/") {
		add(dir)
	}
	return required, optional
}

// probeFilesystemConfinement reports the filesystem profile. Mode off is its
// own status: contain run does not refuse it, and verify does not count it as
// a pass, a skip, or a failure. Enforce runs the canary and fails closed.
func probeFilesystemConfinement(ctx context.Context, env *probeEnv) (string, string) {
	// service-posture signs an operator-written unit Pipelock does not render.
	// A canary of a separate transient unit would not be that unit's filesystem,
	// so this path reports a distinct non-pass and clears any preloaded profile
	// before a test hook or a config load can turn it into a signed claim.
	if env != nil && env.postureLauncher == servicePostureLauncher {
		env.filesystem = filesystemProfile{}
		return statusFilesystemNotApplicable, filesystemNotApplicableDetail
	}
	if env != nil && env.filesystemProbe != nil {
		return env.filesystemProbe(ctx, env)
	}
	if env == nil {
		return statusFail, "filesystem confinement probe environment is missing"
	}
	profile := env.filesystem
	if profile.Mode == "" {
		var err error
		profile, err = filesystemProfileForProbe(env, env.agentHome)
		if err != nil {
			return statusFail, err.Error()
		}
		env.filesystem = profile
	}
	if profile.Mode != config.ContainmentFilesystemModeEnforce {
		return statusFilesystemOff, "filesystem profile: off"
	}
	return probeFilesystemConfinementEnforce(ctx, env, profile)
}

// filesystemCanaryOutcome maps the canary process status. Exit 0 is the only
// pass. Each other code names the check that failed.
func filesystemCanaryOutcome(code int, output string) (string, string) {
	switch code {
	case 0:
		return statusPass, "contained service cannot read the operator home or a hidden secret, cannot write a protected filesystem path, and can use its read-write workspace"
	case 11:
		return statusFail, "operator home canary was visible inside the contained service"
	case 12:
		return statusFail, "contained service could create a file on a filesystem ProtectSystem should keep read-only"
	case 13:
		return statusFail, "read-write workspace was not visible and writable inside the contained service"
	case 14:
		return statusFail, "hidden secret was readable inside the contained service"
	default:
		if output == "" {
			return statusFail, fmt.Sprintf("filesystem confinement canary exited %d", code)
		}
		return statusFail, fmt.Sprintf("filesystem confinement canary exited %d: %s", code, oneLine(output))
	}
}
