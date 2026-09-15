// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	"github.com/luckyPipewrench/pipelock/internal/config"
)

var nftHandlePattern = regexp.MustCompile(`\s+# handle ([1-9][0-9]*)\s*$`)

// nftReloadEnv isolates the boot-time reconciler from the installer so tests
// can exercise its emitted nft transaction without changing a host ruleset.
type nftReloadEnv struct {
	nftPath    string
	rulesPath  string
	configPath string
	table      string
	chain      string
	runCmd     runCommand
	readFile   func(string) ([]byte, error)
	writeFile  func(string, []byte, os.FileMode) error
	removeFile func(string) error
	now        func() time.Time
	// warn reports a non-fatal reconciliation problem (a dropped declared
	// loopback service) to the operator. Every boot/manual reload runs
	// unattended via systemd, so this writes to stderr -- captured by the
	// journal -- rather than returning an error that would abort the reload
	// and leave the agent's egress boundary un-reconciled at all.
	warn func(string)
}

var (
	newNFTReloadEnv           = defaultNFTReloadEnv
	requireNFTReloadPrivilege = requireContainPrivilege
)

func defaultNFTReloadEnv() *nftReloadEnv {
	platform := detectContainPlatform(os.ReadFile, os.Stat, exec.LookPath)
	return &nftReloadEnv{
		nftPath:    platform.nftPath,
		rulesPath:  defaultNFTRulesPath,
		configPath: filepath.Join(defaultConfigDir, "pipelock.yaml"),
		table:      defaultNFTTable,
		chain:      defaultNFTChain,
		runCmd:     realRunCommand,
		readFile:   os.ReadFile,
		writeFile:  os.WriteFile,
		removeFile: os.Remove,
		now:        time.Now,
		warn: func(msg string) {
			_, _ = fmt.Fprintln(os.Stderr, "WARNING: "+msg)
		},
	}
}

func reloadNFTRulesCmd() *cobra.Command {
	return &cobra.Command{
		Use:           "reload-nft-rules",
		Short:         "Reload managed nft containment rules without duplicating them",
		Hidden:        true,
		SilenceUsage:  true,
		SilenceErrors: true,
		Args:          cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := requireNFTReloadPrivilege("reload-nft-rules"); err != nil {
				return cliutil.ExitCodeError(cliutil.ExitConfig, err)
			}
			if err := reloadNFTRules(cmd.Context(), newNFTReloadEnv()); err != nil {
				return cliutil.ExitCodeError(cliutil.ExitGeneral, err)
			}
			return nil
		},
	}
}

func reloadNFTRules(ctx context.Context, env *nftReloadEnv) error {
	persisted, err := env.readFile(env.rulesPath)
	if err != nil {
		return fmt.Errorf("read nft rules %s: %w", env.rulesPath, err)
	}
	header, ok, err := parseNFTRulesHeaderUIDs(persisted)
	if err != nil {
		return fmt.Errorf("parse nft rules header %s: %w", env.rulesPath, err)
	}
	if !ok {
		return fmt.Errorf("nft rules %s is missing the managed uid header", env.rulesPath)
	}

	// The persisted rules file is NOT the source of truth for declared
	// loopback services: an operator can add, remove, or let an entry expire
	// in the managed config without ever re-running `contain install`, and
	// the persisted file would otherwise still carry a now-removed or
	// now-expired accept forever. Every reload -- boot-time or the operator
	// re-running `pipelock contain reload-nft-rules` by hand -- re-derives
	// the managed block from the CURRENT managed config, the same reader
	// `contain install` uses, so removed and expired entries are dropped
	// here even if nobody re-runs install.
	loopbackServices := reconcileDeclaredContainmentLoopbackServicesForReload(env, header.proxyPort)
	rules := []byte(renderNFTRulesWithServices(nftRuleOptions{
		OperatorUID:      header.operatorUID,
		ProxyUID:         header.proxyUID,
		AgentUID:         header.agentUID,
		ProxyPort:        header.proxyPort,
		Table:            env.table,
		Chain:            env.chain,
		LoopbackServices: loopbackServices,
	}))

	out, code, err := env.runCmd(ctx, env.nftPath, "-n", "-a", "list", "chain", "inet", env.table, env.chain)
	if err != nil {
		return fmt.Errorf("list nft managed chain: %w", err)
	}
	if code != 0 && strings.Contains(out, "No such file or directory") {
		// A missing chain is the normal first-boot state. Loading the canonical
		// file is sufficient and preserves nft's own error handling for any
		// other missing-table situation.
		out = ""
	} else if code != 0 {
		return fmt.Errorf("list nft managed chain exit=%d: %s", code, oneLine(out))
	}
	script := renderNFTManagedChainReloadScript(out, string(rules), env.table, env.chain, header.operatorUID, header.proxyUID, header.agentUID)
	path := env.rulesPath + ".reload"
	if err := env.writeFile(path, []byte(script), modeConfigSecret); err != nil {
		return fmt.Errorf("write nft managed chain reload file %s: %w", path, err)
	}
	defer func() { _ = env.removeFile(path) }()
	if _, code, err := env.runCmd(ctx, env.nftPath, "-c", "-f", path); err != nil || code != 0 {
		if err != nil {
			return fmt.Errorf("validate nft managed chain reload: %w", err)
		}
		return fmt.Errorf("validate nft managed chain reload exit=%d", code)
	}
	if _, code, err := env.runCmd(ctx, env.nftPath, "-f", path); err != nil || code != 0 {
		if err != nil {
			return fmt.Errorf("reload nft managed chain: %w", err)
		}
		return fmt.Errorf("reload nft managed chain exit=%d", code)
	}
	// The kernel state and the persisted rules file must agree, or the NEXT
	// reload (or a reboot that skips this reconciler and loads the file
	// directly) would reintroduce whatever this reload just dropped. Persist
	// only after the live reload succeeds, so a failed reload never
	// overwrites a known-good persisted file with an unapplied change.
	if !bytesEqual(persisted, rules) {
		if err := env.writeFile(env.rulesPath, rules, modeConfigSecret); err != nil {
			return fmt.Errorf("persist reconciled nft rules %s: %w", env.rulesPath, err)
		}
	}
	return nil
}

// reconcileDeclaredContainmentLoopbackServicesForReload resolves the
// declared loopback services this reload should render, from the managed
// config rather than the stale persisted rules file. On any failure to
// read, parse, or validate the declaration -- unreadable managed config,
// malformed YAML, or an expired/malformed entry -- it fails closed by
// returning zero declared services (the agent stays contained and only
// loses the extra declared service) and reports exactly which entry was
// dropped and why via env.warn, rather than silently keeping whatever was
// last rendered.
func reconcileDeclaredContainmentLoopbackServicesForReload(env *nftReloadEnv, proxyPort int) []config.ContainmentLoopbackService {
	now := time.Now
	if env.now != nil {
		now = env.now
	}
	data, err := env.readFile(env.configPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		if env.warn != nil {
			env.warn(fmt.Sprintf("containment: managed config %s is unreadable (%v); reloading without any declared loopback services until it is readable again — run `pipelock contain reload-nft-rules` after fixing it", env.configPath, err))
		}
		return nil
	}
	declared, err := parseContainmentLoopbackServicesFromConfigBytes(data, proxyPort, now())
	if err != nil {
		if env.warn != nil {
			env.warn(fmt.Sprintf("containment: managed config %s declares containment.loopback_services that Pipelock cannot honor (%v); reloading without any declared loopback services until it is fixed — remove or re-approve the offending entry, then run `pipelock contain reload-nft-rules`", env.configPath, err))
		}
		return nil
	}
	return declared
}

// renderNFTManagedChainReloadScript removes complete, unlabelled legacy
// Pipelock rule blocks by handle before loading one canonical block. Legacy
// rules predate per-rule comments, so deleting an individual lookalike would
// risk deleting an operator rule. Requiring the complete ordered six-rule
// block preserves interleaved and standalone foreign rules, including narrow
// established-reply allows.
func renderNFTManagedChainReloadScript(live, rulesBody, table, chain string, operatorUID, proxyUID, agentUID int) string {
	handles := legacyManagedNFTRuleBlockHandles(live, operatorUID, proxyUID, agentUID)
	var script strings.Builder
	for _, handle := range handles {
		_, _ = fmt.Fprintf(&script, "delete rule inet %s %s handle %d\n", table, chain, handle)
	}
	script.WriteString(rulesBody)
	return script.String()
}

type nftRuleWithHandle struct {
	line   string
	handle int
}

func legacyManagedNFTRuleBlockHandles(live string, operatorUID, proxyUID, agentUID int) []int {
	rules := nftRulesWithHandles(live)
	var handles []int
	for i := 0; i < len(rules); {
		blockLen := managedNFTBlockLength(rules, i, operatorUID, proxyUID, agentUID)
		if blockLen == 0 {
			i++
			continue
		}
		for _, rule := range rules[i : i+blockLen] {
			handles = append(handles, rule.handle)
		}
		i += blockLen
	}
	return handles
}

// managedNFTBlockLength returns the length of the managed rule block starting
// at rules[i], or 0 if no managed block starts there. The block is:
// operator accept, proxy accept, one-or-more agent loopback allows (the
// implicit proxy-port allow plus any declared containment.loopback_services
// exceptions, in any number), DNS udp/53 drop, DNS tcp/53 drop, catch-all
// drop. Recognizing a variable number of loopback allows (rather than the
// fixed six-rule legacy shape) is what lets reload replace a block that
// carries declared loopback services instead of leaving them untouched as an
// unrecognized carve-out and appending a second managed block behind the old
// catch-all drop.
func managedNFTBlockLength(rules []nftRuleWithHandle, i, operatorUID, proxyUID, agentUID int) int {
	if i+2 >= len(rules) {
		return 0
	}
	if !lineHasTerminalSkuidVerdict(rules[i].line, operatorUID, "accept") ||
		!lineHasTerminalSkuidVerdict(rules[i+1].line, proxyUID, "accept") {
		return 0
	}
	loopbackCount := 0
	for j := i + 2; j < len(rules) && lineHasAgentLoopbackAllowAnyPortAnyHost(rules[j].line, agentUID); j++ {
		loopbackCount++
	}
	if loopbackCount == 0 {
		return 0
	}
	tailStart := i + 2 + loopbackCount
	if tailStart+2 >= len(rules) {
		return 0
	}
	if !lineHasManagedDNSDrop(rules[tailStart].line, agentUID, "udp") ||
		!lineHasManagedDNSDrop(rules[tailStart+1].line, agentUID, "tcp") ||
		!lineHasManagedCatchAllDrop(rules[tailStart+2].line, agentUID) {
		return 0
	}
	return 2 + loopbackCount + 3
}

func nftRulesWithHandles(live string) []nftRuleWithHandle {
	rules := make([]nftRuleWithHandle, 0)
	for _, raw := range strings.Split(live, "\n") {
		match := nftHandlePattern.FindStringSubmatch(raw)
		if len(match) != 2 {
			continue
		}
		handle, err := strconv.Atoi(match[1])
		if err != nil {
			continue
		}
		line := strings.TrimSpace(strings.TrimSuffix(raw, match[0]))
		if line != "" {
			rules = append(rules, nftRuleWithHandle{line: line, handle: handle})
		}
	}
	return rules
}

func lineHasManagedDNSDrop(line string, agentUID int, protocol string) bool {
	fields := nftLineFields(line)
	prefix := []string{"meta", "skuid", strconv.Itoa(agentUID), protocol, "dport", "53"}
	if len(fields) < len(prefix)+4 {
		return false
	}
	for i, want := range prefix {
		if fields[i] != want {
			return false
		}
	}
	return fieldsHaveNFTCounterLogDrop(fields[len(prefix):], nftLogPrefix(EgressClassDirectDNS)+" ")
}

func lineHasManagedCatchAllDrop(line string, agentUID int) bool {
	fields := nftLineFields(line)
	prefix := []string{"meta", "skuid", strconv.Itoa(agentUID)}
	if len(fields) < len(prefix)+4 {
		return false
	}
	for i, want := range prefix {
		if fields[i] != want {
			return false
		}
	}
	return fieldsHaveNFTCounterLogDrop(fields[len(prefix):], nftLogPrefix(EgressClassNotRoutingThroughPipelock)+" ")
}

func fieldsHaveNFTCounterLogDrop(fields []string, prefix string) bool {
	if len(fields) < 5 || fields[0] != "counter" {
		return false
	}
	i := 1
	if i+3 < len(fields) && fields[i] == "packets" && isNonNegativeInteger(fields[i+1]) && fields[i+2] == "bytes" && isNonNegativeInteger(fields[i+3]) {
		i += 4
	}
	if i+3 >= len(fields) || fields[i] != "log" || fields[i+1] != "prefix" || fields[i+2] != strconv.Quote(prefix) || fields[i+3] != "drop" {
		return false
	}
	return nftRuleTailIsCommentOnly(fields[i+4:])
}

func isNonNegativeInteger(value string) bool {
	_, err := strconv.ParseUint(value, 10, 64)
	return err == nil
}
