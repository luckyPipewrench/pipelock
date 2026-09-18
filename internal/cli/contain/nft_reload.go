// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"context"
	"errors"
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
	nftPath           string
	rulesPath         string
	configPath        string
	reconcileLockPath string
	table             string
	chain             string
	runCmd            runCommand
	readFile          func(string) ([]byte, error)
	writeFile         func(string, []byte, os.FileMode) error
	removeFile        func(string) error
	now               func() time.Time
	// warn reports a non-fatal reconciliation problem (a dropped declared
	// loopback service) to the operator. Every boot/manual reload runs
	// unattended via systemd, so this writes to stderr -- captured by the
	// journal -- rather than returning an error that would abort the reload
	// and leave the agent's egress boundary un-reconciled at all.
	warn func(string)
	// report records the successful reconciliation outcome. It is deliberately
	// separate from warn: a manual reload that made no change is still useful
	// evidence, while warnings describe a safe degradation in the declared
	// loopback-service set.
	report func(string)
	// lockFn wraps the config-snapshot -> kernel-apply -> persist critical
	// section in an exclusive lock, shared with `contain install`'s own nft
	// step, so the two can never interleave on the same managed config and
	// nft state. Defaults to the real flock-based withContainmentReconcileLock;
	// tests substitute a fake to deterministically force an interleaving
	// window without depending on OS scheduling.
	lockFn func(lockPath string, fn func() error) error
	// pauseAfterSnapshot, if set, runs after the declared loopback services
	// have been read from the managed config and BEFORE the kernel
	// transaction is built -- while lockFn's critical section is still
	// held. Test-only: lets a race test deterministically widen the window
	// between snapshot and apply to prove a concurrent `contain install`
	// blocks on the shared lock instead of interleaving.
	pauseAfterSnapshot func()
}

var (
	newNFTReloadEnv           = defaultNFTReloadEnv
	requireNFTReloadPrivilege = requireContainPrivilege
)

func defaultNFTReloadEnv() *nftReloadEnv {
	platform := detectContainPlatform(os.ReadFile, os.Stat, exec.LookPath)
	return &nftReloadEnv{
		nftPath:           platform.nftPath,
		rulesPath:         defaultNFTRulesPath,
		configPath:        filepath.Join(defaultConfigDir, "pipelock.yaml"),
		reconcileLockPath: containmentReconcileLockPathFor(defaultNFTRulesPath),
		table:             defaultNFTTable,
		chain:             defaultNFTChain,
		runCmd:            realRunCommand,
		readFile:          os.ReadFile,
		// writeFileAtomic (temp file + fsync + rename + directory fsync in
		// the same directory) is the same primitive `contain install`
		// already uses for every managed file write. A crash mid-write can
		// therefore never leave the persisted rules file empty or partial:
		// either the previous content survives untouched, or the new
		// content is fully present.
		writeFile:  writeFileAtomic,
		removeFile: os.Remove,
		now:        time.Now,
		warn: func(msg string) {
			_, _ = fmt.Fprintln(os.Stderr, "WARNING: "+msg)
		},
		lockFn: withContainmentReconcileLock,
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
			env := newNFTReloadEnv()
			env.report = func(message string) {
				_, _ = fmt.Fprintln(cmd.OutOrStdout(), message)
			}
			if err := reloadNFTRules(cmd.Context(), env); err != nil {
				return cliutil.ExitCodeError(cliutil.ExitGeneral, err)
			}
			return nil
		},
	}
}

func reloadNFTRules(ctx context.Context, env *nftReloadEnv) error {
	if env.reconcileLockPath == "" {
		// A test env that never set a lock path is not exercising locking;
		// production always sets defaultContainmentReconcileLockPath.
		return reloadNFTRulesLocked(ctx, env)
	}
	lockFn := env.lockFn
	if lockFn == nil {
		lockFn = withContainmentReconcileLock
	}
	// The whole critical section -- reading the current persisted rules,
	// snapshotting the managed config's declared loopback services,
	// applying the kernel transaction, and persisting the result -- runs
	// under one exclusive lock shared with `contain install`'s own nft
	// step (see withContainmentReconcileLock). Without it, an install that
	// promotes a new managed config while a reload is mid-flight on the
	// OLD config can have the reload's later write silently restore an
	// entry the install just revoked.
	return lockFn(env.reconcileLockPath, func() error {
		return reloadNFTRulesLocked(ctx, env)
	})
}

func reloadNFTRulesLocked(ctx context.Context, env *nftReloadEnv) error {
	persisted, err := env.readFile(env.rulesPath)
	if err != nil {
		return fmt.Errorf("read nft rules %s: %w", env.rulesPath, err)
	}
	header, ok, err := parseNFTRulesHeaderUIDs(persisted)
	if err != nil {
		return fmt.Errorf("parse nft rules header %s: %w; rerun `pipelock contain install` to restore it", env.rulesPath, err)
	}
	if !ok {
		// An empty or partial persisted file (e.g. a crash mid-write before
		// this reload started writing atomically) parses no header. Fail
		// closed here rather than loading a chain built from zero UIDs: no
		// containment rule is safer to be missing loudly than to be
		// silently wrong. `contain install` is the only path that can
		// regenerate this file from scratch.
		return fmt.Errorf("nft rules %s is missing the managed uid header (empty or corrupt persisted rules file); rerun `pipelock contain install` to restore it", env.rulesPath)
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
	if env.pauseAfterSnapshot != nil {
		env.pauseAfterSnapshot()
	}
	rules := []byte(renderNFTRulesWithServices(nftRuleOptions{
		OperatorUID:      header.operatorUID,
		ProxyUID:         header.proxyUID,
		AgentUID:         header.agentUID,
		ProxyPort:        header.proxyPort,
		Table:            env.table,
		Chain:            env.chain,
		LoopbackServices: loopbackServices,
	}))

	// Persist the reconciled file FIRST, atomically, before touching the
	// kernel. writeFileAtomic's temp-file-then-rename means a crash here
	// either leaves the previous content fully intact or lands the new
	// content fully intact -- never empty or partial. If the kernel
	// transaction below then fails, restoreOnFailure below writes the
	// PREVIOUS content back (also atomically), so an operator reading the
	// file is not shown a change that was never applied.
	//
	// What this ordering does NOT buy, stated because the opposite was
	// claimed while defending it: the persisted file is not what a reboot
	// replays. The boot unit runs `contain reload-nft-rules`, which derives
	// the declared set from the managed CONFIG and re-renders from that, so
	// a stale file cannot re-introduce a revoked service. The window that
	// remains is a process killed between the rename and the kernel
	// transaction on a machine that keeps running: the file then describes
	// a boundary the kernel is not enforcing until the next reconciliation,
	// which `contain verify` reports. Closing that properly needs a durable
	// commit protocol rather than a different order.
	fileChanged := !bytesEqual(persisted, rules)
	if fileChanged {
		if err := env.writeFile(env.rulesPath, rules, modeConfigSecret); err != nil {
			return fmt.Errorf("persist reconciled nft rules %s: %w", env.rulesPath, err)
		}
	}
	restoreOnFailure := func(cause error) error {
		if !fileChanged {
			return cause
		}
		if restoreErr := env.writeFile(env.rulesPath, persisted, modeConfigSecret); restoreErr != nil {
			return errors.Join(cause, fmt.Errorf("restore previous nft rules %s after failed reload: %w", env.rulesPath, restoreErr))
		}
		return cause
	}

	out, code, err := env.runCmd(ctx, env.nftPath, "-n", "-a", "list", "chain", "inet", env.table, env.chain)
	if err != nil {
		return restoreOnFailure(fmt.Errorf("list nft managed chain: %w", err))
	}
	if code != 0 && strings.Contains(out, "No such file or directory") {
		// A missing chain is the normal first-boot state. Loading the canonical
		// file is sufficient and preserves nft's own error handling for any
		// other missing-table situation.
		out = ""
	} else if code != 0 {
		return restoreOnFailure(fmt.Errorf("list nft managed chain exit=%d: %s", code, oneLine(out)))
	}
	if !fileChanged && liveManagedNFTBlockMatchesRules(out, string(rules), header.operatorUID, header.proxyUID, header.agentUID) {
		if env.report != nil {
			env.report(nftReloadOutcome(false, 0, false))
		}
		return nil
	}
	managedHandles := legacyManagedNFTRuleBlockHandles(out, header.operatorUID, header.proxyUID, header.agentUID)
	script := renderNFTManagedChainReloadScript(out, string(rules), env.table, env.chain, header.operatorUID, header.proxyUID, header.agentUID)
	path := env.rulesPath + ".reload"
	if err := env.writeFile(path, []byte(script), modeConfigSecret); err != nil {
		return restoreOnFailure(fmt.Errorf("write nft managed chain reload file %s: %w", path, err))
	}
	defer func() { _ = env.removeFile(path) }()
	if _, code, err := env.runCmd(ctx, env.nftPath, "-c", "-f", path); err != nil || code != 0 {
		if err != nil {
			return restoreOnFailure(fmt.Errorf("validate nft managed chain reload: %w", err))
		}
		return restoreOnFailure(fmt.Errorf("validate nft managed chain reload exit=%d", code))
	}
	if _, code, err := env.runCmd(ctx, env.nftPath, "-f", path); err != nil || code != 0 {
		if err != nil {
			return restoreOnFailure(fmt.Errorf("reload nft managed chain: %w", err))
		}
		return restoreOnFailure(fmt.Errorf("reload nft managed chain exit=%d", code))
	}
	if env.report != nil {
		env.report(nftReloadOutcome(fileChanged, len(managedHandles), out == ""))
	}
	return nil
}

// partialManagedNFTBlockLength recovers a managed block whose declared-service
// rules are neither complete pairs nor the all-forward legacy shape: one
// service has a forward allow with no reply, or the two halves were separated.
// Such a block is reachable after an interrupted reconciliation, and until it
// is recognized nothing deletes it, so reload appends a replacement block and
// leaves the old forward allows in the chain. A forward allow for a service
// the operator has REVOKED would survive that way, which is the failure
// direction this exists to close.
//
// It stays narrow on purpose. A reply accept is absorbed only when the block
// already carries a forward allow for that exact host and port, so an
// operator's hand-written reply rule for a service this block never declared
// is left alone, exactly as the strict pair matcher leaves it alone.
func partialManagedNFTBlockLength(rules []nftRuleWithHandle, i, loopbackStart, agentUID int) (int, map[int]bool) {
	declared := map[string]bool{}
	foreign := map[int]bool{}
	tailStart := loopbackStart + 1
	for tailStart < len(rules) {
		line := rules[tailStart].line
		if lineHasAgentLoopbackAllowAnyPortAnyHost(line, agentUID) {
			fields := nftLineFields(line)
			declared[fields[5]+"/"+fields[8]] = true
			tailStart++
			continue
		}
		if key, ok := agentLoopbackReplyHostPortKey(line, agentUID); ok {
			if !declared[key] {
				// An operator reply rule for a service this block never declared.
				// Step OVER it rather than stopping here: stopping abandons every
				// managed rule after it, so a revoked service's forward allow would
				// survive reload and stay reachable. Its handle is excluded from
				// deletion, which is why the caller selects handles individually
				// instead of deleting a contiguous span.
				foreign[rules[tailStart].handle] = true
			}
			tailStart++
			continue
		}
		break
	}
	if tailStart == loopbackStart+1 || tailStart+2 >= len(rules) {
		return 0, nil
	}
	if !lineHasManagedDNSDrop(rules[tailStart].line, agentUID, "udp") ||
		!lineHasManagedDNSDrop(rules[tailStart+1].line, agentUID, "tcp") ||
		!lineHasManagedCatchAllDrop(rules[tailStart+2].line, agentUID) {
		return 0, nil
	}
	return tailStart + 3 - i, foreign
}

// agentLoopbackReplyHostPortKey reports the host/port a reply accept answers
// for, so a caller can require that the same block declared its forward.
func agentLoopbackReplyHostPortKey(line string, agentUID int) (string, bool) {
	fields := nftLineFields(line)
	for _, host := range []string{"127.0.0.1", "::1"} {
		for _, field := range fields {
			port, err := strconv.Atoi(field)
			if err != nil || !isTCPPort(field) {
				continue
			}
			if lineHasAgentLoopbackReplyForHost(line, agentUID, host, port) {
				return host + "/" + field, true
			}
		}
	}
	return "", false
}

func nftReloadOutcome(fileChanged bool, removedRules int, loadedMissingChain bool) string {
	if !fileChanged && removedRules == 0 && !loadedMissingChain {
		return "containment nft rules already reconciled, no change"
	}
	if loadedMissingChain {
		return "containment nft rules reconciled: loaded managed rules into a missing chain"
	}
	changes := make([]string, 0, 2)
	if removedRules > 0 {
		changes = append(changes, fmt.Sprintf("removed %d managed rule(s)", removedRules))
	}
	if fileChanged {
		changes = append(changes, "updated persisted rules")
	}
	return "containment nft rules reconciled: " + strings.Join(changes, "; ")
}

// liveManagedNFTBlockMatchesRules identifies the genuine no-op case without
// trusting textual equality. `nft -n -a` adds handles and counters and prints
// established/reply numerically, while the persisted source uses the named
// state. Foreign rules are deliberately excluded from this comparison.
func liveManagedNFTBlockMatchesRules(live, rulesBody string, operatorUID, proxyUID, agentUID int) bool {
	handles := legacyManagedNFTRuleBlockHandles(live, operatorUID, proxyUID, agentUID)
	want := managedNFTLinesFromRulesBody(rulesBody)
	if len(handles) == 0 || len(handles) != len(want) {
		return false
	}
	managed := make(map[int]struct{}, len(handles))
	for _, handle := range handles {
		managed[handle] = struct{}{}
	}
	got := make([]string, 0, len(handles))
	for _, rule := range nftRulesWithHandles(live) {
		if _, ok := managed[rule.handle]; ok {
			got = append(got, canonicalManagedNFTLine(rule.line))
		}
	}
	if len(got) != len(want) {
		return false
	}
	for i := range want {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

func managedNFTLinesFromRulesBody(rulesBody string) []string {
	lines := make([]string, 0)
	for _, line := range strings.Split(rulesBody, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "meta ") {
			lines = append(lines, canonicalManagedNFTLine(line))
		}
	}
	return lines
}

func canonicalManagedNFTLine(line string) string {
	fields := nftLineFields(line)
	canonical := make([]string, 0, len(fields))
	for i := 0; i < len(fields); i++ {
		if fields[i] == "counter" && i+4 < len(fields) && fields[i+1] == "packets" && isNonNegativeInteger(fields[i+2]) && fields[i+3] == "bytes" && isNonNegativeInteger(fields[i+4]) {
			canonical = append(canonical, fields[i])
			i += 4
			continue
		}
		if fields[i] == "0x2" && i > 0 && fields[i-1] == "state" {
			canonical = append(canonical, "established")
			continue
		}
		if fields[i] == "1" && i > 0 && fields[i-1] == "direction" {
			canonical = append(canonical, "reply")
			continue
		}
		canonical = append(canonical, fields[i])
	}
	return strings.Join(canonical, " ")
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
			// A genuinely absent managed config is not itself an error --
			// Pipelock may be reloading before contain install has ever
			// staged one -- but it is not silent either: an operator who
			// expects a declared service reachable needs to know reload
			// found no config to read it from, not only that the config was
			// malformed once it existed.
			if env.warn != nil {
				env.warn(fmt.Sprintf("containment: managed config %s not found; reloading without any declared loopback services; run `pipelock contain install` to restore it", env.configPath))
			}
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
		blockLen, foreign := managedNFTBlockLength(rules, i, operatorUID, proxyUID, agentUID)
		if blockLen == 0 {
			i++
			continue
		}
		for _, rule := range rules[i : i+blockLen] {
			if foreign[rule.handle] {
				continue
			}
			handles = append(handles, rule.handle)
		}
		i += blockLen
	}
	return handles
}

// managedNFTBlockLength returns the length of the managed rule block starting
// at rules[i], or 0 if no managed block starts there. The block is:
// operator accept, proxy accept, the implicit agent proxy-loopback allow,
// zero or more complete declared-service forward/reply pairs, DNS udp/53 drop,
// DNS tcp/53 drop, and catch-all drop. The reply matcher is exact so reload
// removes both halves of a declared service without absorbing unrelated
// hand-written reply rules. A contiguous-forward legacy block remains
// recognizable only to migrate rules rendered before reply pairs existed.
func managedNFTBlockLength(rules []nftRuleWithHandle, i, operatorUID, proxyUID, agentUID int) (int, map[int]bool) {
	if i+2 >= len(rules) {
		return 0, nil
	}
	if !lineHasTerminalSkuidVerdict(rules[i].line, operatorUID, "accept") ||
		!lineHasTerminalSkuidVerdict(rules[i+1].line, proxyUID, "accept") {
		return 0, nil
	}
	loopbackStart := i + 2
	if !lineHasAgentLoopbackAllowAnyPortAnyHost(rules[loopbackStart].line, agentUID) {
		return 0, nil
	}

	// The first allow is the implicit proxy port. Every additional service in a
	// current block must be the complete forward/reply pair rendered together.
	tailStart := loopbackStart + 1
	for tailStart < len(rules) && lineHasAgentLoopbackAllowAnyPortAnyHost(rules[tailStart].line, agentUID) {
		if tailStart+1 >= len(rules) || !lineHasAgentLoopbackReplyForForwardLine(rules[tailStart].line, rules[tailStart+1].line, agentUID) {
			if length := legacyManagedNFTBlockLength(rules, i, operatorUID, proxyUID, agentUID); length > 0 {
				return length, nil
			}
			return partialManagedNFTBlockLength(rules, i, loopbackStart, agentUID)
		}
		tailStart += 2
	}
	if tailStart+2 >= len(rules) {
		return 0, nil
	}
	if !lineHasManagedDNSDrop(rules[tailStart].line, agentUID, "udp") ||
		!lineHasManagedDNSDrop(rules[tailStart+1].line, agentUID, "tcp") ||
		!lineHasManagedCatchAllDrop(rules[tailStart+2].line, agentUID) {
		return 0, nil
	}
	return tailStart + 3 - i, nil
}

// legacyManagedNFTBlockLength recognizes the contiguous-forward format that
// earlier releases wrote. It is a migration-only path: current declared
// services must use complete pairs, while a block with no reply rules at all
// has to be removed before the repaired block can take effect ahead of its
// historical catch-all drop.
func legacyManagedNFTBlockLength(rules []nftRuleWithHandle, i, operatorUID, proxyUID, agentUID int) int {
	if i+2 >= len(rules) ||
		!lineHasTerminalSkuidVerdict(rules[i].line, operatorUID, "accept") ||
		!lineHasTerminalSkuidVerdict(rules[i+1].line, proxyUID, "accept") {
		return 0
	}
	tailStart := i + 2
	for tailStart < len(rules) && lineHasAgentLoopbackAllowAnyPortAnyHost(rules[tailStart].line, agentUID) {
		tailStart++
	}
	if tailStart == i+2 || tailStart+2 >= len(rules) ||
		!lineHasManagedDNSDrop(rules[tailStart].line, agentUID, "udp") ||
		!lineHasManagedDNSDrop(rules[tailStart+1].line, agentUID, "tcp") ||
		!lineHasManagedCatchAllDrop(rules[tailStart+2].line, agentUID) {
		return 0
	}
	return tailStart + 3 - i
}

func lineHasAgentLoopbackReplyForForwardLine(forward, reply string, agentUID int) bool {
	fields := nftLineFields(forward)
	if !lineHasAgentLoopbackAllowAnyPortAnyHost(forward, agentUID) {
		return false
	}
	port, err := strconv.Atoi(fields[8])
	if err != nil {
		return false
	}
	return lineHasAgentLoopbackReplyForHost(reply, agentUID, fields[5], port)
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
