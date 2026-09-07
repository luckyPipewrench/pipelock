// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
)

var nftHandlePattern = regexp.MustCompile(`\s+# handle ([1-9][0-9]*)\s*$`)

// nftReloadEnv isolates the boot-time reconciler from the installer so tests
// can exercise its emitted nft transaction without changing a host ruleset.
type nftReloadEnv struct {
	nftPath    string
	rulesPath  string
	table      string
	chain      string
	runCmd     runCommand
	readFile   func(string) ([]byte, error)
	writeFile  func(string, []byte, os.FileMode) error
	removeFile func(string) error
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
		table:      defaultNFTTable,
		chain:      defaultNFTChain,
		runCmd:     realRunCommand,
		readFile:   os.ReadFile,
		writeFile:  os.WriteFile,
		removeFile: os.Remove,
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
	rules, err := env.readFile(env.rulesPath)
	if err != nil {
		return fmt.Errorf("read nft rules %s: %w", env.rulesPath, err)
	}
	header, ok, err := parseNFTRulesHeaderUIDs(rules)
	if err != nil {
		return fmt.Errorf("parse nft rules header %s: %w", env.rulesPath, err)
	}
	if !ok {
		return fmt.Errorf("nft rules %s is missing the managed uid header", env.rulesPath)
	}
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
	script := renderNFTManagedChainReloadScript(out, string(rules), env.table, env.chain, header.operatorUID, header.proxyUID, header.agentUID, header.proxyPort)
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
	return nil
}

// renderNFTManagedChainReloadScript removes complete, unlabelled legacy
// Pipelock rule blocks by handle before loading one canonical block. Legacy
// rules predate per-rule comments, so deleting an individual lookalike would
// risk deleting an operator rule. Requiring the complete ordered six-rule
// block preserves interleaved and standalone foreign rules, including narrow
// established-reply allows.
func renderNFTManagedChainReloadScript(live, rulesBody, table, chain string, operatorUID, proxyUID, agentUID, proxyPort int) string {
	handles := legacyManagedNFTRuleBlockHandles(live, operatorUID, proxyUID, agentUID, proxyPort)
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

func legacyManagedNFTRuleBlockHandles(live string, operatorUID, proxyUID, agentUID, proxyPort int) []int {
	rules := nftRulesWithHandles(live)
	var handles []int
	for i := 0; i+5 < len(rules); {
		block := rules[i : i+6]
		if !isLegacyManagedNFTBlock(block, operatorUID, proxyUID, agentUID, proxyPort) {
			i++
			continue
		}
		for _, rule := range block {
			handles = append(handles, rule.handle)
		}
		i += len(block)
	}
	return handles
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

func isLegacyManagedNFTBlock(block []nftRuleWithHandle, operatorUID, proxyUID, agentUID, proxyPort int) bool {
	return len(block) == 6 &&
		lineHasTerminalSkuidVerdict(block[0].line, operatorUID, "accept") &&
		lineHasTerminalSkuidVerdict(block[1].line, proxyUID, "accept") &&
		lineHasAgentProxyLoopbackAllow(block[2].line, agentUID, proxyPort) &&
		lineHasManagedDNSDrop(block[3].line, agentUID, "udp") &&
		lineHasManagedDNSDrop(block[4].line, agentUID, "tcp") &&
		lineHasManagedCatchAllDrop(block[5].line, agentUID)
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
