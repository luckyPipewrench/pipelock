// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"time"
)

type nftCommandOutput func(context.Context, string, ...string) ([]byte, error)

const selfManagedNFTTimeout = 5 * time.Second

type selfManagedNFTVerifyOptions struct {
	ctx         context.Context
	operatorUID int
	proxyUID    int
	agentUID    int
	proxyPort   int
	statFn      func(string) (fs.FileInfo, error)
	run         nftCommandOutput
}

// VerifySelfManagedNFTRules confirms that live kernel state contains the
// canonical inet owner-match boundary for the supplied identities and port.
func VerifySelfManagedNFTRules(ctx context.Context, operatorUID, proxyUID, agentUID, proxyPort int) error {
	return verifySelfManagedNFTRules(selfManagedNFTVerifyOptions{
		ctx: ctx, operatorUID: operatorUID, proxyUID: proxyUID,
		agentUID: agentUID, proxyPort: proxyPort, statFn: os.Stat, run: runNFTCommand,
	})
}

func verifySelfManagedNFTRules(opts selfManagedNFTVerifyOptions) error {
	nftPath, err := trustedNFTPath(opts.statFn)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(opts.ctx, selfManagedNFTTimeout)
	defer cancel()
	out, err := opts.run(ctx, nftPath, "-n", "-a", "list", "chain", "inet", defaultNFTTable, defaultNFTChain)
	if err != nil {
		return fmt.Errorf("read live containment nft chain: %w: %s", err, oneLine(string(out)))
	}
	return validateSelfManagedNFTRules(string(out), opts.operatorUID, opts.proxyUID, opts.agentUID, opts.proxyPort)
}

func runNFTCommand(ctx context.Context, nftPath string, args ...string) ([]byte, error) {
	// #nosec G204 -- trustedNFTPath restricts execution to a root-owned,
	// non-writable binary at one of two fixed absolute system paths.
	return exec.CommandContext(ctx, nftPath, args...).CombinedOutput()
}

func trustedNFTPath(statFn func(string) (fs.FileInfo, error)) (string, error) {
	for _, path := range []string{"/usr/sbin/nft", "/usr/bin/nft"} {
		if _, err := statFn(path); err != nil {
			continue
		}
		if err := expectPrivilegedExecutablePath(statFn, "nft", path); err != nil {
			return "", err
		}
		return path, nil
	}
	return "", fmt.Errorf("trusted nft executable not found at /usr/sbin/nft or /usr/bin/nft")
}

func validateSelfManagedNFTRules(out string, operatorUID, proxyUID, agentUID, proxyPort int) error {
	if !nftTableDumpDeclaresExpectedTable(out, defaultNFTTable) ||
		!liveNFTContainmentMatches(out, defaultNFTChain, operatorUID, proxyUID, agentUID, proxyPort) {
		return fmt.Errorf("live containment nft chain does not match the canonical owner-match boundary for agent uid %d and proxy port %d", agentUID, proxyPort)
	}
	return nil
}
