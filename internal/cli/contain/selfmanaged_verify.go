// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
)

type nftCommandOutput func(context.Context, string, ...string) ([]byte, error)

// VerifySelfManagedNFTRules confirms that live kernel state contains the
// canonical inet owner-match boundary for the supplied identities and port.
func VerifySelfManagedNFTRules(ctx context.Context, operatorUID, proxyUID, agentUID, proxyPort int) error {
	return verifySelfManagedNFTRules(ctx, operatorUID, proxyUID, agentUID, proxyPort, os.Stat, runNFTCommand)
}

func verifySelfManagedNFTRules(
	ctx context.Context,
	operatorUID, proxyUID, agentUID, proxyPort int,
	statFn func(string) (fs.FileInfo, error),
	run nftCommandOutput,
) error {
	nftPath, err := trustedNFTPath(statFn)
	if err != nil {
		return err
	}
	out, err := run(ctx, nftPath, "-n", "-a", "list", "chain", "inet", defaultNFTTable, defaultNFTChain)
	if err != nil {
		return fmt.Errorf("read live containment nft chain: %w: %s", err, oneLine(string(out)))
	}
	return validateSelfManagedNFTRules(string(out), operatorUID, proxyUID, agentUID, proxyPort)
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
