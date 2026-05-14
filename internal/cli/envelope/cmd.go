// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package envelope implements operator CLI helpers for mediation envelopes.
package envelope

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	domenvelope "github.com/luckyPipewrench/pipelock/internal/envelope"
)

const (
	directoryAlg               = "ed25519"
	directoryUse               = "pipelock-mediation"
	maxVerifyStdinBodyBytes    = 16 << 20
	maxVerifyRawRequestBytes   = maxVerifyStdinBodyBytes + (1 << 20)
	runtimeTrustAdvisoryFormat = "note: runtime proxy verification reads trusted keys from pipelock.yaml mediation_envelope.verify_inbound.trust_list; this trust store is for operator workflows until runtime trust-store loading is added.\n"
)

var errHTTPRequestTooLarge = errors.New("request exceeds size limit")

// Cmd returns the `pipelock envelope` cobra command tree.
func Cmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:           "envelope",
		Short:         "Manage mediation-envelope federation trust",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	cmd.AddCommand(trustCmd())
	return cmd
}

func trustCmd() *cobra.Command {
	var storePath string
	cmd := &cobra.Command{
		Use:           "trust",
		Short:         "Manage trusted mediation-envelope peers",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	cmd.PersistentFlags().StringVar(&storePath, "store", "", "trust store path (default $XDG_STATE_HOME/pipelock/envelope/trust.json)")
	cmd.AddCommand(
		trustAddCmd(&storePath),
		trustListCmd(&storePath),
		trustRemoveCmd(&storePath),
		trustVerifyCmd(&storePath),
	)
	return cmd
}

func trustAddCmd(storePath *string) *cobra.Command {
	var keyHex, sourceURL string
	cmd := &cobra.Command{
		Use:   "add <trust-domain-or-spiffe-id>",
		Short: "Add or update a trusted mediation-envelope peer",
		Long: `Add or update a trusted mediation-envelope peer in the local operator
trust store.

The runtime proxy verifier does not read this store yet. To change what
Pipelock accepts at runtime, update mediation_envelope.verify_inbound.trust_list
in pipelock.yaml and reload the proxy. This store is used by operator workflows
such as trust list review, peer onboarding, and envelope trust verify.

Only use --source for a directory you already intend to trust. The fetched key
becomes local trust material for operator verification workflows.`,
		Args:          cobra.ExactArgs(1),
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			trustDomain, spiffeID, err := parseTrustTarget(args[0])
			if err != nil {
				return cliutil.ExitCodeError(cliutil.ExitConfig, err)
			}
			key, source, err := resolveTrustKey(cmd.Context(), keyHex, sourceURL)
			if err != nil {
				return cliutil.ExitCodeError(cliutil.ExitConfig, err)
			}
			store, err := newTrustStore(*storePath)
			if err != nil {
				return cliutil.ExitCodeError(cliutil.ExitConfig, err)
			}
			records, err := store.load()
			if err != nil {
				return cliutil.ExitCodeError(cliutil.ExitConfig, err)
			}
			rec := trustRecord{
				TrustDomain: trustDomain,
				SPIFFEID:    spiffeID,
				KeyHex:      key,
				KeySource:   source,
				AddedAt:     time.Now().UTC(),
			}
			idx := findTrustRecord(records, trustDomain, spiffeID)
			switch {
			case idx >= 0 && records[idx].KeyHex == key && records[idx].KeySource == source:
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "already trusted\t%s\n", displayTrustTarget(records[idx]))
				_, _ = fmt.Fprint(cmd.ErrOrStderr(), runtimeTrustAdvisoryFormat)
				return nil
			case idx >= 0:
				rec.AddedAt = records[idx].AddedAt
				records[idx] = rec
			default:
				records = append(records, rec)
			}
			if err := store.save(records); err != nil {
				return cliutil.ExitCodeError(cliutil.ExitConfig, err)
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "trusted\t%s\n", displayTrustTarget(rec))
			_, _ = fmt.Fprint(cmd.ErrOrStderr(), runtimeTrustAdvisoryFormat)
			return nil
		},
	}
	cmd.Flags().StringVar(&keyHex, "key", "", "raw hex Ed25519 public key")
	cmd.Flags().StringVar(&sourceURL, "source", "", "well-known HTTP Message Signatures directory URL to trust")
	return cmd
}

func trustListCmd(storePath *string) *cobra.Command {
	var jsonOut bool
	cmd := &cobra.Command{
		Use:           "list",
		Short:         "List trusted mediation-envelope peers",
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			store, err := newTrustStore(*storePath)
			if err != nil {
				return cliutil.ExitCodeError(cliutil.ExitConfig, err)
			}
			records, err := store.load()
			if err != nil {
				return cliutil.ExitCodeError(cliutil.ExitConfig, err)
			}
			if jsonOut {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(records)
			}
			tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			_, _ = fmt.Fprintln(tw, "TRUST_DOMAIN\tSPIFFE_ID\tKEY\tSOURCE\tADDED_AT")
			for _, rec := range records {
				_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
					rec.TrustDomain,
					emptyDash(rec.SPIFFEID),
					keySummary(rec.KeyHex),
					emptyDash(rec.KeySource),
					rec.AddedAt.UTC().Format(time.RFC3339),
				)
			}
			return tw.Flush()
		},
	}
	cmd.Flags().BoolVar(&jsonOut, "json", false, "print trust list as JSON")
	return cmd
}

func trustRemoveCmd(storePath *string) *cobra.Command {
	cmd := &cobra.Command{
		Use:           "remove <trust-domain-or-spiffe-id>",
		Short:         "Remove a trusted mediation-envelope peer",
		Args:          cobra.ExactArgs(1),
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			trustDomain, spiffeID, err := parseTrustTarget(args[0])
			if err != nil {
				return cliutil.ExitCodeError(cliutil.ExitConfig, err)
			}
			store, err := newTrustStore(*storePath)
			if err != nil {
				return cliutil.ExitCodeError(cliutil.ExitConfig, err)
			}
			records, err := store.load()
			if err != nil {
				return cliutil.ExitCodeError(cliutil.ExitConfig, err)
			}
			idx := findTrustRecord(records, trustDomain, spiffeID)
			if idx < 0 {
				return cliutil.ExitCodeError(cliutil.ExitConfig, fmt.Errorf("trust target %q is not present", args[0]))
			}
			removed := records[idx]
			records = append(records[:idx], records[idx+1:]...)
			if err := store.save(records); err != nil {
				return cliutil.ExitCodeError(cliutil.ExitConfig, err)
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "removed\t%s\n", displayTrustTarget(removed))
			return nil
		},
	}
	return cmd
}

func trustVerifyCmd(storePath *string) *cobra.Command {
	var stdin bool
	cmd := &cobra.Command{
		Use:           "verify",
		Short:         "Verify an inbound mediation envelope against the trust list",
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			store, err := newTrustStore(*storePath)
			if err != nil {
				return cliutil.ExitCodeError(cliutil.ExitConfig, err)
			}
			records, err := store.load()
			if err != nil {
				return cliutil.ExitCodeError(cliutil.ExitConfig, err)
			}
			verifier, err := verifierFromTrustRecords(records)
			if err != nil {
				return cliutil.ExitCodeError(cliutil.ExitConfig, err)
			}
			if !stdin {
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "trust store ready\t%d trusted peer(s)\n", len(records))
				return nil
			}
			req, body, err := readHTTPRequest(cmd.InOrStdin())
			if err != nil {
				return cliutil.ExitCodeError(cliutil.ExitConfig, err)
			}
			env, err := verifier.VerifyRequest(req, body)
			if err != nil {
				return cliutil.ExitCodeError(cliutil.ExitSecurity, fmt.Errorf("verification failed: %w", err))
			}
			actor, err := domenvelope.ParseActorStrict(env.Actor)
			if err != nil {
				return cliutil.ExitCodeError(cliutil.ExitSecurity, fmt.Errorf("verified envelope has invalid actor: %w", err))
			}
			if !actorAllowedByTrustRecords(actor, records) {
				return cliutil.ExitCodeError(cliutil.ExitSecurity, fmt.Errorf("actor %q is not in the trust list", env.Actor))
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "verified\tactor=%s\ttrust_domain=%s\n", env.Actor, actor.TrustDomain)
			return nil
		},
	}
	cmd.Flags().BoolVar(&stdin, "stdin", false, "read a raw HTTP request from stdin")
	return cmd
}

func resolveTrustKey(ctx context.Context, keyHex, sourceURL string) (string, string, error) {
	keyHex = strings.TrimSpace(keyHex)
	sourceURL = strings.TrimSpace(sourceURL)
	switch {
	case keyHex != "" && sourceURL != "":
		return "", "", errors.New("use exactly one of --key or --source")
	case keyHex != "":
		key, err := normalizeKeyHex(keyHex)
		return key, "", err
	case sourceURL != "":
		key, err := fetchDirectoryKey(ctx, sourceURL)
		return key, sourceURL, err
	default:
		return "", "", errors.New("one of --key or --source is required")
	}
}

func fetchDirectoryKey(ctx context.Context, sourceURL string) (string, error) {
	parsed, err := url.Parse(sourceURL)
	if err != nil {
		return "", fmt.Errorf("parsing directory URL: %w", err)
	}
	if !isAllowedDirectoryURL(parsed) {
		return "", errors.New("directory URL must be https or loopback http")
	}
	u, err := http.NewRequestWithContext(ctx, http.MethodGet, sourceURL, nil)
	if err != nil {
		return "", fmt.Errorf("building directory request: %w", err)
	}
	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, _ []*http.Request) error {
			if !isAllowedDirectoryURL(req.URL) {
				return errors.New("directory URL must be https or loopback http")
			}
			return nil
		},
	}
	resp, err := client.Do(u)
	if err != nil {
		return "", fmt.Errorf("fetching directory: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("directory returned HTTP %d", resp.StatusCode)
	}
	var dir domenvelope.Directory
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&dir); err != nil {
		return "", fmt.Errorf("decoding directory: %w", err)
	}
	for _, key := range dir.Keys {
		if key.Algorithm != directoryAlg || key.Use != directoryUse {
			continue
		}
		keyHex, err := normalizeKeyHex(key.PublicKey)
		if err != nil {
			return "", fmt.Errorf("directory key %q: %w", key.KeyID, err)
		}
		return keyHex, nil
	}
	return "", errors.New("directory contains no pipelock Ed25519 mediation key")
}

// verifierFromTrustRecords builds a verifier at trust-domain granularity.
// Callers that need SPIFFE-ID pins must also call actorAllowedByTrustRecords
// after VerifyRequest succeeds; the verifier alone does not enforce them.
func verifierFromTrustRecords(records []trustRecord) (*domenvelope.Verifier, error) {
	if len(records) == 0 {
		return nil, errors.New("trust store is empty")
	}
	keysByDomain := make(map[string]ed25519.PublicKey)
	for _, rec := range records {
		pubBytes, err := hex.DecodeString(rec.KeyHex)
		if err != nil {
			return nil, fmt.Errorf("decode key for %s: %w", rec.TrustDomain, err)
		}
		pub := ed25519.PublicKey(pubBytes)
		if existing, ok := keysByDomain[rec.TrustDomain]; ok {
			if !bytes.Equal(existing, pub) {
				return nil, fmt.Errorf("trust domain %q has multiple keys; split it into one key before verifying", rec.TrustDomain)
			}
			continue
		}
		keysByDomain[rec.TrustDomain] = pub
	}
	keys := make([]domenvelope.TrustedKey, 0, len(keysByDomain))
	for domain, pub := range keysByDomain {
		keys = append(keys, domenvelope.TrustedKey{
			KeyID:        domain,
			PublicKey:    pub,
			TrustDomains: []string{domain},
		})
	}
	return domenvelope.NewVerifier(domenvelope.VerifierConfig{
		TrustedKeys: keys,
		ReplayCache: domenvelope.NewReplayCache(5*time.Minute, 10000),
		Skew:        time.Minute,
		ActorFormat: domenvelope.ActorFormatSPIFFE,
	})
}

func actorAllowedByTrustRecords(actor domenvelope.ParsedActor, records []trustRecord) bool {
	for _, rec := range records {
		if rec.TrustDomain != actor.TrustDomain {
			continue
		}
		if rec.SPIFFEID == "" {
			return true
		}
		parsed, err := domenvelope.ParseActorStrict(rec.SPIFFEID)
		if err == nil && parsed.TrustDomain == actor.TrustDomain && parsed.Workload == actor.Workload {
			return true
		}
	}
	return false
}

func readHTTPRequest(r io.Reader) (*http.Request, []byte, error) {
	limited := &requestLimitReader{r: r, remaining: maxVerifyRawRequestBytes}
	req, err := http.ReadRequest(bufio.NewReader(limited))
	if err != nil {
		if limited.exceeded || errors.Is(err, errHTTPRequestTooLarge) {
			return nil, nil, fmt.Errorf("request exceeds %d bytes", maxVerifyRawRequestBytes)
		}
		return nil, nil, fmt.Errorf("reading HTTP request: %w", err)
	}
	var body []byte
	if req.Body != nil {
		body, err = io.ReadAll(io.LimitReader(req.Body, maxVerifyStdinBodyBytes+1))
		_ = req.Body.Close()
		if err != nil {
			if limited.exceeded || errors.Is(err, errHTTPRequestTooLarge) {
				return nil, nil, fmt.Errorf("request exceeds %d bytes", maxVerifyRawRequestBytes)
			}
			return nil, nil, fmt.Errorf("reading request body: %w", err)
		}
		if len(body) > maxVerifyStdinBodyBytes {
			return nil, nil, fmt.Errorf("request body exceeds %d bytes", maxVerifyStdinBodyBytes)
		}
		req.Body = io.NopCloser(bytes.NewReader(body))
		req.ContentLength = int64(len(body))
	}
	return req, body, nil
}

type requestLimitReader struct {
	r         io.Reader
	remaining int64
	exceeded  bool
}

func (r *requestLimitReader) Read(p []byte) (int, error) {
	if r.remaining <= 0 {
		r.exceeded = true
		return 0, errHTTPRequestTooLarge
	}
	if int64(len(p)) > r.remaining {
		p = p[:r.remaining]
	}
	n, err := r.r.Read(p)
	r.remaining -= int64(n)
	return n, err
}

func displayTrustTarget(rec trustRecord) string {
	if rec.SPIFFEID != "" {
		return rec.SPIFFEID
	}
	return rec.TrustDomain
}

func keySummary(key string) string {
	if len(key) <= 16 {
		return key
	}
	return key[:12] + "..." + key[len(key)-4:]
}

func emptyDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
