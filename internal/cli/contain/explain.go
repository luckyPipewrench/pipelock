// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
)

const (
	defaultEgressEventsPath = "/var/lib/pipelock/contain/egress-events.jsonl"

	EgressClassDangerous                 = "dangerous"
	EgressClassToolIgnoresProxy          = "tool_ignores_proxy"
	EgressClassMisclassifiedLocalContext = "misclassified_local_context"
	EgressClassInfraProtection           = "infra_protection"
	EgressClassMissingCA                 = "missing_ca"
	EgressClassDirectDNS                 = "direct_dns_blocked"
	EgressClassNotRoutingThroughPipelock = "not_routing_through_pipelock"
)

type containExplainOpts struct {
	eventsPath string
	format     string
}

type egressBlockEvent struct {
	ID          string    `json:"id"`
	Time        time.Time `json:"time,omitempty"`
	Class       string    `json:"class"`
	Process     string    `json:"process,omitempty"`
	PID         *int      `json:"pid,omitempty"`
	UID         *int      `json:"uid,omitempty"`
	Destination string    `json:"dest,omitempty"`
	Port        *int      `json:"port,omitempty"`
	Protocol    string    `json:"protocol,omitempty"`
	Host        string    `json:"host,omitempty"`
	SizeBytes   int64     `json:"size_bytes,omitempty"`
	LimitBytes  int64     `json:"limit_bytes,omitempty"`
	Remediation string    `json:"remediation,omitempty"`
}

func explainCmd() *cobra.Command {
	var opts containExplainOpts
	cmd := &cobra.Command{
		Use:   "explain <event-id>",
		Short: "Explain a contained-egress block event",
		Long: `Explain a contained-egress block event.

The command reads the contain egress JSONL event log, finds the requested
event id, classifies the block, and prints the concrete remediation. The
installed nftables rules also emit classed kernel log prefixes for raw
egress drops; a collector can attach process metadata and write those events
to the JSONL file consumed here.`,
		SilenceUsage:  true,
		SilenceErrors: true,
		Args:          cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if opts.format != "" && opts.format != "text" && opts.format != "json" {
				return cliutil.ExitCodeError(cliutil.ExitConfig, fmt.Errorf("invalid --format %q (want text or json)", opts.format))
			}
			if opts.eventsPath == "" {
				opts.eventsPath = defaultEgressEventsPath
			}
			return runExplain(cmd.OutOrStdout(), opts, args[0])
		},
	}
	cmd.Flags().StringVar(&opts.eventsPath, "events", defaultEgressEventsPath, "contain egress JSONL event log")
	cmd.Flags().StringVar(&opts.format, "format", "text", "output format: text or json")
	return cmd
}

func runExplain(out io.Writer, opts containExplainOpts, id string) error {
	event, err := findEgressBlockEvent(opts.eventsPath, id)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return cliutil.ExitCodeError(cliutil.ExitConfig, fmt.Errorf("contain egress event log not found: %s", opts.eventsPath))
		}
		if errors.Is(err, errEgressEventNotFound) {
			return cliutil.ExitCodeError(cliutil.ExitConfig, fmt.Errorf("contain egress event %q not found in %s", id, opts.eventsPath))
		}
		return cliutil.ExitCodeError(cliutil.ExitConfig, err)
	}
	if event.Remediation == "" {
		event.Remediation = remediationForEgressClass(event.Class)
	}
	if opts.format == "json" {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return enc.Encode(event)
	}
	_, _ = fmt.Fprintf(out, "event: %s\n", event.ID)
	_, _ = fmt.Fprintf(out, "class: %s\n", event.Class)
	if event.Process != "" || event.PID != nil {
		_, _ = fmt.Fprintf(out, "process: %s%s\n", event.Process, pidSuffix(event.PID))
	}
	if event.UID != nil {
		_, _ = fmt.Fprintf(out, "uid: %d\n", *event.UID)
	}
	if event.Destination != "" || event.Port != nil {
		_, _ = fmt.Fprintf(out, "destination: %s%s\n", event.Destination, portSuffix(event.Port))
	}
	if event.Protocol != "" {
		_, _ = fmt.Fprintf(out, "protocol: %s\n", event.Protocol)
	}
	if event.Host != "" || event.SizeBytes != 0 || event.LimitBytes != 0 {
		_, _ = fmt.Fprintf(out, "response: host=%s size=%d limit=%d\n", event.Host, event.SizeBytes, event.LimitBytes)
	}
	_, _ = fmt.Fprintf(out, "remediation: %s\n", event.Remediation)
	return nil
}

var errEgressEventNotFound = errors.New("contain egress event not found")

func findEgressBlockEvent(path, id string) (egressBlockEvent, error) {
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return egressBlockEvent{}, err
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var event egressBlockEvent
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			return egressBlockEvent{}, fmt.Errorf("parse %s: %w", path, err)
		}
		if event.ID == id {
			return event, nil
		}
	}
	if err := sc.Err(); err != nil {
		return egressBlockEvent{}, fmt.Errorf("read %s: %w", path, err)
	}
	return egressBlockEvent{}, errEgressEventNotFound
}

func remediationForEgressClass(class string) string {
	switch class {
	case EgressClassDangerous:
		return "request was dangerous; keep it blocked or change policy only after review"
	case EgressClassToolIgnoresProxy:
		return "tool ignores proxy settings; run it through the plk wrapper or configure HTTPS_PROXY/ALL_PROXY for that tool"
	case EgressClassMissingCA:
		return "tool is using the proxy but does not trust Pipelock's CA; run pipelock contain ca-refresh and point the tool at /etc/pipelock/combined-ca.pem"
	case EgressClassDirectDNS:
		return "direct DNS is blocked; use the system resolver through the wrapped tool or route the tool through Pipelock"
	case EgressClassMisclassifiedLocalContext:
		return "local context was misclassified; narrow the rule or add a documented suppression without disabling egress scanning"
	case EgressClassInfraProtection:
		return "infra protection tripped; inspect session/airlock state and reset only after confirming the traffic is non-adversarial"
	case EgressClassNotRoutingThroughPipelock:
		return "not routing through Pipelock; use plk-launch/plk-* wrappers or configure the tool to honor HTTP_PROXY and HTTPS_PROXY"
	default:
		return "inspect the event and route the tool through Pipelock before retrying"
	}
}

func nftLogPrefix(class string) string {
	return "pipelock-contain class=" + class
}

func pidSuffix(pid *int) string {
	if pid == nil {
		return ""
	}
	return " pid=" + strconv.Itoa(*pid)
}

func portSuffix(port *int) string {
	if port == nil {
		return ""
	}
	return ":" + strconv.Itoa(*port)
}
