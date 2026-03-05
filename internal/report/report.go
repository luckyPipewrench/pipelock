// Package report generates HTML and JSON audit reports from JSONL event logs.
package report

import (
	"io"
	"time"
)

// Event represents a single parsed audit log entry.
type Event struct {
	Time           time.Time `json:"time"`
	Level          string    `json:"level"`
	Event          string    `json:"event"`
	Component      string    `json:"component,omitempty"`
	Message        string    `json:"message,omitempty"`
	Method         string    `json:"method,omitempty"`
	URL            string    `json:"url,omitempty"`
	Target         string    `json:"target,omitempty"`
	Scanner        string    `json:"scanner,omitempty"`
	Reason         string    `json:"reason,omitempty"`
	Action         string    `json:"action,omitempty"`
	ClientIP       string    `json:"client_ip,omitempty"`
	RequestID      string    `json:"request_id,omitempty"`
	StatusCode     int       `json:"status_code,omitempty"`
	SizeBytes      int       `json:"size_bytes,omitempty"`
	MatchCount     int       `json:"match_count,omitempty"`
	Patterns       []string  `json:"patterns,omitempty"`
	MITRETechnique string    `json:"mitre_technique,omitempty"`
	Score          float64   `json:"score,omitempty"`
	Version        string    `json:"version,omitempty"`
	ConfigHash     string    `json:"config_hash,omitempty"`
	Mode           string    `json:"mode,omitempty"`
	Pattern        string    `json:"pattern,omitempty"`
	Severity       string    `json:"severity,omitempty"`
	Session        string    `json:"session,omitempty"`
	Tool           string    `json:"tool,omitempty"`
	Direction      string    `json:"direction,omitempty"`
	Header         string    `json:"header,omitempty"`
	Listen         string    `json:"listen,omitempty"`
	Status         string    `json:"status,omitempty"`
	Detail         string    `json:"detail,omitempty"`
	Transport      string    `json:"transport,omitempty"`
	Endpoint       string    `json:"endpoint,omitempty"`
	Source         string    `json:"source,omitempty"`
	DenyMessage    string    `json:"deny_message,omitempty"`
	ConnectHost    string    `json:"connect_host,omitempty"`
	SNIHost        string    `json:"sni_host,omitempty"`
	Category       string    `json:"category,omitempty"`
}

// Report is the top-level report data structure.
type Report struct {
	Title        string          `json:"title"`
	Generated    time.Time       `json:"generated"`
	Version      string          `json:"version"`
	ConfigHashes []string        `json:"config_hashes"`
	Mode         string          `json:"mode"`
	TimeRange    TimeRange       `json:"time_range"`
	Risk         RiskRating      `json:"risk"`
	Summary      Summary         `json:"summary"`
	Categories   []CategoryStats `json:"categories"`
	Timeline     []TimeBucket    `json:"timeline"`
	Evidence     []Event         `json:"evidence"`
}

// RiskRating is Red, Yellow, or Green.
type RiskRating string

const (
	RiskRed    RiskRating = "red"
	RiskYellow RiskRating = "yellow"
	RiskGreen  RiskRating = "green"
)

// TimeRange describes the report window.
type TimeRange struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

// Summary holds the KPI numbers.
type Summary struct {
	TotalEvents   int `json:"total_events"`
	Blocks        int `json:"blocks"`
	Warnings      int `json:"warnings"`
	Criticals     int `json:"criticals"`
	Allowed       int `json:"allowed"`
	UniqueDomains int `json:"unique_domains"`
}

// CategoryStats groups events by attack category.
type CategoryStats struct {
	Name            string   `json:"name"`
	Count           int      `json:"count"`
	Severity        string   `json:"severity"`
	MITRETechniques []string `json:"mitre_techniques"`
	SampleEvidence  []string `json:"sample_evidence,omitempty"`
}

// TimeBucket is one slot in the timeline histogram.
type TimeBucket struct {
	Start   time.Time `json:"start"`
	Blocks  int       `json:"blocks"`
	Warns   int       `json:"warns"`
	Allowed int       `json:"allowed"`
}

// Options controls report generation.
type Options struct {
	Title       string
	MaxEvidence int  // cap on evidence appendix entries (default 100)
	Redact      bool // strip URLs/IPs from evidence
}

// defaultMaxEvidence is the evidence appendix cap when Options.MaxEvidence is 0.
const defaultMaxEvidence = 100

// DefaultTitle is used when Options.Title is empty.
const DefaultTitle = "Pipelock Agent Egress Report"

// Generate reads JSONL events, applies time filters, aggregates, and produces a Report.
func Generate(r io.Reader, popts ParseOptions, opts Options) (*Report, error) {
	events, err := ParseEvents(r, popts)
	if err != nil {
		return nil, err
	}
	return Aggregate(events, opts), nil
}
