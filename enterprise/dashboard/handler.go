//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package dashboard

import (
	"bytes"
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/evidenceview"
	"github.com/luckyPipewrench/pipelock/internal/license"
)

const (
	contentSecurityPolicy = "default-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'"
	contentTypeHTML       = "text/html; charset=utf-8"
	contentTypeText       = "text/plain; charset=utf-8"
	auditSessionMaxBytes  = 128
)

//go:embed evidence.tmpl.html exemptions.tmpl.html agents.tmpl.html investigator.tmpl.html
var templateFS embed.FS

var (
	evidenceTemplate     = template.Must(template.ParseFS(templateFS, "evidence.tmpl.html"))
	exemptionsTemplate   = template.Must(template.ParseFS(templateFS, "exemptions.tmpl.html"))
	agentsTemplate       = template.Must(template.ParseFS(templateFS, "agents.tmpl.html"))
	investigatorTemplate = template.Must(template.ParseFS(templateFS, "investigator.tmpl.html"))
)

type pageData struct {
	Sessions        []SessionSummary
	SelectedSession string
	Evidence        SessionEvidence
	HasEvidence     bool
	RawAllowed      bool
}

type exemptionsPageData struct {
	Inventory ExemptionInventory
}

// New returns a read-only HTTP handler for the Enterprise Evidence dashboard.
//
// SECURITY: this handler serves sensitive evidence (signed receipt payloads,
// destinations, block reasons, signer fingerprints, session IDs). The
// license-feature check is NOT authentication. Mount this handler ONLY on an
// authenticated, admin-only listener, and never on the agent-reachable proxy
// port. Set Options.Authorize to enforce an authenticated principal per
// request; it fails closed when it returns an error. When Authorize is nil the
// surrounding router MUST provide the authentication boundary.
func New(opts Options) http.Handler {
	model := NewReadModel(opts)
	mux := http.NewServeMux()
	d := &dashboardHandler{
		model:        model,
		hasFeature:   opts.HasFeature,
		authorize:    opts.Authorize,
		authorizeRaw: opts.AuthorizeRaw,
		auditWriter:  opts.AuditWriter,
	}
	mux.Handle("/", d.gate(http.HandlerFunc(d.handleIndex)))
	mux.Handle("/exemptions", d.gate(http.HandlerFunc(d.handleExemptions)))
	mux.Handle("/session/", d.gate(http.HandlerFunc(d.handleSession)))
	mux.Handle("/agents", d.gate(http.HandlerFunc(d.handleAgents)))
	mux.Handle("/agent/", d.gate(http.HandlerFunc(d.handleAgent)))
	return mux
}

type dashboardHandler struct {
	model        *ReadModel
	hasFeature   func(string) bool
	authorize    func(*http.Request) error
	authorizeRaw func(*http.Request) error
	auditWriter  io.Writer
	auditMu      sync.Mutex
}

type rawAllowedContextKey struct{}

// rawAllowed reports whether this request may see the raw view (destinations
// and full signed payloads). Fail closed: raw is shown only when an authorizer
// is configured and accepts the request.
func (d *dashboardHandler) rawAllowed(r *http.Request) bool {
	return d.authorizeRaw != nil && d.authorizeRaw(r) == nil
}

func rawAllowedFromContext(r *http.Request) bool {
	raw, _ := r.Context().Value(rawAllowedContextKey{}).(bool)
	return raw
}

// recordAudit writes one access-log line for an authenticated request. Viewing
// evidence is itself an audited action. No-op when no writer is configured.
func (d *dashboardHandler) recordAudit(r *http.Request, raw bool) {
	if d.auditWriter == nil {
		return
	}
	role := "metadata"
	if raw {
		role = "raw"
	}
	session := r.URL.Query().Get("session")
	if session == "" {
		// Trim to the session ID for the audit field. The investigator path is
		// /session/<id>/receipt/<seq>, so cut at the first "/" to log <id>
		// rather than the full sub-path.
		rest := strings.TrimPrefix(r.URL.Path, "/session/")
		if i := strings.IndexByte(rest, '/'); i >= 0 {
			rest = rest[:i]
		}
		session = rest
	}
	if session == "" {
		session = "-"
	}
	sessionDisplay, sessionHash := auditSessionField(session)
	d.auditMu.Lock()
	defer d.auditMu.Unlock()
	_, _ = fmt.Fprintf(d.auditWriter, "%s pipelock-dashboard access role=%s method=%s path=%q session=%q session_sha256=%s remote=%s\n",
		time.Now().UTC().Format(time.RFC3339), role, r.Method, r.URL.Path, sessionDisplay, sessionHash, r.RemoteAddr)
}

func auditSessionField(session string) (display, hash string) {
	sum := sha256.Sum256([]byte(session))
	hash = hex.EncodeToString(sum[:])

	var b strings.Builder
	truncated := false
	for _, r := range session {
		if b.Len() >= auditSessionMaxBytes {
			truncated = true
			break
		}
		if r >= 0x20 && r <= 0x7e {
			b.WriteRune(r)
			continue
		}
		b.WriteByte('?')
	}
	display = b.String()
	if truncated && len(display) > 3 {
		display = display[:auditSessionMaxBytes-3] + "..."
	}
	if display == "" {
		display = "-"
	}
	return display, hash
}

func (d *dashboardHandler) gate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", contentSecurityPolicy)
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if d.hasFeature == nil || !d.hasFeature(license.FeatureAgents) {
			w.Header().Set("Content-Type", contentTypeText)
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte("Pipelock Enterprise agents feature required\n"))
			return
		}
		// Authentication boundary. The license check above is entitlement, not
		// identity; fail closed when a configured authorizer rejects the request.
		if d.authorize != nil {
			if err := d.authorize(r); err != nil {
				w.Header().Set("Content-Type", contentTypeText)
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte("forbidden\n"))
				return
			}
		}
		raw := d.rawAllowed(r)
		d.recordAudit(r, raw)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), rawAllowedContextKey{}, raw)))
	})
}

func (d *dashboardHandler) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	if !requireGet(w, r) {
		return
	}

	sessions, err := d.model.Sessions()
	if err != nil {
		http.Error(w, "could not read evidence sessions", http.StatusInternalServerError)
		return
	}

	selected := r.URL.Query().Get("session")
	if selected == "" && len(sessions) > 0 {
		selected = sessions[0].ID
	}
	d.render(w, sessions, selected, rawAllowedFromContext(r))
}

func (d *dashboardHandler) handleExemptions(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/exemptions" {
		http.NotFound(w, r)
		return
	}
	if !requireGet(w, r) {
		return
	}
	inventory := d.model.Exemptions()
	// Exemption scopes/attributes are a map of internal destinations, IP
	// allowlists, addresses, and enforcement exceptions — as sensitive as the
	// evidence view's raw destinations. Fail closed: strip them in Go unless
	// this request is authorized for raw, so raw values never reach a
	// metadata-only response.
	if !rawAllowedFromContext(r) {
		inventory = redactExemptions(inventory)
	}
	data := exemptionsPageData{Inventory: inventory}
	var buf bytes.Buffer
	if err := exemptionsTemplate.Execute(&buf, data); err != nil {
		http.Error(w, "could not render exemptions", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", contentTypeHTML)
	_, _ = w.Write(buf.Bytes())
}

func requireGet(w http.ResponseWriter, r *http.Request) bool {
	if r.Method == http.MethodGet {
		return true
	}
	w.Header().Set("Allow", http.MethodGet)
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	return false
}

type agentsPageData struct {
	Groups     []evidenceview.AgentGroup
	Filter     FilterSpec
	RawAllowed bool
}

type investigatorPageData struct {
	SessionID   string
	Seq         uint64
	Explanation evidenceview.DecisionExplanation
	RawAllowed  bool
}

func (d *dashboardHandler) handleAgents(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/agents" {
		http.NotFound(w, r)
		return
	}
	if !requireGet(w, r) {
		return
	}
	filter := d.model.ResolveFilter(r)
	groups, err := d.model.Agents(filter)
	if err != nil {
		http.Error(w, "could not read agent evidence", http.StatusInternalServerError)
		return
	}
	data := agentsPageData{
		Groups:     groups,
		Filter:     filter,
		RawAllowed: rawAllowedFromContext(r),
	}
	var buf bytes.Buffer
	if err := agentsTemplate.Execute(&buf, data); err != nil {
		http.Error(w, "could not render agents view", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", contentTypeHTML)
	_, _ = w.Write(buf.Bytes())
}

func (d *dashboardHandler) handleAgent(w http.ResponseWriter, r *http.Request) {
	if !requireGet(w, r) {
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, "/agent/")
	if rest == "" || strings.Contains(rest, "/") {
		http.NotFound(w, r)
		return
	}
	agentID := rest
	filter := d.model.ResolveFilter(r)
	group, found, err := d.model.Agent(agentID, filter)
	if err != nil {
		http.Error(w, "could not read agent evidence", http.StatusInternalServerError)
		return
	}
	if !found {
		http.NotFound(w, r)
		return
	}
	data := agentsPageData{
		Groups:     []evidenceview.AgentGroup{group},
		Filter:     filter,
		RawAllowed: rawAllowedFromContext(r),
	}
	var buf bytes.Buffer
	if err := agentsTemplate.Execute(&buf, data); err != nil {
		http.Error(w, "could not render agent view", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", contentTypeHTML)
	_, _ = w.Write(buf.Bytes())
}

func (d *dashboardHandler) handleSession(w http.ResponseWriter, r *http.Request) {
	if !requireGet(w, r) {
		return
	}

	rest := strings.TrimPrefix(r.URL.Path, "/session/")
	if rest == "" {
		http.NotFound(w, r)
		return
	}
	// Handle /session/<id>/receipt/<seq> — the investigator route.
	if strings.Contains(rest, "/") {
		d.handleSessionReceipt(w, r, rest)
		return
	}
	selected := rest
	sessions, err := d.model.Sessions()
	if err != nil {
		http.Error(w, "could not read evidence sessions", http.StatusInternalServerError)
		return
	}
	d.render(w, sessions, selected, rawAllowedFromContext(r))
}

func (d *dashboardHandler) handleSessionReceipt(w http.ResponseWriter, r *http.Request, rest string) {
	// Expected: <sessionID>/receipt/<seq>
	parts := strings.SplitN(rest, "/", 3)
	if len(parts) != 3 || parts[1] != "receipt" || parts[0] == "" || parts[2] == "" {
		http.NotFound(w, r)
		return
	}
	sessionID := parts[0]
	// Reject path traversal.
	if strings.Contains(sessionID, "..") || strings.Contains(sessionID, "/") {
		http.NotFound(w, r)
		return
	}
	seq, err := strconv.ParseUint(parts[2], 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	explanation, found, err := d.model.ReceiptDetail(sessionID, seq)
	if err != nil {
		http.Error(w, "could not read receipt detail", http.StatusInternalServerError)
		return
	}
	if !found {
		http.NotFound(w, r)
		return
	}
	raw := rawAllowedFromContext(r)
	if !raw {
		explanation = evidenceview.RedactExplanation(explanation)
	}
	data := investigatorPageData{
		SessionID:   sessionID,
		Seq:         seq,
		Explanation: explanation,
		RawAllowed:  raw,
	}
	var buf bytes.Buffer
	if err := investigatorTemplate.Execute(&buf, data); err != nil {
		http.Error(w, "could not render investigator view", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", contentTypeHTML)
	_, _ = w.Write(buf.Bytes())
}

func (d *dashboardHandler) render(w http.ResponseWriter, sessions []SessionSummary, selected string, raw bool) {
	data := pageData{
		Sessions:        sessions,
		SelectedSession: selected,
		RawAllowed:      raw,
	}
	if selected != "" {
		evidence, err := d.model.Session(selected)
		if err != nil {
			http.Error(w, "could not read selected evidence", http.StatusInternalServerError)
			return
		}
		// Fail closed: strip destinations and signed payloads in Go before
		// templating unless this request is authorized for raw, so the raw
		// bytes never reach the response.
		if !raw {
			evidence = redactRaw(evidence)
		}
		data.Evidence = evidence
		data.HasEvidence = true
	}

	var buf bytes.Buffer
	if err := evidenceTemplate.Execute(&buf, data); err != nil {
		http.Error(w, "could not render evidence", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", contentTypeHTML)
	_, _ = w.Write(buf.Bytes())
}
