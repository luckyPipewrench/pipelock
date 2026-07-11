//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package dashboard

import (
	"bytes"
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"errors"
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

//go:embed evidence.tmpl.html exemptions.tmpl.html agents.tmpl.html investigator.tmpl.html fleetoverview.tmpl.html workbench.tmpl.html incident.tmpl.html budgets.tmpl.html trustkeys.tmpl.html compliance.tmpl.html
var templateFS embed.FS

var (
	evidenceTemplate      = template.Must(template.ParseFS(templateFS, "evidence.tmpl.html"))
	exemptionsTemplate    = template.Must(template.ParseFS(templateFS, "exemptions.tmpl.html"))
	agentsTemplate        = template.Must(template.ParseFS(templateFS, "agents.tmpl.html"))
	investigatorTemplate  = template.Must(template.ParseFS(templateFS, "investigator.tmpl.html"))
	fleetoverviewTemplate = template.Must(template.ParseFS(templateFS, "fleetoverview.tmpl.html"))
	workbenchTemplate     = template.Must(template.ParseFS(templateFS, "workbench.tmpl.html"))
	incidentTemplate      = template.Must(template.ParseFS(templateFS, "incident.tmpl.html"))
	budgetsTemplate       = template.Must(template.ParseFS(templateFS, "budgets.tmpl.html"))
	trustKeysTemplate     = template.Must(template.ParseFS(templateFS, "trustkeys.tmpl.html"))
	complianceTemplate    = template.Must(template.ParseFS(templateFS, "compliance.tmpl.html"))
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

// Permission is the bounded dashboard route/action vocabulary consumed by the
// RBAC seam. Keep these stable: external auth adapters map identities to these
// strings, while handlers stay unaware of user/role storage.
type Permission string

const (
	PermissionEvidenceRead     Permission = "dashboard:evidence:read"
	PermissionRawRead          Permission = "dashboard:raw:read"
	PermissionExemptionsRead   Permission = "dashboard:exemptions:read"
	PermissionAgentsRead       Permission = "dashboard:agents:read"
	PermissionBudgetsRead      Permission = "dashboard:budgets:read"
	PermissionFleetRead        Permission = "dashboard:fleet:read"
	PermissionSignedActionRead Permission = "dashboard:signed_action:read"
	PermissionIncidentRead     Permission = "dashboard:incident:read"
	PermissionTrustKeysRead    Permission = "dashboard:trust_keys:read"
	PermissionComplianceRead   Permission = "dashboard:compliance:read"
)

const (
	agentsFeatureForbidden = "Pipelock Enterprise agents feature required\n"
	fleetFeatureForbidden  = "Pipelock Enterprise fleet feature required\n"
)

type routeSpec struct {
	pattern          string
	feature          string
	forbiddenMessage string
	permission       Permission
	handler          func(*dashboardHandler) http.Handler
}

// CompliancePath is the single source of truth for the compliance route, shared
// by the route table and the auditor-token authorization gate so the auth
// boundary cannot drift from the route if the path changes.
const CompliancePath = "/compliance"

func dashboardRouteSpecs() []routeSpec {
	return []routeSpec{
		{
			pattern:          "/",
			feature:          license.FeatureAgents,
			forbiddenMessage: agentsFeatureForbidden,
			permission:       PermissionEvidenceRead,
			handler: func(d *dashboardHandler) http.Handler {
				return http.HandlerFunc(d.handleIndex)
			},
		},
		{
			pattern:          "/exemptions",
			feature:          license.FeatureAgents,
			forbiddenMessage: agentsFeatureForbidden,
			permission:       PermissionExemptionsRead,
			handler: func(d *dashboardHandler) http.Handler {
				return http.HandlerFunc(d.handleExemptions)
			},
		},
		{
			pattern:          "/session/",
			feature:          license.FeatureAgents,
			forbiddenMessage: agentsFeatureForbidden,
			permission:       PermissionEvidenceRead,
			handler: func(d *dashboardHandler) http.Handler {
				return http.HandlerFunc(d.handleSession)
			},
		},
		{
			pattern:          "/agents",
			feature:          license.FeatureAgents,
			forbiddenMessage: agentsFeatureForbidden,
			permission:       PermissionAgentsRead,
			handler: func(d *dashboardHandler) http.Handler {
				return http.HandlerFunc(d.handleAgents)
			},
		},
		{
			pattern:          "/agent/",
			feature:          license.FeatureAgents,
			forbiddenMessage: agentsFeatureForbidden,
			permission:       PermissionAgentsRead,
			handler: func(d *dashboardHandler) http.Handler {
				return http.HandlerFunc(d.handleAgent)
			},
		},
		{
			pattern:          "/budgets",
			feature:          license.FeatureAgents,
			forbiddenMessage: agentsFeatureForbidden,
			permission:       PermissionBudgetsRead,
			handler: func(d *dashboardHandler) http.Handler {
				return http.HandlerFunc(d.handleBudgets)
			},
		},
		{
			pattern:          "/trust-keys",
			feature:          license.FeatureAgents,
			forbiddenMessage: agentsFeatureForbidden,
			permission:       PermissionTrustKeysRead,
			handler: func(d *dashboardHandler) http.Handler {
				return http.HandlerFunc(d.handleTrustKeys)
			},
		},
		{
			pattern:          CompliancePath,
			feature:          license.FeatureAgents,
			forbiddenMessage: agentsFeatureForbidden,
			permission:       PermissionComplianceRead,
			handler: func(d *dashboardHandler) http.Handler {
				return http.HandlerFunc(d.handleCompliance)
			},
		},
		{
			pattern:          "/fleet",
			feature:          license.FeatureFleet,
			forbiddenMessage: fleetFeatureForbidden,
			permission:       PermissionFleetRead,
			handler: func(d *dashboardHandler) http.Handler {
				return http.HandlerFunc(d.handleFleetOverview)
			},
		},
		{
			pattern:          "/fleet/",
			feature:          license.FeatureFleet,
			forbiddenMessage: fleetFeatureForbidden,
			permission:       PermissionFleetRead,
			handler: func(d *dashboardHandler) http.Handler {
				return http.HandlerFunc(d.handleFleetOverview)
			},
		},
		{
			pattern:          "/workbench",
			feature:          license.FeatureFleet,
			forbiddenMessage: fleetFeatureForbidden,
			permission:       PermissionSignedActionRead,
			handler: func(d *dashboardHandler) http.Handler {
				return http.HandlerFunc(d.handleWorkbench)
			},
		},
		{
			pattern:          "/workbench/",
			feature:          license.FeatureFleet,
			forbiddenMessage: fleetFeatureForbidden,
			permission:       PermissionSignedActionRead,
			handler: func(d *dashboardHandler) http.Handler {
				return http.HandlerFunc(d.handleWorkbench)
			},
		},
		{
			pattern:          "/incident",
			feature:          license.FeatureFleet,
			forbiddenMessage: fleetFeatureForbidden,
			permission:       PermissionIncidentRead,
			handler: func(d *dashboardHandler) http.Handler {
				return http.HandlerFunc(d.handleIncident)
			},
		},
		{
			pattern:          "/incident/",
			feature:          license.FeatureFleet,
			forbiddenMessage: fleetFeatureForbidden,
			permission:       PermissionIncidentRead,
			handler: func(d *dashboardHandler) http.Handler {
				return http.HandlerFunc(d.handleIncident)
			},
		},
	}
}

// AllPermissions returns the complete bounded permission vocabulary: every
// permission referenced by a dashboard route plus the raw-view elevation.
// Derived from the route specs so it cannot drift from what handlers actually
// require; auth adapters use it to prove their mapping covers every permission
// (an unmapped permission fails closed and disables its route).
func AllPermissions() []Permission {
	seen := map[Permission]struct{}{PermissionRawRead: {}}
	all := []Permission{PermissionRawRead}
	for _, spec := range dashboardRouteSpecs() {
		if _, ok := seen[spec.permission]; ok {
			continue
		}
		seen[spec.permission] = struct{}{}
		all = append(all, spec.permission)
	}
	return all
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
		model:               model,
		hasFeature:          opts.HasFeature,
		authorize:           opts.Authorize,
		authorizePermission: opts.AuthorizePermission,
		authorizeRaw:        opts.AuthorizeRaw,
		authorizeFleetScope: opts.AuthorizeFleetScope,
		auditWriter:         opts.AuditWriter,
	}
	for _, spec := range dashboardRouteSpecs() {
		mux.Handle(spec.pattern, d.routeGate(spec, spec.handler(d)))
	}
	return mux
}

type dashboardHandler struct {
	model               *ReadModel
	hasFeature          func(string) bool
	authorize           func(*http.Request) error
	authorizePermission func(*http.Request, Permission) error
	authorizeRaw        func(*http.Request) error
	authorizeFleetScope func(*http.Request, DecisionScope, bool) error
	auditWriter         io.Writer
	auditMu             sync.Mutex
}

type rawAllowedContextKey struct{}

// rawAllowed reports whether this request may see the raw view (destinations
// and full signed payloads). Fail closed: raw is shown only when an authorizer
// is configured and accepts the request.
func (d *dashboardHandler) rawAllowed(r *http.Request) bool {
	if d.authorizeRaw == nil || d.authorizeRaw(r) != nil {
		return false
	}
	if d.authorizePermission != nil {
		return d.authorizePermission(r, PermissionRawRead) == nil
	}
	return true
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
	_, _ = fmt.Fprintf(d.auditWriter, "%s pipelock-dashboard access role=%s method=%s path=%q session=%q session_sha256=%s org_sha256=%s fleet_sha256=%s artifact_sha256=%s remote=%s\n",
		time.Now().UTC().Format(time.RFC3339), role, r.Method, r.URL.Path, sessionDisplay, sessionHash,
		auditHashField(r.URL.Query().Get("org_id")), auditHashField(r.URL.Query().Get("fleet_id")),
		auditHashField(r.URL.Query().Get("artifact_hash")), r.RemoteAddr)
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

func auditHashField(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "-"
	}
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func (d *dashboardHandler) recordDecisionScopeAudit(r *http.Request, raw bool, scope DecisionScope, page any) {
	if d.auditWriter == nil {
		return
	}
	role := "metadata"
	if raw {
		role = "raw"
	}
	var decisionSource, fleetSource, decisionFound, fleetFound, divergence bool
	conflict := "-"
	switch p := page.(type) {
	case WorkbenchPage:
		decisionSource = p.SourceConfigured
		decisionFound = p.HasReplay
		divergence = p.HasReplay && p.Replay.Divergence
		if p.HasReplay && p.Replay.Conflict != "" {
			conflict = p.Replay.Conflict
		}
	case IncidentPage:
		decisionSource = p.DecisionSourceConfigured
		fleetSource = p.FleetSourceConfigured
		decisionFound = p.HasDecision
		fleetFound = p.HasFleet
		divergence = p.HasDecision && p.Decision.Divergence
		if p.HasDecision && p.Decision.Conflict != "" {
			conflict = p.Decision.Conflict
		}
	}
	d.auditMu.Lock()
	defer d.auditMu.Unlock()
	_, _ = fmt.Fprintf(d.auditWriter, "%s pipelock-dashboard scope role=%s method=%s path=%q org_sha256=%s fleet_sha256=%s artifact_sha256=%s decision_source=%t fleet_source=%t decision_found=%t fleet_found=%t divergence=%t conflict=%q remote=%s\n",
		time.Now().UTC().Format(time.RFC3339), role, r.Method, r.URL.Path,
		auditHashField(scope.OrgID), auditHashField(scope.FleetID), auditHashField(scope.ArtifactHash),
		decisionSource, fleetSource, decisionFound, fleetFound, divergence, conflict, r.RemoteAddr)
}

func (d *dashboardHandler) authorizeFleetScopeRequest(w http.ResponseWriter, r *http.Request, scope DecisionScope, sourceConfigured bool, raw bool) bool {
	if !sourceConfigured {
		return true
	}
	if d.authorizeFleetScope == nil {
		http.Error(w, "fleet scope authorization required", http.StatusForbidden)
		return false
	}
	if err := d.authorizeFleetScope(r, normalizeDecisionScope(scope), raw); err != nil {
		http.Error(w, "fleet scope not authorized", http.StatusForbidden)
		return false
	}
	return true
}

func (d *dashboardHandler) routeGate(spec routeSpec, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", contentSecurityPolicy)
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if !knownPermission(spec.permission) {
			w.Header().Set("Content-Type", contentTypeText)
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte("forbidden\n"))
			return
		}
		if d.hasFeature == nil || !d.hasFeature(spec.feature) {
			w.Header().Set("Content-Type", contentTypeText)
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(spec.forbiddenMessage))
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
		if d.authorizePermission != nil {
			if err := d.authorizePermission(r, spec.permission); err != nil {
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

func knownPermission(permission Permission) bool {
	for _, known := range AllPermissions() {
		if permission == known {
			return true
		}
	}
	return false
}

func (d *dashboardHandler) handleCompliance(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != CompliancePath {
		http.NotFound(w, r)
		return
	}
	if !requireGet(w, r) {
		return
	}
	orgID := r.URL.Query().Get("org_id")
	fleetID := r.URL.Query().Get("fleet_id")
	_, sourceConfigured := d.model.complianceFleetSource()
	if !d.authorizeFleetScopeRequest(w, r, DecisionScope{OrgID: orgID, FleetID: fleetID}, sourceConfigured, false) {
		return
	}
	page, err := d.model.Compliance(r.Context(), orgID, fleetID)
	if err != nil {
		if errors.Is(err, errInvalidFleetScope) {
			http.Error(w, "invalid fleet scope", http.StatusBadRequest)
			return
		}
		http.Error(w, "could not build compliance read model", http.StatusInternalServerError)
		return
	}
	var buf bytes.Buffer
	if err := complianceTemplate.Execute(&buf, page); err != nil {
		http.Error(w, "could not render compliance console", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", contentTypeHTML)
	_, _ = w.Write(buf.Bytes())
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

func (d *dashboardHandler) handleFleetOverview(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/fleet" {
		http.NotFound(w, r)
		return
	}
	if !requireGet(w, r) {
		return
	}
	q := r.URL.Query()
	if err := validateFleetScope(q.Get("org_id"), q.Get("fleet_id"), d.model.fleetSource != nil); err != nil {
		http.Error(w, "invalid fleet scope", http.StatusBadRequest)
		return
	}
	if !d.authorizeFleetScopeRequest(w, r, DecisionScope{OrgID: q.Get("org_id"), FleetID: q.Get("fleet_id")}, d.model.fleetSource != nil, rawAllowedFromContext(r)) {
		return
	}
	overview, err := d.model.FleetOverview(r.Context(), q.Get("org_id"), q.Get("fleet_id"), rawAllowedFromContext(r))
	if err != nil {
		if errors.Is(err, errInvalidFleetScope) {
			http.Error(w, "invalid fleet scope", http.StatusBadRequest)
			return
		}
		http.Error(w, "could not read fleet overview", http.StatusInternalServerError)
		return
	}
	var buf bytes.Buffer
	if err := fleetoverviewTemplate.Execute(&buf, overview); err != nil {
		http.Error(w, "could not render fleet overview", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", contentTypeHTML)
	_, _ = w.Write(buf.Bytes())
}

type decisionScopePageOptions struct {
	path             string
	tmpl             *template.Template
	buildErr         string
	renderErr        string
	sourceConfigured func(*ReadModel) bool
	build            func(context.Context, DecisionScope, bool) (any, error)
}

func (d *dashboardHandler) serveDecisionScopePage(w http.ResponseWriter, r *http.Request, opts decisionScopePageOptions) {
	if r.URL.Path != opts.path {
		http.NotFound(w, r)
		return
	}
	if !requireGet(w, r) {
		return
	}
	scope := decisionScopeFromRequest(r)
	if err := validateDecisionScope(scope); err != nil {
		http.Error(w, "invalid decision scope", http.StatusBadRequest)
		return
	}
	raw := rawAllowedFromContext(r)
	sourceConfigured := scope.ArtifactHash != "" && opts.sourceConfigured != nil && opts.sourceConfigured(d.model)
	if !d.authorizeFleetScopeRequest(w, r, scope, sourceConfigured, raw) {
		return
	}
	page, err := opts.build(r.Context(), scope, raw)
	if err != nil {
		http.Error(w, opts.buildErr, http.StatusInternalServerError)
		return
	}
	if scope.ArtifactHash != "" {
		d.recordDecisionScopeAudit(r, raw, scope, page)
	}
	var buf bytes.Buffer
	if err := opts.tmpl.Execute(&buf, page); err != nil {
		http.Error(w, opts.renderErr, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", contentTypeHTML)
	_, _ = w.Write(buf.Bytes())
}

// handleWorkbench serves the read-only Signed Action Workbench. It is GET-only
// and reaches no write path: it renders static prepare guidance and, when a
// conductor decision source is wired and an artifact hash is supplied, the
// read-only replay of that past decision.
func (d *dashboardHandler) handleWorkbench(w http.ResponseWriter, r *http.Request) {
	d.serveDecisionScopePage(w, r, decisionScopePageOptions{
		path:      "/workbench",
		tmpl:      workbenchTemplate,
		buildErr:  "could not build workbench view",
		renderErr: "could not render workbench",
		sourceConfigured: func(m *ReadModel) bool {
			return m.conductorSource != nil
		},
		build: func(ctx context.Context, scope DecisionScope, raw bool) (any, error) {
			return d.model.Workbench(ctx, scope, raw)
		},
	})
}

// handleIncident serves the read-only Incident Cockpit. It is GET-only and
// reaches no write path: it correlates a conductor decision replay with the
// bounded fleet applied-state summary.
func (d *dashboardHandler) handleIncident(w http.ResponseWriter, r *http.Request) {
	d.serveDecisionScopePage(w, r, decisionScopePageOptions{
		path:      "/incident",
		tmpl:      incidentTemplate,
		buildErr:  "could not build incident view",
		renderErr: "could not render incident view",
		sourceConfigured: func(m *ReadModel) bool {
			return m.conductorSource != nil || m.fleetSource != nil
		},
		build: func(ctx context.Context, scope DecisionScope, raw bool) (any, error) {
			return d.model.Incident(ctx, scope, raw)
		},
	})
}

func decisionScopeFromRequest(r *http.Request) DecisionScope {
	q := r.URL.Query()
	return DecisionScope{
		OrgID:        q.Get("org_id"),
		FleetID:      q.Get("fleet_id"),
		ArtifactHash: q.Get("artifact_hash"),
	}
}

func (d *dashboardHandler) handleBudgets(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/budgets" {
		http.NotFound(w, r)
		return
	}
	if !requireGet(w, r) {
		return
	}
	overview, err := d.model.Budgets(r.Context(), rawAllowedFromContext(r))
	if err != nil {
		http.Error(w, "could not read agent budgets", http.StatusInternalServerError)
		return
	}
	var buf bytes.Buffer
	if err := budgetsTemplate.Execute(&buf, overview); err != nil {
		http.Error(w, "could not render budgets", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", contentTypeHTML)
	_, _ = w.Write(buf.Bytes())
}

func (d *dashboardHandler) handleTrustKeys(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/trust-keys" {
		http.NotFound(w, r)
		return
	}
	if !requireGet(w, r) {
		return
	}
	page, err := d.model.TrustKeys()
	if err != nil {
		http.Error(w, "could not audit trust and keys", http.StatusInternalServerError)
		return
	}
	var buf bytes.Buffer
	if err := trustKeysTemplate.Execute(&buf, page); err != nil {
		http.Error(w, "could not render trust and keys", http.StatusInternalServerError)
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
