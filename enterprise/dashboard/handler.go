//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package dashboard

import (
	"bytes"
	"embed"
	"html/template"
	"net/http"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/license"
)

const (
	contentSecurityPolicy = "default-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'"
	contentTypeHTML       = "text/html; charset=utf-8"
	contentTypeText       = "text/plain; charset=utf-8"
)

//go:embed evidence.tmpl.html
var templateFS embed.FS

var evidenceTemplate = template.Must(template.ParseFS(templateFS, "evidence.tmpl.html"))

type pageData struct {
	Sessions        []SessionSummary
	SelectedSession string
	Evidence        SessionEvidence
	HasEvidence     bool
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
		model:      model,
		hasFeature: opts.HasFeature,
		authorize:  opts.Authorize,
	}
	mux.Handle("/", d.gate(http.HandlerFunc(d.handleIndex)))
	mux.Handle("/session/", d.gate(http.HandlerFunc(d.handleSession)))
	return mux
}

type dashboardHandler struct {
	model      *ReadModel
	hasFeature func(string) bool
	authorize  func(*http.Request) error
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
		next.ServeHTTP(w, r)
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
	d.render(w, sessions, selected)
}

func (d *dashboardHandler) handleSession(w http.ResponseWriter, r *http.Request) {
	if !requireGet(w, r) {
		return
	}

	selected := strings.TrimPrefix(r.URL.Path, "/session/")
	if selected == "" || strings.Contains(selected, "/") {
		http.NotFound(w, r)
		return
	}
	sessions, err := d.model.Sessions()
	if err != nil {
		http.Error(w, "could not read evidence sessions", http.StatusInternalServerError)
		return
	}
	d.render(w, sessions, selected)
}

func requireGet(w http.ResponseWriter, r *http.Request) bool {
	if r.Method == http.MethodGet {
		return true
	}
	w.Header().Set("Allow", http.MethodGet)
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	return false
}

func (d *dashboardHandler) render(w http.ResponseWriter, sessions []SessionSummary, selected string) {
	data := pageData{
		Sessions:        sessions,
		SelectedSession: selected,
	}
	if selected != "" {
		evidence, err := d.model.Session(selected)
		if err != nil {
			http.Error(w, "could not read selected evidence", http.StatusInternalServerError)
			return
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
