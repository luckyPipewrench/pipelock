package killswitch

import (
	"bytes"
	"crypto/subtle"
	"html/template"
	"net/http"
)

// dashboardTmpl is parsed once at NewAPIHandler init time. Since the template
// is a compile-time constant, any parse error is a programming bug that panics
// at startup, consistent with Scanner.New() and other init-time validation.
var dashboardTmpl *template.Template

func initDashboardTemplate() {
	dashboardTmpl = template.Must(template.New("dashboard").Parse(dashboardHTML))
}

type dashboardData struct {
	Active  bool
	Sources map[string]bool
	Message string
	Flash   string // success/error message after toggle
	Token   string // echoed back for form POST submissions
}

// HandleDashboard serves an HTML dashboard for kill switch state and control.
// GET /dashboard renders the current state. POST /dashboard toggles via API source.
// Both require Bearer token auth (same token as HandleToggle/HandleStatus).
// POST is rate-limited using the same window as HandleToggle.
func (h *APIHandler) HandleDashboard(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodGet+", "+http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Limit request body before any form parsing (matches HandleToggle).
	// Prevents memory exhaustion from unauthenticated oversized POST bodies.
	r.Body = http.MaxBytesReader(w, r.Body, 1024)

	// Auth check (same as HandleToggle/HandleStatus).
	rt := h.ctrl.cfg.Load()
	if rt.apiToken == "" {
		http.Error(w, "kill switch API not configured (no api_token)", http.StatusServiceUnavailable)
		return
	}

	token := extractBearerToken(r)
	if token == "" && r.Method == http.MethodPost {
		// Form token only for POST (browser form submission).
		// GET must use Bearer header to avoid token leaking into URL query strings,
		// browser history, server access logs, and referrer headers.
		token = r.FormValue("token")
	}
	if token == "" || subtle.ConstantTimeCompare([]byte(token), []byte(rt.apiToken)) != 1 {
		w.Header().Set("WWW-Authenticate", `Bearer realm="pipelock"`)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var flash string

	if r.Method == http.MethodPost {
		// Rate limit (same as HandleToggle)
		if !h.checkRateLimit() {
			w.Header().Set("Retry-After", "60")
			http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
			return
		}

		action := r.FormValue("action")
		switch action {
		case "activate":
			h.ctrl.SetAPI(true)
			flash = "Kill switch activated via API source."
		case "deactivate":
			h.ctrl.SetAPI(false)
			flash = "Kill switch API source deactivated."
		default:
			flash = "Unknown action."
		}
	}

	sources := h.ctrl.Sources()
	anyActive := false
	for _, v := range sources {
		if v {
			anyActive = true
			break
		}
	}

	data := dashboardData{
		Active:  anyActive,
		Sources: sources,
		Message: rt.message,
		Flash:   flash,
		Token:   token,
	}

	// Render to buffer first so that template errors produce a clean 500
	// instead of appending error text to a partial 200 response.
	var buf bytes.Buffer
	if err := dashboardTmpl.Execute(&buf, data); err != nil {
		http.Error(w, "template error", http.StatusInternalServerError)
		return
	}

	// Security headers: prevent caching (token in body), clickjacking, and content sniffing.
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write(buf.Bytes())
}

const dashboardHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Pipelock Kill Switch</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, monospace;
         background: #1a1a2e; color: #e0e0e0; padding: 2rem; }
  .container { max-width: 600px; margin: 0 auto; }
  h1 { font-size: 1.5rem; margin-bottom: 1.5rem; color: #fff; }
  .status-banner { padding: 1rem; border-radius: 8px; margin-bottom: 1.5rem;
                   font-weight: bold; font-size: 1.2rem; text-align: center; }
  .status-active { background: #c0392b; color: #fff; }
  .status-inactive { background: #27ae60; color: #fff; }
  .sources { margin-bottom: 1.5rem; }
  .source { display: flex; justify-content: space-between; align-items: center;
            padding: 0.75rem 1rem; border-bottom: 1px solid #2a2a4a; }
  .source:last-child { border-bottom: none; }
  .source-name { font-weight: 500; }
  .dot { display: inline-block; width: 12px; height: 12px; border-radius: 50%; }
  .dot-active { background: #e74c3c; }
  .dot-inactive { background: #2ecc71; }
  .flash { padding: 0.75rem 1rem; border-radius: 4px; margin-bottom: 1rem;
           background: #2a2a4a; border-left: 4px solid #3498db; }
  .controls { display: flex; gap: 0.5rem; }
  .btn { padding: 0.6rem 1.2rem; border: none; border-radius: 4px; cursor: pointer;
         font-size: 0.9rem; font-weight: 600; }
  .btn-danger { background: #c0392b; color: #fff; }
  .btn-danger:hover { background: #e74c3c; }
  .btn-safe { background: #27ae60; color: #fff; }
  .btn-safe:hover { background: #2ecc71; }
  .message { margin-top: 1rem; padding: 0.75rem; background: #2a2a4a; border-radius: 4px;
             font-size: 0.85rem; color: #bbb; }
  .footer { margin-top: 2rem; font-size: 0.75rem; color: #666; }
  input[type="hidden"] { display: none; }
</style>
</head>
<body>
<div class="container">
  <h1>Pipelock Kill Switch</h1>

  {{if .Flash}}<div class="flash">{{.Flash}}</div>{{end}}

  <div class="status-banner {{if .Active}}status-active{{else}}status-inactive{{end}}">
    {{if .Active}}KILL SWITCH ACTIVE{{else}}KILL SWITCH INACTIVE{{end}}
  </div>

  <div class="sources">
    {{range $name, $active := .Sources}}
    <div class="source">
      <span class="source-name">{{$name}}</span>
      <span class="dot {{if $active}}dot-active{{else}}dot-inactive{{end}}"></span>
    </div>
    {{end}}
  </div>

  {{if .Message}}<div class="message">Message: {{.Message}}</div>{{end}}

  <div class="controls">
    <form method="POST" action="/dashboard">
      <input type="hidden" name="token" value="{{.Token}}">
      <input type="hidden" name="action" value="activate">
      <button type="submit" class="btn btn-danger">Activate</button>
    </form>
    <form method="POST" action="/dashboard">
      <input type="hidden" name="token" value="{{.Token}}">
      <input type="hidden" name="action" value="deactivate">
      <button type="submit" class="btn btn-safe">Deactivate</button>
    </form>
  </div>

  <div class="footer">Pipelock Agent Firewall. API source only. Config, signal, and sentinel sources are controlled externally.</div>
</div>
</body>
</html>`
