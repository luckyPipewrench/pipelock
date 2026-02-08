package proxy

import "net/http"

// AgentHeader is the HTTP header used to identify the calling agent.
const AgentHeader = "X-Pipelock-Agent"

// ExtractAgent reads the agent name from the request. It checks the
// X-Pipelock-Agent header first, then the "agent" query parameter,
// falling back to "anonymous".
func ExtractAgent(r *http.Request) string {
	if agent := r.Header.Get(AgentHeader); agent != "" {
		return agent
	}
	if agent := r.URL.Query().Get("agent"); agent != "" {
		return agent
	}
	return "anonymous"
}
