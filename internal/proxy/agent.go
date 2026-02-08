package proxy

import (
	"net/http"
	"regexp"
)

// AgentHeader is the HTTP header used to identify the calling agent.
const AgentHeader = "X-Pipelock-Agent"

// maxAgentNameLen limits agent names to prevent log bloat.
const maxAgentNameLen = 64

// agentNameRe matches characters NOT allowed in agent names.
var agentNameRe = regexp.MustCompile(`[^a-zA-Z0-9._-]`)

// ExtractAgent reads the agent name from the request. It checks the
// X-Pipelock-Agent header first, then the "agent" query parameter,
// falling back to "anonymous". Names are sanitized to prevent log injection.
func ExtractAgent(r *http.Request) string {
	agent := r.Header.Get(AgentHeader)
	if agent == "" {
		agent = r.URL.Query().Get("agent")
	}
	if agent == "" {
		return "anonymous" //nolint:goconst // clarity over deduplication
	}
	agent = agentNameRe.ReplaceAllString(agent, "_")
	if len(agent) > maxAgentNameLen {
		agent = agent[:maxAgentNameLen]
	}
	if agent == "" {
		return "anonymous" //nolint:goconst // clarity over deduplication
	}
	return agent
}
