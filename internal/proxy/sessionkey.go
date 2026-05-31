package proxy

// sessionKeyFor builds the per-session key used for adaptive-enforcement
// tracking and audit correlation. A named agent is namespaced ahead of its
// client IP so that two agents sharing one client IP are tracked as distinct
// sessions. An unnamed or anonymous agent keys on the client IP alone.
//
// This is the single source of truth for session-key construction. Every
// transport (fetch, forward, CONNECT, WebSocket, TLS intercept) must build
// the key the same way, otherwise adaptive escalation and de-escalation would
// track different keys for the same logical session.
func sessionKeyFor(agent, clientIP string) string {
	if agent == "" || agent == agentAnonymous {
		return clientIP
	}
	return agent + "|" + clientIP
}
