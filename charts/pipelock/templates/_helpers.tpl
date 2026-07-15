{{/*
Expand the name of the chart.
*/}}
{{- define "pipelock.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "pipelock.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "pipelock.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels.
*/}}
{{- define "pipelock.labels" -}}
helm.sh/chart: {{ include "pipelock.chart" . }}
{{ include "pipelock.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels.
*/}}
{{- define "pipelock.selectorLabels" -}}
app.kubernetes.io/name: {{ include "pipelock.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use.
*/}}
{{- define "pipelock.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "pipelock.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Return the chart deployment mode.
*/}}
{{- define "pipelock.mode" -}}
{{- default "proxy" .Values.mode -}}
{{- end }}

{{/*
Build the container image reference. A digest pins by manifest hash
(repository@sha256:...); otherwise the image is referenced by tag
(repository:tag), with the tag falling through to .Chart.AppVersion when empty.
A digest and a tag are never combined, so the ":@sha256:" malformed reference
cannot be rendered. Fails loudly if image.tag itself contains a digest, the
misconfiguration that produced ":@sha256:" before image.digest existed.
*/}}
{{- define "pipelock.image" -}}
{{- $repository := required "image.repository is required" .Values.image.repository -}}
{{- $digest := default "" .Values.image.digest -}}
{{- $tag := default "" .Values.image.tag -}}
{{- if or (hasPrefix "sha256:" $tag) (contains "@" $tag) -}}
{{- fail "image.tag must not contain a digest; set the sha256 string in image.digest instead" -}}
{{- end -}}
{{- if $digest -}}
{{- if not (regexMatch "^sha256:[a-f0-9]{64}$" $digest) -}}
{{- fail "image.digest must be a sha256 digest like sha256:<64 lowercase hex chars>" -}}
{{- end -}}
{{- printf "%s@%s" $repository $digest -}}
{{- else -}}
{{- printf "%s:%s" $repository (default .Chart.AppVersion $tag) -}}
{{- end -}}
{{- end }}

{{/*
Validate mode and security-critical enterprise chart requirements.
*/}}
{{- define "pipelock.validate" -}}
{{- $mode := include "pipelock.mode" . -}}
{{- $ingress := default list .Values.networkPolicy.ingress -}}
{{- $egress := default list .Values.networkPolicy.egress -}}
{{- if not (has $mode (list "proxy" "conductor" "fleetSink")) -}}
{{- fail "mode must be one of proxy, conductor, or fleetSink" -}}
{{- end -}}
{{- if and (ne $mode "proxy") (not .Values.networkPolicy.enabled) -}}
{{- fail "networkPolicy.enabled=true is required when mode is conductor or fleetSink" -}}
{{- end -}}
{{- if and (ne $mode "proxy") (ne (default "dev" .Values.networkPolicy.preset) "airgapped") (or (eq (len $ingress) 0) (eq (len $egress) 0)) -}}
{{- fail "enterprise modes require explicit networkPolicy.ingress and networkPolicy.egress rules unless preset=airgapped" -}}
{{- end -}}
{{- if and (eq $mode "fleetSink") .Values.podMonitor.enabled -}}
{{- fail "podMonitor.enabled is not supported in fleetSink mode because the standalone sink does not expose a Prometheus metrics endpoint" -}}
{{- end -}}
{{- if and .Values.mcp.enabled .Values.mcp.upstream -}}
{{- $mcpPortText := regexFind "[0-9]+$" (default "" .Values.mcp.listen) -}}
{{- $mcpHost := regexReplaceAll ":[0-9]+$" (default "" .Values.mcp.listen) "" -}}
{{- $ipv4Octet := "(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])" -}}
{{- $mcpLoopback := or (regexMatch (printf "^127\\.%s\\.%s\\.%s$" $ipv4Octet $ipv4Octet $ipv4Octet) $mcpHost) (eq $mcpHost "[::1]") -}}
{{- if or (eq $mcpPortText "") (ne (int $mcpPortText) (int .Values.service.mcpPort)) -}}
{{- fail "mcp.listen must end with the same port configured by service.mcpPort so the Service and container listener cannot diverge" -}}
{{- end -}}
{{- if and .Values.mcp.authTokenFile .Values.mcp.allowUnauthenticated -}}
{{- fail "set only one of mcp.authTokenFile or mcp.allowUnauthenticated, not both" -}}
{{- end -}}
{{- if and (not $mcpLoopback) (not .Values.mcp.authTokenFile) (not .Values.mcp.allowUnauthenticated) -}}
{{- fail "mcp.listen is non-loopback and reachable through the Service: set mcp.authTokenFile to a mounted bearer-token file, or set mcp.allowUnauthenticated=true (only sound with networkPolicy.enabled=true)" -}}
{{- end -}}
{{- if and .Values.mcp.allowUnauthenticated (not .Values.networkPolicy.enabled) -}}
{{- fail "mcp.allowUnauthenticated=true requires networkPolicy.enabled=true; without it the MCP listener accepts unauthenticated calls from any pod in the cluster" -}}
{{- end -}}
{{- end -}}
{{- if and (eq $mode "conductor") .Values.conductor.persistence.enabled (gt (int .Values.conductor.replicaCount) 1) (has "ReadWriteOnce" (default list .Values.conductor.persistence.accessModes)) -}}
{{- fail "conductor.replicaCount must be 1 when conductor.persistence.accessModes includes ReadWriteOnce" -}}
{{- end -}}
{{- if and (eq $mode "fleetSink") .Values.fleetSink.persistence.enabled (gt (int .Values.fleetSink.replicaCount) 1) (has "ReadWriteOnce" (default list .Values.fleetSink.persistence.accessModes)) -}}
{{- fail "fleetSink.replicaCount must be 1 when fleetSink.persistence.accessModes includes ReadWriteOnce" -}}
{{- end -}}
{{- if .Values.conductorFollower.enabled -}}
{{- $_ := required "conductorFollower.conductorURL is required when conductorFollower.enabled=true" .Values.conductorFollower.conductorURL -}}
{{- $_ := required "conductorFollower.serverCASecretRef.name is required when conductorFollower.enabled=true" .Values.conductorFollower.serverCASecretRef.name -}}
{{- $_ := required "conductorFollower.clientSecretRef.name is required when conductorFollower.enabled=true" .Values.conductorFollower.clientSecretRef.name -}}
{{- $_ := required "conductorFollower.trustRosterSecretRef.name is required when conductorFollower.enabled=true" .Values.conductorFollower.trustRosterSecretRef.name -}}
{{- end -}}
{{- end }}

{{/*
PVC names.
*/}}
{{- define "pipelock.conductorStorageName" -}}
{{- printf "%s-conductor-storage" (include "pipelock.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end }}

{{- define "pipelock.fleetSinkStorageName" -}}
{{- printf "%s-fleet-sink-storage" (include "pipelock.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end }}

{{- define "pipelock.followerBundleCacheName" -}}
{{- printf "%s-follower-bundles" (include "pipelock.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end }}

{{- define "pipelock.followerAuditQueueName" -}}
{{- printf "%s-follower-audit-queue" (include "pipelock.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end }}
