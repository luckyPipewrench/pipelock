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
