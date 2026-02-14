{{/*
Expand the name of the chart.
*/}}
{{- define "private-verifiable-compute.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "pvc.name" -}}
    {{- include "private-verifiable-compute.name" . }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "private-verifiable-compute.fullname" -}}
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
{{- define "private-verifiable-compute.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "private-verifiable-compute.labels" -}}
helm.sh/chart: {{ include "private-verifiable-compute.chart" . }}
{{ include "private-verifiable-compute.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Privacy Gateway labels
*/}}
{{- define "pvc.privacy-gateway.labels" -}}
helm.sh/chart: {{ include "private-verifiable-compute.chart" . }}
{{ include "pvc.privacy-gateway.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Relay labels
*/}}
{{- define "pvc.relay.labels" -}}
helm.sh/chart: {{ include "private-verifiable-compute.chart" . }}
{{ include "pvc.relay.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Identity Server labels
*/}}
{{- define "pvc.identity-server.labels" -}}
helm.sh/chart: {{ include "private-verifiable-compute.chart" . }}
{{ include "pvc.identity-server.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
TEE LLM labels
*/}}
{{- define "pvc.tee-llm.labels" -}}
helm.sh/chart: {{ include "private-verifiable-compute.chart" . }}
{{ include "pvc.tee-llm.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
TEE Embedding labels
*/}}
{{- define "pvc.tee-embedding.labels" -}}
helm.sh/chart: {{ include "private-verifiable-compute.chart" . }}
{{ include "pvc.tee-embedding.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
TEE Server labels
*/}}
{{- define "pvc.tee-server.labels" -}}
helm.sh/chart: {{ include "private-verifiable-compute.chart" . }}
{{ include "pvc.tee-server.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
TEE Client labels
*/}}
{{- define "pvc.client.labels" -}}
helm.sh/chart: {{ include "private-verifiable-compute.chart" . }}
{{ include "pvc.client.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "private-verifiable-compute.selectorLabels" -}}
app.kubernetes.io/name: {{ include "private-verifiable-compute.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Privacy Gateway Selector labels
*/}}
{{- define "pvc.privacy-gateway.selectorLabels" -}}
app.kubernetes.io/name: {{ include "pvc.privacy-gateway.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Relay Selector labels
*/}}
{{- define "pvc.relay.selectorLabels" -}}
app.kubernetes.io/name: {{ include "pvc.relay.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Identity Server Selector labels
*/}}
{{- define "pvc.identity-server.selectorLabels" -}}
app.kubernetes.io/name: {{ include "pvc.identity-server.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
TEE LLM labels
*/}}
{{- define "pvc.tee-llm.selectorLabels" -}}
app.kubernetes.io/name: {{ include "pvc.tee-llm.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
TEE Embedding labels
*/}}
{{- define "pvc.tee-embedding.selectorLabels" -}}
app.kubernetes.io/name: {{ include "pvc.tee-embedding.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
TEE Server labels
*/}}
{{- define "pvc.tee-server.selectorLabels" -}}
app.kubernetes.io/name: {{ include "pvc.tee-server.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Client labels
*/}}
{{- define "pvc.client.selectorLabels" -}}
app.kubernetes.io/name: {{ include "pvc.client.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}


{{/*
Create the name of the service account to use
*/}}
{{- define "private-verifiable-compute.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "private-verifiable-compute.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}


{{/*
Create the name of the service account to use
*/}}
{{- define "pvc.privacy-gateway.serviceAccountName" -}}
{{- default "default" .Values.privacyGateway.serviceAccount.name }}
{{- end }}

{{- define "pvc.relay.serviceAccountName" -}}
{{- default "default" .Values.relay.serviceAccount.name }}
{{- end }}

{{- define "pvc.identity-server.serviceAccountName" -}}
{{- default "default" .Values.identityServer.serviceAccount.name }}
{{- end }}

{{- define "pvc.tee-server.serviceAccountName" -}}
{{- default "default" .Values.teeLlm.serviceAccount.name }}
{{- end }}

{{- define "pvc.client.serviceAccountName" -}}
{{- default "default" .Values.client.serviceAccount.name }}
{{- end }}

{{- define "pvc.url" -}}
{{- $scheme := default "http" .scheme -}}
{{- $host := required "host is required" .host -}}
{{- $port := required "port is required" .port -}}
{{- $path := default "" .path -}}
{{- printf "%s://%s:%v%s" $scheme $host $port $path -}}
{{- end -}}

{{/*
URL Scheme
*/}}
{{- define "pvc.gateway.url" -}}
{{ include "pvc.url" (dict "scheme" (default "http" .Values.privacyGateway.urlScheme) "host" (include "pvc.privacy-gateway.name" .) "port" .Values.privacyGateway.service.port) }}
{{- end -}}

{{- define "pvc.gateway.url.target" -}}
{{ include "pvc.url" (dict "scheme" (default "http" .Values.privacyGateway.urlScheme) "host" (include "pvc.privacy-gateway.name" .) "port" .Values.privacyGateway.service.port "path" "/gateway") }}
{{- end -}}

{{- define "pvc.identity.url" -}}
{{ include "pvc.url" (dict "scheme" (default "http" .Values.identityServer.urlScheme) "host" (include "pvc.identity-server.name" .) "port" .Values.identityServer.service.port) }}
{{- end -}}

{{- define "pvc.relay.url" -}}
{{ include "pvc.url" (dict "scheme" (default "http" .Values.relay.urlScheme) "host" (include "pvc.relay.name" .) "port" .Values.relay.service.port) }}
{{- end -}}

{{- define "pvc.tee-llm.url" -}}
{{ include "pvc.url" (dict "scheme" (default "http" .Values.teeLlm.urlScheme) "host" (include "pvc.tee-llm.name" .) "port" .Values.teeLlm.llmPort) }}
{{- end -}}

{{- define "pvc.tee-embedding.url" -}}
{{ include "pvc.url" (dict "scheme" (default "http" .Values.teeLlm.urlScheme) "host" (include "pvc.tee-embedding.name" .) "port" .Values.teeLlm.embeddingPort) }}
{{- end -}}

{{- define "pvc.tee-server.url" -}}
{{ include "pvc.url" (dict "scheme" (default "http" .Values.teeLlm.urlScheme) "host" (include "pvc.tee-server.name" .) "port" .Values.teeLlm.service.port) }}
{{- end -}}

{{- define "pvc.tee-embedding.url" -}}
{{ include "pvc.url" (dict "scheme" (default "http" .Values.teeLlm.urlScheme) "host" (include "pvc.tee-embedding.name" .) "port" .Values.teeLlm.embeddingPort) }}
{{- end -}}

{{- define "pvc.target.url" -}}
{{ include "pvc.tee-server.name" .}}:{{ .Values.teeLlm.service.port }}
{{- end -}}
