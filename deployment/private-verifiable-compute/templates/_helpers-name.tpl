{{- /*
    These helpers encapsulates logic on how we name resources. They also enable
    parent charts to reference these dynamic resource names.
*/}}

{{- define "pvc.name.dash" -}}
    {{- if (include "pvc.name" .) }}
        {{- include "pvc.name" . }}-
    {{- end }}
{{- end }}


{{- /*
    Namespaced resources
*/}}

{{- /* privacy-gateway Deployment */}}
{{- define "pvc.privacy-gateway.name" -}}
    {{- include "pvc.name.dash" . }}privacy-gateway
{{- end }}

{{- define "pvc.relay.name" -}}
    {{- include "pvc.name.dash" . }}relay
{{- end }}

{{- define "pvc.identity-server.name" -}}
    {{- include "pvc.name.dash" . }}identity-server
{{- end }}

{{- define "pvc.tee-llm.name" -}}
    {{- include "pvc.name.dash" . }}tee-llm
{{- end }}

{{- define "pvc.tee-embedding.name" -}}
    {{- include "pvc.name.dash" . }}tee-embedding
{{- end }}

{{- define "pvc.tee-server.name" -}}
    {{- include "pvc.name.dash" . }}tee-server
{{- end }}

{{- define "pvc.client.name" -}}
    {{- include "pvc.name.dash" . }}client
{{- end }}