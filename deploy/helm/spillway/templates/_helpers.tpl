{{/*
Expand the name of the chart.
*/}}
{{- define "spillway.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "spillway.fullname" -}}
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
{{- define "spillway.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels.
*/}}
{{- define "spillway.labels" -}}
helm.sh/chart: {{ include "spillway.chart" . }}
{{ include "spillway.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels.
*/}}
{{- define "spillway.selectorLabels" -}}
app.kubernetes.io/name: {{ include "spillway.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use.
*/}}
{{- define "spillway.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "spillway.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Resolve the container image.
*/}}
{{- define "spillway.image" -}}
{{- $tag := default .Chart.AppVersion .Values.image.tag -}}
{{- printf "%s:%s" .Values.image.repository $tag -}}
{{- end }}

{{/*
Resolve Redis address.
When the bundled Redis subchart is enabled, use the subchart's master service.
Otherwise, require externalRedis.addr.
*/}}
{{- define "spillway.redisAddr" -}}
{{- if .Values.redis.enabled -}}
{{- printf "%s-redis-master:6379" .Release.Name -}}
{{- else -}}
{{- required "externalRedis.addr is required when redis.enabled is false" .Values.externalRedis.addr -}}
{{- end -}}
{{- end }}

{{/*
Resolve the AWS credentials secret name.
*/}}
{{- define "spillway.awsSecretName" -}}
{{- if .Values.secrets.aws.existingSecret -}}
{{- .Values.secrets.aws.existingSecret -}}
{{- else -}}
{{- printf "%s-aws" (include "spillway.fullname" .) -}}
{{- end -}}
{{- end }}

{{/*
Resolve the Tailscale secret name.
*/}}
{{- define "spillway.tsSecretName" -}}
{{- if .Values.secrets.tailscale.existingSecret -}}
{{- .Values.secrets.tailscale.existingSecret -}}
{{- else -}}
{{- printf "%s-tailscale" (include "spillway.fullname" .) -}}
{{- end -}}
{{- end }}
