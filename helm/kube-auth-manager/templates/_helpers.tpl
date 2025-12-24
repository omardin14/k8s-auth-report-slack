{{/*
Expand the name of the chart.
*/}}
{{- define "kube-auth-manager.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "kube-auth-manager.fullname" -}}
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
{{- define "kube-auth-manager.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "kube-auth-manager.labels" -}}
helm.sh/chart: {{ include "kube-auth-manager.chart" . }}
{{ include "kube-auth-manager.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "kube-auth-manager.selectorLabels" -}}
app.kubernetes.io/name: {{ include "kube-auth-manager.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "kube-auth-manager.serviceAccountName" -}}
{{- if .Values.rbac.serviceAccount.name }}
{{- .Values.rbac.serviceAccount.name }}
{{- else }}
{{- include "kube-auth-manager.fullname" . }}
{{- end }}
{{- end }}

{{/*
Create the name of the cluster role
*/}}
{{- define "kube-auth-manager.clusterRoleName" -}}
{{- if .Values.rbac.clusterRole.name }}
{{- .Values.rbac.clusterRole.name }}
{{- else }}
{{- include "kube-auth-manager.fullname" . }}
{{- end }}
{{- end }}

{{/*
Create the name of the cluster role binding
*/}}
{{- define "kube-auth-manager.clusterRoleBindingName" -}}
{{- if .Values.rbac.clusterRoleBinding.name }}
{{- .Values.rbac.clusterRoleBinding.name }}
{{- else }}
{{- include "kube-auth-manager.fullname" . }}
{{- end }}
{{- end }}

{{/*
Create the name of the secret
*/}}
{{- define "kube-auth-manager.secretName" -}}
{{- if kindIs "string" .Values.slack.token }}
{{- printf "%s-slack-credentials" (include "kube-auth-manager.fullname" .) }}
{{- else }}
slack-credentials
{{- end }}
{{- end }}

{{/*
Get the namespace
*/}}
{{- define "kube-auth-manager.namespace" -}}
{{- .Values.namespace.name }}
{{- end }}


