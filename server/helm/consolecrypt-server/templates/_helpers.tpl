{{/*
Chart name.
*/}}
{{- define "consolecrypt-server.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Fully qualified app name (max 63 chars, DNS label).
*/}}
{{- define "consolecrypt-server.fullname" -}}
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

{{- define "consolecrypt-server.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels (without component).
*/}}
{{- define "consolecrypt-server.labels" -}}
helm.sh/chart: {{ include "consolecrypt-server.chart" . }}
app.kubernetes.io/name: {{ include "consolecrypt-server.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Values.image.tag | default .Chart.AppVersion | trunc 63 | trimSuffix "-" | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: consolecrypt
{{- end }}

{{/*
Selector labels of the server pods.
*/}}
{{- define "consolecrypt-server.selectorLabels" -}}
app.kubernetes.io/name: {{ include "consolecrypt-server.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: server
{{- end }}

{{- define "consolecrypt-server.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "consolecrypt-server.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{- define "consolecrypt-server.image" -}}
{{- if .Values.image.digest }}
{{- printf "%s@%s" .Values.image.repository .Values.image.digest }}
{{- else }}
{{- printf "%s:%s" .Values.image.repository (.Values.image.tag | default .Chart.AppVersion | toString) }}
{{- end }}
{{- end }}

{{/*
Name of the chart-managed Secret (database URL / SMTP password).
*/}}
{{- define "consolecrypt-server.secretName" -}}
{{- include "consolecrypt-server.fullname" . }}
{{- end }}

{{/*
"true" when the chart itself stores the external database URL in its Secret.
*/}}
{{- define "consolecrypt-server.managesDatabaseUrl" -}}
{{- if and (not .Values.postgresql.enabled) (not .Values.database.existingSecret) .Values.database.url -}}
true
{{- end }}
{{- end }}

{{/*
"true" when the chart itself stores the SMTP password in its Secret.
*/}}
{{- define "consolecrypt-server.managesSmtpPassword" -}}
{{- if and (eq .Values.mail.transport "smtp") (not .Values.mail.smtp.existingSecret) .Values.mail.smtp.password -}}
true
{{- end }}
{{- end }}

{{/*
Data (plain values) of the chart-managed Secret, as YAML; empty when nothing
is managed by the chart.
*/}}
{{- define "consolecrypt-server.secretData" -}}
{{- $data := dict }}
{{- if include "consolecrypt-server.managesDatabaseUrl" . }}
{{- $_ := set $data "CC_DATABASE_URL" .Values.database.url }}
{{- end }}
{{- if include "consolecrypt-server.managesSmtpPassword" . }}
{{- $_ := set $data "CC_SMTP_PASSWORD" .Values.mail.smtp.password }}
{{- end }}
{{- if $data }}
{{- toYaml $data }}
{{- end }}
{{- end }}

{{/*
true/false for CC_TRUST_PROXY_HEADERS ("auto" follows ingress.enabled).
*/}}
{{- define "consolecrypt-server.trustProxyHeaders" -}}
{{- $v := toString .Values.config.trustProxyHeaders }}
{{- if eq $v "auto" }}
{{- ternary "true" "false" (.Values.ingress.enabled | default false) }}
{{- else }}
{{- $v }}
{{- end }}
{{- end }}

{{/*
Non-secret CC_* settings as YAML (ConfigMap data). Empty values are omitted so
the server default applies. Integers are rendered without exponent notation.
*/}}
{{- define "consolecrypt-server.configData" -}}
{{- $c := .Values.config }}
{{- $sharing := dict }}
{{- range $name := list "objectSharingEnabled" "sharedGroupsEnabled" "sharedSecretsEnabled" "sharingOwnerOnlineEnrollmentEnabled" }}
{{- $value := false }}
{{- if hasKey $c $name }}{{- $value = get $c $name }}{{- end }}
{{- if not (kindIs "bool" $value) }}{{- fail (printf "config.%s must be a boolean" $name) }}{{- end }}
{{- $_ := set $sharing $name $value }}
{{- end }}
{{- $extensions := or $sharing.sharedGroupsEnabled $sharing.sharedSecretsEnabled $sharing.sharingOwnerOnlineEnrollmentEnabled }}
{{- if and $extensions (not $sharing.objectSharingEnabled) }}
{{- fail "sharing extensions require config.objectSharingEnabled=true" }}
{{- end }}
{{- if and (or $sharing.objectSharingEnabled $extensions) (not (and (kindIs "bool" $c.requireRequestProof) $c.requireRequestProof)) }}
{{- fail "object sharing requires config.requireRequestProof=true" }}
{{- end }}
{{- $env := dict
  "CC_LISTEN_ADDR" "0.0.0.0:8080"
  "CC_METRICS_LISTEN" (ternary "0.0.0.0:9090" "off" (.Values.metrics.enabled | default false))
  "CC_RUN_MIGRATIONS" .Values.migrations.runAtStartup
  "CC_DATABASE_MAX_CONNECTIONS" .Values.database.maxConnections
  "CC_PUBLIC_URL" $c.publicUrl
  "CC_SOURCE_CODE_URL" $c.sourceCodeUrl
  "CC_REGISTRATION_OPEN" $c.registrationOpen
  "CC_REQUIRE_EMAIL_VERIFICATION" $c.requireEmailVerification
  "CC_TRUST_PROXY_HEADERS" (include "consolecrypt-server.trustProxyHeaders" .)
  "CC_EVENT_BUS" $c.eventBus
  "CC_HSTS" $c.hsts
  "CC_REQUIRE_REQUEST_PROOF" $c.requireRequestProof
  "CC_OBJECT_SHARING_ENABLED" $sharing.objectSharingEnabled
  "CC_SHARED_GROUPS_ENABLED" $sharing.sharedGroupsEnabled
  "CC_SHARED_SECRETS_ENABLED" $sharing.sharedSecretsEnabled
  "CC_SHARING_OWNER_ONLINE_ENROLLMENT_ENABLED" $sharing.sharingOwnerOnlineEnrollmentEnabled
  "CC_LOG_FORMAT" $c.log.format
  "CC_LOG" $c.log.filter
  "CC_ACCESS_TOKEN_TTL_SECS" $c.tokens.accessTtlSecs
  "CC_REFRESH_TOKEN_TTL_SECS" $c.tokens.refreshTtlSecs
  "CC_DEVICE_REQUEST_TTL_SECS" $c.tokens.deviceRequestTtlSecs
  "CC_PASSWORD_RESET_TTL_SECS" $c.tokens.passwordResetTtlSecs
  "CC_EMAIL_VERIFY_TTL_SECS" $c.tokens.emailVerifyTtlSecs
  "CC_ARGON2_MEMORY_KIB" $c.argon2.memoryKib
  "CC_ARGON2_ITERATIONS" $c.argon2.iterations
  "CC_ARGON2_PARALLELISM" $c.argon2.parallelism
  "CC_ARGON2_MAX_CONCURRENT" $c.argon2.maxConcurrent
  "CC_RATE_LIMIT_ENABLED" $c.rateLimit.enabled
  "CC_RATE_LIMIT_AUTH_PER_IP_PER_MINUTE" $c.rateLimit.authPerIpPerMinute
  "CC_RATE_LIMIT_LOGIN_PER_EMAIL_PER_MINUTE" $c.rateLimit.loginPerEmailPerMinute
  "CC_RATE_LIMIT_RECOVERY_PER_EMAIL_PER_HOUR" $c.rateLimit.recoveryPerEmailPerHour
  "CC_RATE_LIMIT_PROOF_PER_DEVICE_PER_MINUTE" $c.rateLimit.proofPerDevicePerMinute
  "CC_SYNC_PAGE_BYTES" $c.sync.pageBytes
  "CC_MAX_VAULT_BYTES" $c.quotas.maxVaultBytes
  "CC_MAX_VAULTS_PER_ACCOUNT" $c.quotas.maxVaultsPerAccount
  "CC_WS_PING_INTERVAL_SECS" $c.websocket.pingIntervalSecs
  "CC_WS_SESSION_RECHECK_SECS" $c.websocket.sessionRecheckSecs
  "CC_WS_MAX_CONNECTIONS_PER_USER" $c.websocket.maxConnectionsPerUser
  "CC_MAINTENANCE_INTERVAL_SECS" $c.maintenance.intervalSecs
  "CC_RETENTION_SESSION_DAYS" $c.maintenance.retention.sessionDays
  "CC_RETENTION_SYNC_MUTATION_DAYS" $c.maintenance.retention.syncMutationDays
  "CC_RETENTION_AUDIT_DAYS" $c.maintenance.retention.auditDays
  "CC_RETENTION_DELETED_VAULT_DAYS" $c.maintenance.retention.deletedVaultDays
  "CC_RETENTION_DEVICE_REQUEST_DAYS" $c.maintenance.retention.deviceRequestDays
  "CC_DATABASE_CONNECT_TIMEOUT_SECS" $.Values.database.connectTimeoutSecs
  "CC_MAIL_TRANSPORT" .Values.mail.transport
  "CC_MAIL_FROM" .Values.mail.from
}}
{{- if eq .Values.mail.transport "smtp" }}
{{- $_ := set $env "CC_SMTP_HOST" .Values.mail.smtp.host }}
{{- $_ := set $env "CC_SMTP_PORT" .Values.mail.smtp.port }}
{{- $_ := set $env "CC_SMTP_TLS" .Values.mail.smtp.tls }}
{{- $_ := set $env "CC_SMTP_USERNAME" .Values.mail.smtp.username }}
{{- end }}
{{- if eq .Values.mail.transport "file" }}
{{- $_ := set $env "CC_MAIL_DIR" .Values.mail.file.dir }}
{{- end }}
{{- $out := dict }}
{{- range $k, $v := $env }}
{{- if not (or (kindIs "invalid" $v) (eq (toString $v) "")) }}
{{- if kindIs "float64" $v }}
{{- $v = int64 $v }}
{{- end }}
{{- $_ := set $out $k (toString $v) }}
{{- end }}
{{- end }}
{{- toYaml $out }}
{{- end }}

{{/*
Bundled PostgreSQL names.
*/}}
{{- define "consolecrypt-server.postgresql.fullname" -}}
{{- printf "%s-postgresql" (include "consolecrypt-server.fullname" .) | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "consolecrypt-server.postgresql.selectorLabels" -}}
app.kubernetes.io/name: {{ include "consolecrypt-server.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: database
{{- end }}

{{- define "consolecrypt-server.postgresql.secretName" -}}
{{- default (include "consolecrypt-server.postgresql.fullname" .) .Values.postgresql.auth.existingSecret }}
{{- end }}

{{- define "consolecrypt-server.postgresql.secretKey" -}}
{{- if .Values.postgresql.auth.existingSecret }}
{{- .Values.postgresql.auth.existingSecretPasswordKey }}
{{- else -}}
password
{{- end }}
{{- end }}

{{- define "consolecrypt-server.postgresql.image" -}}
{{- printf "%s:%s" .Values.postgresql.image.repository (.Values.postgresql.image.tag | toString) }}
{{- end }}

{{/*
Database env vars for server / migration containers.
Call with (dict "ctx" $ "secretName" <name of the Secret holding CC_DATABASE_URL>).
With the bundled PostgreSQL the URL carries no password; the server applies
CC_DATABASE_PASSWORD on top of it, so passwords never need URL-escaping.
*/}}
{{- define "consolecrypt-server.databaseEnv" -}}
{{- $ := .ctx }}
{{- if $.Values.postgresql.enabled }}
- name: CC_DATABASE_PASSWORD
  valueFrom:
    secretKeyRef:
      name: {{ include "consolecrypt-server.postgresql.secretName" $ }}
      key: {{ include "consolecrypt-server.postgresql.secretKey" $ }}
- name: CC_DATABASE_URL
  value: {{ printf "postgres://%s@%s:5432/%s" $.Values.postgresql.auth.username (include "consolecrypt-server.postgresql.fullname" $) $.Values.postgresql.auth.database | quote }}
{{- else if $.Values.database.existingSecret }}
- name: CC_DATABASE_URL
  valueFrom:
    secretKeyRef:
      name: {{ $.Values.database.existingSecret }}
      key: {{ $.Values.database.existingSecretKey }}
{{- else if $.Values.database.url }}
- name: CC_DATABASE_URL
  valueFrom:
    secretKeyRef:
      name: {{ .secretName }}
      key: CC_DATABASE_URL
{{- end }}
{{- end }}

{{/*
All explicit env vars of the server container (secrets + extraEnv), as YAML
list items; empty when there are none.
*/}}
{{- define "consolecrypt-server.serverEnv" -}}
{{- include "consolecrypt-server.databaseEnv" (dict "ctx" . "secretName" (include "consolecrypt-server.secretName" .)) }}
{{- if eq .Values.mail.transport "smtp" }}
{{- if .Values.mail.smtp.existingSecret }}
- name: CC_SMTP_PASSWORD
  valueFrom:
    secretKeyRef:
      name: {{ .Values.mail.smtp.existingSecret }}
      key: {{ .Values.mail.smtp.existingSecretPasswordKey }}
{{- else if .Values.mail.smtp.password }}
- name: CC_SMTP_PASSWORD
  valueFrom:
    secretKeyRef:
      name: {{ include "consolecrypt-server.secretName" . }}
      key: CC_SMTP_PASSWORD
{{- end }}
{{- end }}
{{- with .Values.extraEnv }}
{{ toYaml . }}
{{- end }}
{{- end }}

{{/*
"true" when some database is configured.
*/}}
{{- define "consolecrypt-server.hasDatabase" -}}
{{- if or .Values.postgresql.enabled .Values.database.existingSecret .Values.database.url -}}
true
{{- end }}
{{- end }}

{{/*
Validate values; fails rendering with a clear message.
*/}}
{{- define "consolecrypt-server.validate" -}}
{{- $v := .Values }}
{{- if not (has (toString $v.config.eventBus) (list "postgres" "local")) }}
{{- fail "config.eventBus must be \"postgres\" or \"local\"" }}
{{- end }}
{{- if and (eq (toString $v.config.eventBus) "local") (or (gt (int $v.replicaCount) 1) $v.autoscaling.enabled) }}
{{- fail "config.eventBus=local works with a single replica only; use config.eventBus=postgres with replicaCount > 1 or autoscaling" }}
{{- end }}
{{- if not (has (toString $v.config.trustProxyHeaders) (list "auto" "true" "false")) }}
{{- fail "config.trustProxyHeaders must be auto, true or false" }}
{{- end }}
{{- if not (has (toString $v.config.log.format) (list "json" "pretty")) }}
{{- fail "config.log.format must be json or pretty" }}
{{- end }}
{{- if not (has (toString $v.mail.transport) (list "disabled" "smtp" "file")) }}
{{- fail "mail.transport must be disabled, smtp or file" }}
{{- end }}
{{- if eq (toString $v.mail.transport) "smtp" }}
{{- if not $v.mail.smtp.host }}
{{- fail "mail.transport=smtp requires mail.smtp.host" }}
{{- end }}
{{- if not (has (toString $v.mail.smtp.tls) (list "tls" "starttls" "none")) }}
{{- fail "mail.smtp.tls must be tls, starttls or none" }}
{{- end }}
{{- end }}
{{- if and $v.postgresql.enabled (or $v.database.url $v.database.existingSecret) }}
{{- fail "configure either postgresql.enabled=true (bundled) or database.url/database.existingSecret (external), not both" }}
{{- end }}
{{- if $v.postgresql.enabled }}
{{- if not (regexMatch "^[A-Za-z_][A-Za-z0-9_]{0,62}$" (toString $v.postgresql.auth.username)) }}
{{- fail "postgresql.auth.username must match ^[A-Za-z_][A-Za-z0-9_]*$" }}
{{- end }}
{{- if not (regexMatch "^[A-Za-z_][A-Za-z0-9_]{0,62}$" (toString $v.postgresql.auth.database)) }}
{{- fail "postgresql.auth.database must match ^[A-Za-z_][A-Za-z0-9_]*$" }}
{{- end }}
{{- end }}
{{- end }}
