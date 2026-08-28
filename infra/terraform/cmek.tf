# cmek.tf — Customer-managed encryption keys, bound explicitly per service.
#
# Practice D5 / principle P-09. COMPLIANCE.md claims bank-held key control over the audit
# trail; that claim is only true if each service is bound to a key the bank rotates and can
# destroy. Google-managed default encryption is NOT that. Every key lives in var.region, so
# the key material shares the residency of the data it protects (P-03).
#
# The three bindings that matter, wired in their own files to the resources below:
#   Cloud Logging  -> the project CMEK settings for log buckets (logging_worm.tf).
#   BigQuery       -> dataset default_encryption_configuration (bigquery.tf).
#   Cloud Run      -> template encryption_key (cloud_run.tf, both services).
#
# Rotation is a variable, not a constant: var.key_rotation_period. Destroying the key makes
# the ciphertext unreadable, which is deliberate (crypto-shredding is the bank's lever), so
# prevent_destroy guards the key against an accidental `terraform destroy`.

resource "google_kms_key_ring" "audit" {
  project  = var.project_id
  name     = "agent-observability"
  location = var.region # key material shares the data's residency (P-03)

  depends_on = [google_project_service.required]
}

resource "google_kms_crypto_key" "audit" {
  name            = "audit-trail"
  key_ring        = google_kms_key_ring.audit.id
  rotation_period = var.key_rotation_period
  purpose         = "ENCRYPT_DECRYPT"

  lifecycle {
    prevent_destroy = true
  }
}

# Each Google service encrypts with its OWN service agent identity, so every service that
# touches the audit trail needs an explicit encrypter/decrypter grant on the key. Missing any
# one of these is how a "CMEK enabled" deploy silently falls back at create time.
data "google_project" "this" {
  project_id = var.project_id

  # Every data source here reads a service's own answer, so each must wait for the service
  # to be enabled. On the long-lived project the APIs were already on and the missing
  # ordering never showed; on a fresh project it is a race the first apply loses.
  depends_on = [google_project_service.required]
}

# Service agents are ASKED FOR, never spelled out. A "service-<number>@gcp-sa-<x>" string is a
# guess about an implementation detail and it fails twice over: the agent does not exist until
# the service is provisioned, so the apply dies with "Service account ... does not exist", and
# the local part is not uniform (BigQuery's CMEK agent is bq-<number>@bigquery-encryption,
# nothing like the others). Both halves were true here on the first real apply, 2026-08-24.
#
# Each block below either CREATES the identity or READS it from the service that owns it, so
# the address is authoritative and the ordering is explicit rather than hoped for.
data "google_bigquery_default_service_account" "this" {
  project = var.project_id

  depends_on = [google_project_service.required]
}

# Cloud Logging exposes no service_identity resource; this data source is the authoritative
# answer to "which agent encrypts this project's logs".
data "google_logging_project_cmek_settings" "this" {
  project = var.project_id

  depends_on = [google_project_service.required]
}

resource "google_project_service_identity" "run" {
  provider = google-beta
  project  = var.project_id
  service  = "run.googleapis.com"

  depends_on = [google_project_service.required]
}

locals {
  cmek_service_agents = {
    logging  = data.google_logging_project_cmek_settings.this.service_account_id
    bigquery = data.google_bigquery_default_service_account.this.email
    run      = google_project_service_identity.run.email
  }
}

resource "google_kms_crypto_key_iam_member" "service_agents" {
  for_each = local.cmek_service_agents

  crypto_key_id = google_kms_crypto_key.audit.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "serviceAccount:${each.value}"
}

# The locked WORM bucket's own CMEK binding lives on the bucket resource itself
# (logging_worm.tf, `cmek_settings`), because a Cloud Logging bucket takes its key at the
# bucket level rather than from a project-wide default.

output "audit_cmek_key" {
  description = "CMEK protecting the audit trail (bank-rotated; destroying it crypto-shreds)."
  value       = google_kms_crypto_key.audit.id
}
