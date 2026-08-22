# logging_worm.tf — Hrz5 WORM audit trail: locked Cloud Logging bucket + sink + audit config.
#
# This is the compliance heart of Hrz5 (catalog system Hrz5; rule R2). Rsk1 (and any other
# catalog system) routes immutable audit records here via POST /v1/audit; the
# CloudLoggingAuditAdapter writes already-redacted AuditEvents to the log below, and this
# sink routes them into a LOCKED log bucket — Write-Once-Read-Many.
#
# General Principle map:
#   R2 / P-08 (immutable audit / WORM): retention = var.retention_days (~7 years) and
#         locked = true make the bucket WORM. Records cannot be edited or deleted for the
#         full window.
#   P-03 (residency): bucket location is us-central1.
#   P-04 (no raw PII in logs): only redacted prompts/responses are written (enforced in
#         the app + upstream A1); DATA_READ audit logging records every read of the store.
#
# ############################################################################ #
# # WARNING — LOCKING IS IRREVERSIBLE.                                        # #
# # Setting `locked = true` below PERMANENTLY prevents reducing retention or  # #
# # deleting this bucket for the full retention window (var.retention_days).  # #
# # You CANNOT undo it, not even with project-owner rights, and `terraform    # #
# # destroy` will NOT remove it. Confirm retention_days before the first      # #
# # apply. To trial without locking, set locked = false (NOT compliant for    # #
# # production — it breaks the rule R2 WORM guarantee Rsk1 depends on).       # #
# ############################################################################ #

resource "google_logging_project_bucket_config" "worm_audit" {
  project  = var.project_id
  location = var.region # us-central1 (P-03)
  # bucket_id matches settings.yaml logging.bucket_id
  bucket_id   = "agent-observability-worm"
  description = "WORM audit bucket for catalog system Hrz5 (locked, ~7y retention, rule R2)."
  # retention_days defaults to 2557 (~7 years) — see var.retention_days.
  retention_days = var.retention_days

  # IRREVERSIBLE — see WARNING banner above. WORM compliance (rule R2) requires this true.
  locked = true

  # Bank-held key over the WORM trail itself (P-09, practice D5). Without this the bucket
  # is encrypted with a Google-managed key and the "bank controls the audit key" claim in
  # COMPLIANCE.md is not true. Destroying the key crypto-shreds the trail, which is the
  # only lever that exists once `locked = true` forbids deletion.
  cmek_settings {
    kms_key_name = google_kms_crypto_key.audit.id
  }

  depends_on = [
    google_project_service.required,
    google_kms_crypto_key_iam_member.service_agents,
  ]
}

# The structured log Hrz5's CloudLoggingAuditAdapter writes to (settings.logging.log_name).
locals {
  audit_log_name = "agent-observability-audit"
}

# Route the audit log stream into the locked WORM bucket.
resource "google_logging_project_sink" "audit_to_worm" {
  project     = var.project_id
  name        = "agent-observability-to-worm"
  description = "Routes the agent-observability-audit log to the locked WORM bucket (rule R2)."

  destination = "logging.googleapis.com/${google_logging_project_bucket_config.worm_audit.id}"

  # Capture this service's audit log plus all Cloud Audit Logs (admin / data access).
  filter = <<-EOT
    logName="projects/${var.project_id}/logs/${local.audit_log_name}"
    OR logName:"cloudaudit.googleapis.com"
  EOT

  unique_writer_identity = true
}

# --------------------------------------------------------------------------- #
# Enable Data Access audit logs (DATA_READ) so every READ of the audit store
# (e.g. a GET /v1/audit read-back or a regulator pull) is itself audited (P-08).
# DATA_WRITE and ADMIN_READ are added explicitly alongside DATA_READ.
# --------------------------------------------------------------------------- #
resource "google_project_iam_audit_config" "data_access" {
  project = var.project_id
  service = "allServices"

  audit_log_config {
    log_type = "DATA_READ"
  }
  audit_log_config {
    log_type = "DATA_WRITE"
  }
  audit_log_config {
    log_type = "ADMIN_READ"
  }
}
