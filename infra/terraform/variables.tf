# variables.tf — Only genuinely per-tenant inputs are variables. Everything else is a
# configurable regional values. project_id has no default on purpose.

variable "project_id" {
  type        = string
  description = "Target GCP project id for the Hrz5 observability deploy (per-tenant)."
}

variable "region" {
  type        = string
  description = "Deployment region, validated against allowed_regions (P-03)."
  default     = "us-central1"

  validation {
    condition     = contains(var.allowed_regions, var.region)
    error_message = "region must be present in allowed_regions (P-03)."
  }
}

variable "allowed_regions" {
  type        = list(string)
  description = "Residency-approved deployment regions."
  default     = ["us-central1"]

  validation {
    condition     = length(var.allowed_regions) > 0
    error_message = "allowed_regions must contain at least one approved GCP region."
  }
}

variable "enforce_org_policies" {
  type        = bool
  description = "Manage the residency + require-CMEK Org Policies here (org_policy.tf). Set false when policy is owned centrally at folder / org level."
  default     = true
}

variable "key_rotation_period" {
  type        = string
  description = "CMEK rotation period for the audit key (P-09). Seconds, e.g. 7776000s = 90 days."
  default     = "7776000s"

  validation {
    condition     = can(regex("^[0-9]+s$", var.key_rotation_period))
    error_message = "key_rotation_period must be a seconds duration such as \"7776000s\"."
  }
}

variable "access_policy_id" {
  type        = string
  description = "Access Context Manager policy id for the VPC-SC perimeter (org-level, adopter-owned). Empty disables the perimeter resources entirely."
  default     = ""
}

variable "vpc_sc_enforce" {
  type        = bool
  description = "Promote the VPC-SC perimeter from dry run to enforced. Keep false until the dry-run violation alert has been quiet."
  default     = false
}

variable "vpc_sc_restricted_services" {
  type        = list(string)
  description = "Services locked inside the VPC-SC perimeter."
  default = [
    "logging.googleapis.com",
    "bigquery.googleapis.com",
    "run.googleapis.com",
    "cloudkms.googleapis.com",
    "storage.googleapis.com",
  ]

  validation {
    condition     = contains(var.vpc_sc_restricted_services, "logging.googleapis.com")
    error_message = "logging.googleapis.com must stay restricted: it holds the WORM audit trail."
  }
}

variable "vpc_sc_access_levels" {
  type        = list(string)
  description = "Access levels permitted to reach into the perimeter (adopter-owned; usually a corporate-network / managed-device level)."
  default     = []
}

variable "retention_days" {
  type        = number
  description = "WORM audit-bucket retention in days. ~7 years (rule R2). IRREVERSIBLE once locked."
  default     = 2557
}

variable "worm_locked" {
  description = <<-EOT
    Lock the WORM audit bucket (rule R2).
    #########################################################################
    # WARNING: LOCKING IS IRREVERSIBLE. With true, the bucket and its       #
    # retention window can NEVER be reduced or deleted until every entry    #
    # ages out (2557 days by default), not even with project-owner rights.  #
    #########################################################################
    true (the default) is REQUIRED for a compliant production deploy: the audit trail is
    Write-Once-Read-Many only when locked. Set false ONLY for evaluation/demo stacks that
    must remain deletable (terraform destroy works); that posture is NOT compliant, and
    Rsk1 depends on the guarantee it gives up.

    Setting this false against an ALREADY-locked bucket does not unlock it. The API refuses,
    as it should. This governs the first apply.
  EOT
  type        = bool
  default     = true
}

variable "container_image" {
  type        = string
  description = "Cloud Run container image for the Hrz5 service."
  default     = "us-central1-docker.pkg.dev/REPLACE_ME/hrz/agent-observability:latest"
}

variable "service_audience" {
  type        = string
  description = "Canonical HTTPS Cloud Run/LB audience accepted for service ID tokens."

  validation {
    condition     = startswith(var.service_audience, "https://")
    error_message = "service_audience must use HTTPS."
  }
}

variable "audit_writer_service_accounts" {
  type        = list(string)
  description = "Service-account emails allowed to write ordinary audit events."

  validation {
    condition     = length(var.audit_writer_service_accounts) > 0
    error_message = "at least one ordinary audit-writer identity is required."
  }
}

variable "release_approver_service_accounts" {
  type        = list(string)
  description = "Separate reviewer service-account emails allowed to approve releases."

  validation {
    condition = (
      length(var.release_approver_service_accounts) > 0 &&
      length(setintersection(
        toset(var.release_approver_service_accounts),
        toset(var.audit_writer_service_accounts)
      )) == 0
    )
    error_message = "reviewer identities must be nonempty and disjoint from audit writers."
  }
}

variable "cloud_run_deletion_protection" {
  type        = bool
  description = <<-EOT
    Cloud Run deletion protection. True (the default) for anything that matters.

    Declared EXPLICITLY rather than inherited: the provider defaults it to true, and the
    services here were never setting it, so the first image change produced
    "cannot destroy service without setting deletion_protection=false" mid-apply — a
    half-applied stack blocked by a value nobody had chosen. A reference or evaluation stack
    that must stay replaceable sets this false deliberately.
  EOT
  default     = true
}

variable "otel_collector_image" {
  type        = string
  description = "OpenTelemetry Collector (contrib) image for the OTLP ingest service. Pin to a digest in production (practice D2)."
  default     = "otel/opentelemetry-collector-contrib:0.109.0"
}

variable "otel_caller_service_accounts" {
  type        = list(string)
  description = "Service-account emails allowed to invoke the OTLP collector (run.invoker). Empty by default; add the verticals' runtime SAs per deployment."
  default     = []
}

variable "slo_availability_goal" {
  type        = number
  description = "Rolling 30-day availability objective for the observability API."
  default     = 0.999

  validation {
    condition     = var.slo_availability_goal > 0 && var.slo_availability_goal < 1
    error_message = "slo_availability_goal must be greater than 0 and less than 1."
  }
}

variable "alert_notification_channels" {
  type        = list(string)
  description = "Existing Cloud Monitoring notification-channel resource names."
  default     = []
}

variable "min_instances" {
  type        = number
  default     = 1
  description = <<-EOT
    Warm instances for the audit ingest.

    Defaults to one rather than zero because callers fail CLOSED on an audit write: a portal that
    forwards one access event per request answers 503 when the write does not land, so a
    cold start here is an outage of whatever is calling. Set it to zero only where the callers
    can tolerate a cold start on the audit path, which today none of them can.
  EOT
  validation {
    condition     = var.min_instances >= 0 && var.min_instances <= 10
    error_message = "min_instances must be between 0 and 10."
  }
}

variable "max_instances" {
  type        = number
  default     = 10
  description = "Upper bound on audit-ingest instances."
  validation {
    condition     = var.max_instances >= 1 && var.max_instances <= 100
    error_message = "max_instances must be between 1 and 100."
  }
}
