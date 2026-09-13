# variables.tf — Only genuinely per-tenant inputs are variables. Everything else is a
# configurable regional values. project_id has no default on purpose.

variable "project_id" {
  type        = string
  description = "Target GCP project id for the agent-observability deploy (per-tenant)."
}

variable "region" {
  type        = string
  description = "Deployment region, validated against allowed_regions (P-03)."
  default     = "asia-southeast1"

  validation {
    condition     = contains(var.allowed_regions, var.region)
    error_message = "region must be present in allowed_regions (P-03)."
  }
}

variable "allowed_regions" {
  type        = list(string)
  description = "Residency-approved deployment regions."
  default     = ["asia-southeast1"]

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
  description = <<-EOT
    WORM audit-bucket retention in days. Default 2557 (~7 years, rule R2).

    The 2557-day compliance floor binds whenever worm_locked = true, which is the production
    posture. It is NOT applied to an unlocked stack, where the retention policy is removable by
    a project owner anyway and therefore evidences routing and coverage rather than
    immutability. That lets a reference or evaluation deployment keep a short window while it
    stays destroyable, without weakening what a production deployment gets: turning the lock
    on re-imposes the floor at plan time.
  EOT
  default     = 2557

  validation {
    condition     = var.worm_locked ? var.retention_days >= 2557 : var.retention_days >= 1
    error_message = "A LOCKED stack must retain at least 2557 days (~7 years, rule R2); an unlocked stack must still retain at least 1 day."
  }
}

variable "worm_locked" {
  type        = bool
  description = <<-EOT
    Lock the WORM audit bucket (rule R2).
    #########################################################################
    # WARNING: LOCKING IS IRREVERSIBLE. With true, the bucket and its       #
    # retention window can NEVER be reduced or deleted until every entry    #
    # ages out (retention_days), not even with project-owner rights.        #
    #########################################################################

    NO DEFAULT, and that is the decision. An irreversible control must never arrive because a
    deployment said nothing, so there is no default of true: the previous default locked this
    stack's bucket for seven years on a first apply nobody had reviewed. A fork running this
    as a system of record must not quietly lose the WORM guarantee either, so there is no
    default of false. Every plan names it.

    true is the compliant production posture: the audit trail is Write-Once-Read-Many only
    when locked, and compliance-advisory depends on that guarantee. false keeps the bucket,
    its retention and its sink, and leaves the bucket destroyable: a reference or evaluation
    posture, NOT WORM, and the deployment tfvars says why.

    Setting false against an ALREADY-locked bucket does not unlock it. The API refuses, as it
    should. This governs the first apply.
  EOT
}

variable "container_image" {
  type        = string
  description = "Cloud Run container image for the agent-observability service."
  default     = "asia-southeast1-docker.pkg.dev/REPLACE_ME/hrz/agent-observability:latest"
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

variable "firestore_delete_protection_enabled" {
  type        = bool
  default     = true
  description = <<-EOT
    Firestore delete protection on the idempotency ledger. Default true.

    This was a hardcoded DELETE_PROTECTION_ENABLED, which made any teardown need a source
    edit before it could even plan. The protection is right for a production stack; a
    reference stack that must stay replaceable declines it in tfvars, exactly as it already
    can for cloud_run_deletion_protection and worm_locked.
  EOT
}

variable "artifact_repository_id" {
  type        = string
  default     = "agent-observability"
  description = <<-EOT
    Artifact Registry repository id for this stack's own images (artifact_registry.tf).
    The registry the reference deployment pulled from was created by hand and existed in no
    Terraform; declaring it is what makes a build-from-zero possible.
  EOT
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

variable "manage_audit_config" {
  type        = bool
  default     = false
  description = <<-EOT
    Whether THIS stack writes the project's data-access audit configuration.

    False by default, and the default is the point. `google_project_iam_audit_config` is
    AUTHORITATIVE for the service it names, so a second stack declaring `allServices` does
    not add to that configuration, it REPLACES it, and a stack asking for DATA_READ and
    DATA_WRITE removes an ADMIN_READ a sibling enabled. Terraform reports that as a create
    rather than a change, because this stack holds no prior state for a resource that is
    nonetheless already live. Nearly every stack in this fleet carries this resource and one
    project hosts many of them, so a default of true is a race whose winner is whichever
    stack applied last.

    Data-access logs are also the highest-volume class Cloud Logging ingests, and nothing in
    the reference deployment reads them.

    Set true in exactly one stack per project, in that deployment's own tfvars, where the
    project genuinely wants data-access logging on.
  EOT
}
