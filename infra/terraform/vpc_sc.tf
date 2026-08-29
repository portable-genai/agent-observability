# vpc_sc.tf — VPC Service Controls perimeter around the audit trail, DRY RUN FIRST.
#
# Practice D5. A perimeter that is enforced on its first apply takes the platform's audit
# path down the moment one legitimate caller was missed, and the usual reaction (delete the
# perimeter) leaves the data exfiltration boundary permanently off. So this ships in dry-run:
# `use_explicit_dry_run_spec = true` makes every violation LOGGED and ALLOWED, the posture
# alert in monitoring.tf turns those log entries into a signal, and only when the dry-run is
# quiet does an adopter set `vpc_sc_enforce = true` to promote the same spec to enforced.
#
# Access Context Manager lives at the ORGANISATION level, so this whole file is inert until
# an adopter supplies `access_policy_id` (their existing policy). That keeps the offline
# `terraform validate` gate honest without pretending we can create org-level resources.

locals {
  vpc_sc_enabled       = var.access_policy_id != ""
  vpc_sc_perimeter_key = "agent_observability"
}

resource "google_access_context_manager_service_perimeter" "audit" {
  count = local.vpc_sc_enabled ? 1 : 0

  parent = "accessPolicies/${var.access_policy_id}"
  name   = "accessPolicies/${var.access_policy_id}/servicePerimeters/${local.vpc_sc_perimeter_key}"
  title  = "Hrz5 agent observability audit perimeter"

  # Dry run unless the adopter has promoted it deliberately.
  use_explicit_dry_run_spec = !var.vpc_sc_enforce

  # `spec` is the dry-run configuration; `status` is the enforced one. Exactly one of them
  # carries the restricted services, decided by the same flag, so promoting the perimeter is
  # a one-variable change and never a rewrite of the rules being promoted.
  dynamic "spec" {
    for_each = var.vpc_sc_enforce ? [] : [1]
    content {
      resources           = ["projects/${data.google_project.this.number}"]
      restricted_services = var.vpc_sc_restricted_services
      access_levels       = var.vpc_sc_access_levels
    }
  }

  dynamic "status" {
    for_each = var.vpc_sc_enforce ? [1] : []
    content {
      resources           = ["projects/${data.google_project.this.number}"]
      restricted_services = var.vpc_sc_restricted_services
      access_levels       = var.vpc_sc_access_levels
    }
  }

  lifecycle {
    create_before_destroy = true
  }
}

output "vpc_sc_mode" {
  description = "Whether the audit perimeter is enforced or still logging in dry run."
  value = (
    local.vpc_sc_enabled
    ? (var.vpc_sc_enforce ? "enforced" : "dry-run")
    : "not configured (set access_policy_id)"
  )
}
