# org_policy.tf — Residency and encryption enforced by Org Policy, not by convention.
#
# Practice D5 / principle P-03. Terraform's own `var.region` validation only constrains what
# THIS configuration asks for; an operator with project rights can still create a resource
# elsewhere by hand. These project-level policies make the allowlist the platform's rule:
#
#   gcp.resourceLocations      -> resources may only be created in var.allowed_regions.
#   gcp.restrictNonCmekServices -> the audit-bearing services must be created WITH CMEK
#                                  (see cmek.tf), so "Google-managed default key" is not a
#                                  silent fallback.
#
# Both are project-scoped `google_org_policy_policy` resources: an adopter who manages policy
# at the folder / org level sets enforce_org_policies = false and mirrors these constraints in
# their own policy repository instead. A second region or enterprise remains a tfvars change,
# never a fork.

resource "google_org_policy_policy" "resource_locations" {
  count = var.enforce_org_policies ? 1 : 0

  name   = "projects/${var.project_id}/policies/gcp.resourceLocations"
  parent = "projects/${var.project_id}"

  spec {
    rules {
      values {
        # in:<region>-locations is the location-group form Org Policy expects.
        allowed_values = [for r in var.allowed_regions : "in:${r}-locations"]
      }
    }
  }

  depends_on = [google_project_service.required]
}

resource "google_org_policy_policy" "require_cmek" {
  count = var.enforce_org_policies ? 1 : 0

  name   = "projects/${var.project_id}/policies/gcp.restrictNonCmekServices"
  parent = "projects/${var.project_id}"

  spec {
    rules {
      values {
        denied_values = [
          "bigquery.googleapis.com",
          "logging.googleapis.com",
          "run.googleapis.com",
        ]
      }
    }
  }

  depends_on = [
    google_project_service.required,
    google_kms_crypto_key.audit,
  ]
}
