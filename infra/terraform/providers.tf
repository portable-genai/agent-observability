# providers.tf — Provider pinning for the Hrz5 observability deploy.
#
# General Principle map:
#   P-03 (data residency): every provider call is pinned to var.region.
#         There is no global / multi-region default.
#   P-02 (no lock-in): Terraform is the only place infra is described; the app talks to
#         ports, not these resources.

terraform {
  required_version = ">= 1.9.0"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 6.0" # 6.x line — current GA surface (mid-2026)
    }
  }
}

# Every resource defaults to Singapore.
provider "google" {
  project = var.project_id
  region  = var.region # regional, default us-central1, never global
}
