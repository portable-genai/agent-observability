# providers.tf — Provider pinning for the Hrz5 observability deploy.
#
# General Principle map:
#   P-03 (data residency): every provider call is pinned to var.region.
#         There is no global / multi-region default.
#   P-02 (no lock-in): Terraform is the only place infra is described; the app talks to
#         ports, not these resources.

terraform {
  required_version = ">= 1.9.0"

  # Partial backend: the bucket and per-installation prefix are supplied at init. Declared at
  # all so that local state is impossible in a real deployment — this stack previously had no
  # backend block, which meant its state lived only on whichever workstation last applied it,
  # and a lost laptop meant a stack nobody could change or destroy.
  backend "gcs" {}

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 6.0" # 6.x line — current GA surface (mid-2026)
    }
    # google_project_service_identity, used in cmek.tf to ask a service for its own agent
    # identity rather than guessing the address, is exposed only on the beta surface.
    google-beta = {
      source  = "hashicorp/google-beta"
      version = "~> 6.0"
    }
  }
}

# Every resource defaults to var.region (us-central1 unless overridden).
provider "google" {
  project = var.project_id
  region  = var.region # regional, default us-central1, never global
}

provider "google-beta" {
  project = var.project_id
  region  = var.region
}
