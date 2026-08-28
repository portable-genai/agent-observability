# artifact_registry.tf — The registry this stack's own images are pulled from.
#
# The reference deployment pulled the service and collector images from a repository that
# was created by hand and existed in no Terraform at all, so a clean checkout could not
# rebuild the stack: every plan's image preconditions point at a registry nothing declares.
# Declared here so Terraform is the only place infrastructure is described.
#
# Image layers carry the application and its configuration, so the repository is bound to
# the same CMEK key as the rest of the audit stack. CMEK does not cascade: the Artifact
# Registry service agent needs its own key grant, and the agent does not exist until it is
# asked for — creating the identity makes that ordering explicit rather than a race.

resource "google_project_service_identity" "artifactregistry" {
  provider = google-beta
  project  = var.project_id
  service  = "artifactregistry.googleapis.com"

  depends_on = [google_project_service.required]
}

resource "google_kms_crypto_key_iam_member" "artifactregistry" {
  crypto_key_id = google_kms_crypto_key.audit.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "serviceAccount:${google_project_service_identity.artifactregistry.email}"
}

resource "google_artifact_registry_repository" "images" {
  project       = var.project_id
  location      = var.region
  repository_id = var.artifact_repository_id
  description   = "Agent observability service and OTel collector images, CMEK-encrypted."
  format        = "DOCKER"

  kms_key_name = google_kms_crypto_key.audit.id

  # Immutable tags: a deployed tag must always name the same bytes, so a digest-pinned
  # deployment cannot be undermined by the tag that produced it being moved afterwards.
  docker_config {
    immutable_tags = true
  }

  depends_on = [
    google_project_service.required,
    google_kms_crypto_key_iam_member.artifactregistry,
  ]
}

output "image_repository" {
  description = "Image prefix to build and push this stack's images into."
  value       = "${var.region}-docker.pkg.dev/${var.project_id}/${google_artifact_registry_repository.images.repository_id}"
}
