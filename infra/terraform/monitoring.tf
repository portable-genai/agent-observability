# monitoring.tf — production dashboard, service-level objective, and paging signals.

resource "google_monitoring_service" "observability" {
  project      = var.project_id
  service_id   = "agent-observability"
  display_name = "Hrz5 Agent Observability"

  # CLOUD_RUN, not "cloud_run_revision". The latter is the MONITORED RESOURCE type used in
  # metric filters, and it is not a Monitoring service type — the API rejects it with
  # "IDENTIFIER_NOT_SET is not a valid service type", which names neither the field nor the
  # value and is why this is worth a comment. Found on the first real apply, 2026-08-24.
  # CLOUD_RUN takes exactly service_name and location; project_id is not one of its labels.
  basic_service {
    service_type = "CLOUD_RUN"
    service_labels = {
      service_name = google_cloud_run_v2_service.observability.name
      location     = var.region
    }
  }
}

resource "google_monitoring_slo" "availability" {
  project      = var.project_id
  service      = google_monitoring_service.observability.service_id
  slo_id       = "availability"
  display_name = "99.9% successful requests over 30 days"
  goal         = var.slo_availability_goal

  rolling_period_days = 30

  request_based_sli {
    good_total_ratio {
      good_service_filter = join(" AND ", [
        "metric.type=\"run.googleapis.com/request_count\"",
        "resource.type=\"cloud_run_revision\"",
        "resource.labels.service_name=\"${google_cloud_run_v2_service.observability.name}\"",
        "metric.labels.response_code_class!=\"5xx\"",
      ])
      total_service_filter = join(" AND ", [
        "metric.type=\"run.googleapis.com/request_count\"",
        "resource.type=\"cloud_run_revision\"",
        "resource.labels.service_name=\"${google_cloud_run_v2_service.observability.name}\"",
      ])
    }
  }
}

locals {
  # Cloud Monitoring REJECTS an alert filter with no resource.type restriction, and only
  # equality, one_of() and starts_with() are accepted forms.
  #
  # Posture violations do NOT arrive on cloud_run_revision. VPC-SC denials and Org Policy
  # residency refusals are Cloud Audit Log entries on audited_resource, and a log-based metric
  # inherits the resource of the entry that produced it. Restricting these two alerts to the
  # service's own resource type would read as precision and match nothing, which is a posture
  # alert that never fires — indistinguishable from a clean posture. The union is therefore
  # deliberately broad; the metric's own log filter is what scopes each signal.
  #
  # The service_errors alert below is different and correctly narrow: those entries are
  # written BY this Cloud Run service, so cloud_run_revision is true by construction.
  posture_alert_resource_types = "resource.type=one_of(\"audited_resource\",\"global\",\"project\",\"cloud_run_revision\",\"cloud_run_job\",\"service_account\",\"cloudkms_cryptokey\",\"cloudkms_keyring\",\"gce_instance\",\"k8s_container\",\"generic_task\",\"generic_node\",\"gcs_bucket\")"
}

resource "google_logging_metric" "service_errors" {
  project = var.project_id
  name    = "hrz_agent_observability_service_errors"
  filter = join(" AND ", [
    "resource.type=\"cloud_run_revision\"",
    "resource.labels.service_name=\"${google_cloud_run_v2_service.observability.name}\"",
    "severity>=ERROR",
  ])

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    unit        = "1"
  }
}

resource "google_monitoring_alert_policy" "service_errors" {
  project      = var.project_id
  display_name = "Hrz5 service errors"
  combiner     = "OR"

  conditions {
    display_name = "At least one error log in five minutes"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.service_errors.name}\" AND resource.type=\"cloud_run_revision\""
      comparison      = "COMPARISON_GT"
      threshold_value = 0
      duration        = "0s"

      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_SUM"
      }
    }
  }

  notification_channels = var.alert_notification_channels

  documentation {
    content   = "Inspect Hrz5 structured logs, verify WORM audit writes, then check OTLP exporter health and queue saturation."
    mime_type = "text/markdown"
  }
}

resource "google_monitoring_alert_policy" "slo_burn" {
  project      = var.project_id
  display_name = "Hrz5 availability SLO fast burn"
  combiner     = "OR"

  conditions {
    display_name = "30-day availability budget burning at 10x"
    condition_threshold {
      filter = "select_slo_burn_rate(\"${google_monitoring_slo.availability.name}\", \"3600s\")"

      comparison      = "COMPARISON_GT"
      threshold_value = 10
      duration        = "300s"
    }
  }

  notification_channels = var.alert_notification_channels

  documentation {
    content   = "The one-hour burn rate is consuming the 30-day availability error budget too quickly. Check 5xx responses, dependencies, and recent deploys."
    mime_type = "text/markdown"
  }
}

resource "google_monitoring_dashboard" "agent_observability" {
  project = var.project_id
  dashboard_json = jsonencode({
    displayName = "Hrz5 Agent Observability — SRE"
    mosaicLayout = {
      columns = 12
      tiles = [
        {
          xPos   = 0
          yPos   = 0
          width  = 6
          height = 4
          widget = {
            title = "Cloud Run request count"
            xyChart = {
              dataSets = [{
                plotType = "LINE"
                timeSeriesQuery = {
                  timeSeriesFilter = {
                    filter = "metric.type=\"run.googleapis.com/request_count\" resource.type=\"cloud_run_revision\" resource.labels.service_name=\"${google_cloud_run_v2_service.observability.name}\""
                    aggregation = {
                      alignmentPeriod  = "60s"
                      perSeriesAligner = "ALIGN_RATE"
                    }
                  }
                }
              }]
              yAxis = { label = "requests/s", scale = "LINEAR" }
            }
          }
        },
        {
          xPos   = 6
          yPos   = 0
          width  = 6
          height = 4
          widget = {
            title = "Cloud Run p95 latency"
            xyChart = {
              dataSets = [{
                plotType = "LINE"
                timeSeriesQuery = {
                  timeSeriesFilter = {
                    filter = "metric.type=\"run.googleapis.com/request_latencies\" resource.type=\"cloud_run_revision\" resource.labels.service_name=\"${google_cloud_run_v2_service.observability.name}\""
                    aggregation = {
                      alignmentPeriod  = "60s"
                      perSeriesAligner = "ALIGN_PERCENTILE_95"
                    }
                  }
                }
              }]
              yAxis = { label = "latency", scale = "LINEAR" }
            }
          }
        }
      ]
    }
  })
}

# --------------------------------------------------------------------------- #
# Posture alerts (practice D5). Residency, CMEK and the VPC-SC perimeter are all
# declared as code above; these turn a DEVIATION from that posture into a page,
# which is what makes a dry-run perimeter useful rather than decorative.
# --------------------------------------------------------------------------- #

# Every VPC-SC violation the DRY-RUN perimeter would have blocked. While
# vpc_sc_enforce = false these are logged and allowed: the alert is the readiness
# signal, and a quiet window is the precondition for promoting to enforced.
resource "google_logging_metric" "vpc_sc_dry_run_violations" {
  project = var.project_id
  name    = "hrz_agent_observability_vpc_sc_dry_run_violations"
  filter = join(" AND ", [
    "log_id(\"cloudaudit.googleapis.com/policy\")",
    "protoPayload.metadata.dryRun=\"true\"",
    "severity>=WARNING",
  ])

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    unit        = "1"
  }
}

resource "google_monitoring_alert_policy" "vpc_sc_dry_run" {
  project      = var.project_id
  display_name = "Hrz5 VPC-SC dry-run violations"
  combiner     = "OR"

  conditions {
    display_name = "A call would have been blocked by the audit perimeter"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.vpc_sc_dry_run_violations.name}\" AND ${local.posture_alert_resource_types}"
      comparison      = "COMPARISON_GT"
      threshold_value = 0
      duration        = "0s"

      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_SUM"
      }
    }
  }

  notification_channels = var.alert_notification_channels

  documentation {
    content   = "A caller tripped the DRY-RUN VPC-SC perimeter (vpc_sc.tf). Identify the principal, then either add it to an access level or fix the caller. Promote vpc_sc_enforce = true only after a quiet window."
    mime_type = "text/markdown"
  }
}

# Residency / encryption posture drift: a resource created outside the allowlist, or
# a CMEK denial, both surface as Org Policy violations in the admin activity log.
resource "google_logging_metric" "residency_policy_violations" {
  project = var.project_id
  name    = "hrz_agent_observability_residency_policy_violations"
  filter = join(" AND ", [
    "log_id(\"cloudaudit.googleapis.com/activity\")",
    "protoPayload.status.message:(\"constraints/gcp.resourceLocations\" OR \"constraints/gcp.restrictNonCmekServices\")",
  ])

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    unit        = "1"
  }
}

resource "google_monitoring_alert_policy" "residency_posture" {
  project      = var.project_id
  display_name = "Hrz5 residency or CMEK posture violation"
  combiner     = "OR"

  conditions {
    display_name = "An Org Policy residency / CMEK constraint denied a create"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.residency_policy_violations.name}\" AND ${local.posture_alert_resource_types}"
      comparison      = "COMPARISON_GT"
      threshold_value = 0
      duration        = "0s"

      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_SUM"
      }
    }
  }

  notification_channels = var.alert_notification_channels

  documentation {
    content   = "Someone tried to create an audit-path resource outside allowed_regions, or without CMEK (org_policy.tf). Treat as a residency incident: identify the principal and the resource before granting an exception."
    mime_type = "text/markdown"
  }
}
