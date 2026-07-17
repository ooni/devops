job "oonimeasurements" {
  type = "service"
  group "oonimeasurements" {
    count = ${desired_count}
    network {
      port "oonimeasurements" {
        static = ${port}
        to = 80
      }
    }
    service {
      name     = "oonimeasurements"
      port     = "oonimeasurements"
      provider = "nomad"

      // Health checks
      check {
        type     = "http"
        path     = "/health"
        interval = "15s"
        timeout  = "5s"
      }
    }
    task "oonimeasurements-task" {
      driver = "docker"
      config {
        image = "${docker_image}"
        ports = ["oonimeasurements"]
      }
      // Secrets go here
      template {
        data        = <<-EOH
        {{ with nomadVar "nomad/jobs/oonimeasurements" }}
        POSTGRESQL_URL={{ .POSTGRESQL_URL }}
        JWT_ENCRYPTION_KEY={{ .JWT_ENCRYPTION_KEY }}
        PROMETHEUS_METRICS_PASSWORD={{ .PROMETHEUS_METRICS_PASSWORD }}
        CLICKHOUSE_URL={{ .CLICKHOUSE_URL }}
        ACCOUNT_ID_HASHING_KEY={{ .ACCOUNT_ID_HASHING_KEY }}
        {{ end }}
        EOH
        destination = "secrets/env.txt"
        env         = true
      }
      // Normal envs go here
      env {
        OTHER_COLLECTORS                = "${other_collectors}"
        BASE_URL                        = "${base_url}"
        S3_BUCKET_NAME                  = "${s3_bucket_name}"
        VALKEY_URL                      = "${valkey_url}"
        RATE_LIMITS                     = "${rate_limits}"
        RATE_LIMITS_WHITELISTED_IPADDRS = "${rate_limits_whitelisted}"
        RATE_LIMITS_UNMETERED_PAGES     = "${rate_limits_unmetered}"
      }
      resources {
        memory = ${task_memory}
      }
    }
  }
}
