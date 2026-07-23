job "${service_name}" {
  type = "service"
  group "${service_name}" {
    count = ${desired_count}
    network {
      port "${service_name}" {
        static = ${port}
        to     = 80
      }
    }
    service {
      name     = "${service_name}"
      port     = "${service_name}"
      provider = "nomad"

      check {
        type     = "http"
        path     = "/health"
        interval = "15s"
        timeout  = "5s"
      }
    }

    task "${service_name}-task" {
      driver = "podman"
      config {
        image = "${docker_image}"
        ports = ["${service_name}"]
      }

%{ if length(secret_keys) > 0 }
      template {
        data        = <<-EOH
        {{ with nomadVar "nomad/jobs/${service_name}" }}
%{ for key in secret_keys ~}
        ${key}={{ .${key} }}
%{ endfor ~}
        {{ end }}
        EOH
        destination = "secrets/env.txt"
        env         = true
      }
%{ endif }

      env {
%{ for key, value in env_vars ~}
        ${key} = "${value}"
%{ endfor ~}
      }

      resources {
        memory = ${task_memory}
      }
    }
  }
}
