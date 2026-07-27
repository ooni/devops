job "valkey" {
  type = "service"
  group "valkey" {
    count = 1

    network {
      port "valkey" {
        to = 6379
      }
    }

    update {
      max_parallel      = 1
      canary            = 1
      min_healthy_time  = "10s"
      healthy_deadline  = "3m"
      progress_deadline = "5m"
      auto_revert       = true
      auto_promote      = true
    }

    task "valkey-task" {
      driver = "docker"
      config {
        image = "docker.io/valkey/valkey:8"
        ports = ["valkey"]
      }

      service {
        name         = "valkey-svc"
        port         = "valkey"
        provider     = "nomad"
        address_mode = "driver"

        check {
          type     = "tcp"
          interval = "10s"
          timeout  = "2s"
        }
      }

      resources {
        memory = 256
      }
    }
  }
}
