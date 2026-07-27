job "valkey" {
  type = "service"
  group "valkey" {
    count = 1

    network {
      port "valkey" {
        to = 6379
      }
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
