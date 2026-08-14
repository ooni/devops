terraform {
  required_providers {
    digitalocean = {
      source  = "digitalocean/digitalocean"
      version = "~> 2.0"
    }
  }
}

resource "digitalocean_droplet" "ooni_th" {
  image    = "debian-13-x64"
  name     = "${var.name}-${var.stage}"
  region   = var.instance_location
  size     = var.instance_size
  ipv6     = true
  ssh_keys = var.ssh_keys

  lifecycle {
    create_before_destroy = true
    ignore_changes        = all
  }
}

resource "aws_route53_record" "ooni_th" {
  zone_id = var.dns_zone_ooni_io
  name    = "${var.hostname}.${var.stage}.ooni.io"
  type    = "A"
  ttl     = 60

  records = [digitalocean_droplet.ooni_th.ipv4_address]
}
