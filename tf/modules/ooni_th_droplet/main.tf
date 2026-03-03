terraform {
  required_providers {
    digitalocean = {
      source  = "digitalocean/digitalocean"
      version = "~> 2.0"
    }
  }
}

data "cloudinit_config" "ooni_th_docker" {
  gzip          = false
  base64_encode = false

  part {
    filename     = "init.cfg"
    content_type = "text/cloud-config"
    content = templatefile("${path.module}/templates/cloud-init-docker.yml", {
      monitoring_ip    = "5.9.112.244",
      deployer_key     = var.deployer_key,
      metrics_password = var.metrics_password,
    })
  }
}

resource "digitalocean_droplet" "ooni_th_docker" {
  image     = "ubuntu-24-04-x64"
  name      = "${var.name}-docker-${var.stage}-${count.index}"
  region    = var.instance_location
  size      = var.instance_size
  ipv6      = true
  ssh_keys  = var.ssh_keys
  user_data = data.cloudinit_config.ooni_th_docker.rendered
  count     = var.droplet_count

  lifecycle {
    create_before_destroy = true
    ignore_changes        = all
  }
}
resource "aws_route53_record" "ooni_th" {
  zone_id = var.dns_zone_ooni_io
  name    = "${each.key}.do.th.${var.stage}.ooni.io"
  type    = "A"
  ttl     = 60
  for_each = {
    for d in digitalocean_droplet.ooni_th_docker : reverse(split("-", d.name))[0] => d.ipv4_address
  }
  records = [each.value]
}
