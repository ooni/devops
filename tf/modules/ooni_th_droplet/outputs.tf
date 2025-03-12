output "droplet_ipv4_address" {
  value = digitalocean_droplet.ooni_th_docker[*].ipv4_address
}

output "droplet_addresses" {
  # for why we use values,
  # see: https://github.com/hashicorp/terraform/issues/23245#issuecomment-548391304
  # https://github.com/hashicorp/terraform/issues/22476
  value = values(aws_route53_record.ooni_th)[*].fqdn
}
