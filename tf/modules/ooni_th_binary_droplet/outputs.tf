output "droplet_ipv4_address" {
  value = digitalocean_droplet.ooni_th.ipv4_address
}

output "fqdn" {
  value = aws_route53_record.ooni_th.fqdn
}
