variable "stage" {
  type = string
}

variable "name" {
  description = "Name of the droplet (will be suffixed with -<stage>)"
  type        = string
}

variable "hostname" {
  description = "DNS label for the helper, e.g. \"json.th\" or \"echo.th\". The record is created as <hostname>.<stage>.ooni.io"
  type        = string
}

variable "instance_location" {
  type    = string
  default = "fra1"
}

variable "instance_size" {
  type    = string
  default = "s-1vcpu-1gb"
}

variable "ssh_keys" {
  description = "Fingerprints of the DigitalOcean account SSH keys to grant root access to"
  type        = list(string)
}

variable "dns_zone_ooni_io" {
  description = "id of the DNS zone for ooni_io"
  type        = string
}
