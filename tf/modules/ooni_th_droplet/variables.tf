variable "stage" {
  type = string
}

variable "name" {
  description = "Name of the droplets"
  type        = string
  default     = "ooni-wcth"
}

variable "instance_location" {
  type    = string
  default = "fra1"
}

variable "instance_size" {
  # s-2vcpu-4gb
  type    = string
  default = "s-1vcpu-1gb"
}

variable "droplet_count" {
  default = 1
}

variable "ssh_keys" {
  type = list(string)
}