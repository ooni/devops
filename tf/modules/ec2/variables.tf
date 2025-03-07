variable "vpc_id" {
  description = "the id of the VPC to deploy the instance into"
}

variable "subnet_id" {
  description = "the ids of the subnet to deploy the instance into"
}

variable "private_subnet_cidr" {
  description = "the cidr block of the private subnet to allow traffic from for the clickhouse proxy"
}

 variable "tags" {
  description = "tags to apply to the resources"
  default     = {}
  type        = map(string)
}

variable "key_name" {
  description = "Name of AWS key pair"
}

variable "name" {
  description = "Name of the resources"
}

variable "instance_type" {
  default = "t2.micro"
}

variable "stage" {
  default = "one of dev, stage, test, prod"
}

variable "dns_zone_ooni_io" {
  description = "id of the DNS zone for ooni_io"
}

variable "sg_prefix" {
    description = "security group prefix"
}

variable "ingress_rules" {
  type = list(object({
      from_port   = number
      to_port     = number
      protocol    = string
      cidr_blocks = list(string)
      ipv6_cidr_blocks = optional(list(string))
    }))
}

variable "egress_rules" {
  type = list(object({
      from_port   = number
      to_port     = number
      protocol    = string
      cidr_blocks = optional(list(string))
      ipv6_cidr_blocks = optional(list(string))
    }))
}

variable "tg_prefix" {
    description = "target group prefix. Will be prefixed with `oo`, example: bkprx -> oobkprx"
}

variable "monitoring_active" {
  description = "If the monitoring system should consider this machine. Set it to 'true' to activate it, anything else to deactivate it"
  default = "true"
  type = string
}