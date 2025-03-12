variable "vpc_id" {
  description = "the id of the VPC to deploy the instance into"
}

variable "subnet_ids" {
  description = "the ids of the subnet of the subnets to deploy the instance into"
}

variable "tags" {
  description = "tags to apply to the resources"
  default     = {}
  type        = map(string)
}

variable "oonibackend_proxy_target_group_arn" {
  description = "aws_alb_target_group.oonibackend_proxy.id"
}

variable "ooniapi_oonirun_target_group_arn" {
  description = "arn for the target group of the oonirun service"
}

variable "ooniapi_ooniauth_target_group_arn" {
  description = "arn for the target group of the ooniauth service"
}

variable "ooniapi_ooniprobe_target_group_arn" {
  description = "arn for the target group of the ooniprobe service"
}

variable "ooniapi_oonifindings_target_group_arn" {
  description = "arn for the target group of the oonifindings service"
}

variable "ooniapi_oonimeasurements_target_group_arn" {
  description = "arn for the target group of the oonimeasurements service"
  default     = null
}

variable "dns_zone_ooni_io" {
  description = "id of the DNS zone for ooni_io"
}

variable "stage" {
  description = "dev, test, prod label for the stage"
}

variable "ooniapi_service_security_groups" {
  description = "the shared web security group from the ecs cluster"
  type        = list(string)
}

variable "oonith_domains" {
  type    = list(string)
  default = ["*.th.dev.ooni.io"]
}

variable "ooniapi_acm_certificate_arn" {
  type = string
}
