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

variable "oonidataapi_target_group_arn" {
  description = "aws_alb_target_group.oonidataapi.id"
}

variable "dns_zone_ooni_io" {
  description = "id of the DNS zone for ooni_io"
}

variable "stage" {
  description = "dev, test, prod label for the stage"
}
