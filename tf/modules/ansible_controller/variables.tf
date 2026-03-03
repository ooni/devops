variable "vpc_id" {
  description = "the id of the VPC to deploy the instance into"
}

variable "subnet_id" {
  description = "the id of the subnet to deploy the instance into"
}


variable "tags" {
  description = "tags to apply to the resources"
  default     = {}
  type        = map(string)
}

variable "key_name" {
  description = "Name of AWS key pair"
}

variable "instance_type" {
  default = "t2.micro"
}

variable "dns_zone_ooni_io" {
  description = "id of the DNS zone for ooni_io"
}

variable "monitoring_sg_ids" {
  description = "Ids of the security groups used for monitoring"
  default     = []
  type        = list(string)
}

variable "monitoring_active" {
  description = "If the monitoring system should consider the ansible controller machine. Set it to 'true' to activate it, anything else to deactivate it"
  default     = "true"
  type        = string
}