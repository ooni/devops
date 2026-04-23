variable "name" {
  description = "Short name used for the instance and DNS record (e.g. 'fastpath' or 'fastpath2')"
  type        = string
}

variable "env" {
  description = "Deployment environment, used for the ec2 module stage and the DNS record (e.g. dev, prod)"
  type        = string
}

variable "vpc_id" {
  description = "ID of the VPC"
  type        = string
}

variable "subnet_id" {
  description = "ID of the subnet to deploy the instance into"
  type        = string
}

variable "private_subnet_cidr" {
  description = "CIDR blocks of the private subnets"
  type        = list(string)
}

variable "public_subnet_cidr" {
  description = "CIDR blocks of the public subnets"
  type        = list(string)
}

variable "dns_zone_ooni_io" {
  description = "Route53 zone id for ooni.io"
  type        = string
}

variable "key_name" {
  description = "Name of the AWS key pair"
  type        = string
}

variable "instance_type" {
  description = "EC2 instance type"
  type        = string
  default     = "t3a.small"
}

variable "disk_size" {
  description = "Root disk size in GB"
  type        = number
  default     = 150
}

variable "sg_prefix" {
  description = "Security group name prefix"
  type        = string
}

variable "tg_prefix" {
  description = "ALB target group name prefix (prefixed with 'oo')"
  type        = string
}

variable "monitoring_proxy_private_ip" {
  description = "Private IP of the monitoring proxy, allowed to scrape metrics on ports 9100 and 9102"
  type        = string
}

variable "monitoring_proxy_public_ip" {
  description = "Public IP of the monitoring proxy, allowed to scrape fastpath metrics on port 9102"
  type        = string
}

variable "tags" {
  description = "Extra tags to apply to the resources"
  type        = map(string)
  default     = {}
}
