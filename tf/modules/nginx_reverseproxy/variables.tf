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

variable "key_name" {
  description = "Name of AWS key pair"
}

variable "name" {
  description = "Name of the resources"
  default     = "ooni-backendproxy"
}

variable "instance_type" {
  default = "t2.micro"
}


variable "proxy_pass_url" {
  description = "URL to pass to the proxy_pass directive"
}

variable "nginx_extra_nginx_config" {
  description = "extra configuration to pass to nginx"
  default     = ""
}
variable "nginx_extra_path_config" {
  description = "extra configuration to pass to nginx"
  default     = ""
}
