variable "aws_region" {
  description = "The AWS region to create things in."
  default     = "eu-central-1"
}

variable "vpc_id" {
  description = "the id of the VPC to deploy the pg instance into"
}

variable "subnet_ids" {
  description = "the ids of the subnet of the subnets to deploy the pg instance into"
}

variable "name" {
  default = "name of the postgresql instance"
}

variable "tags" {
  description = "tags to apply to the resources"
  default     = {}
  type        = map(string)
}

variable "pg_db_name" {
  description = "the name of the default db"
  default     = "oonipg"
}

variable "pg_username" {
  description = "the name of the default user"
  default     = "oonipg"
}

variable "db_instance_class" {
  default = "db.t3.micro"
}

variable "db_allocated_storage" {
  default = "10"
}

variable "db_storage_type" {
  default = "standard"
}

variable "db_max_allocated_storage" {
  default = "100"
}

variable "db_engine_version" {
  default = "16.3"
}

variable "db_parameter_group" {
  default = "default.postgres16"
}

variable "allow_cidr_blocks" {
  default = []
}

variable "allow_security_groups" {
  default = []
}

variable "db_multi_az" {
  default = false
}
