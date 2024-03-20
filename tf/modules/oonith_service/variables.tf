variable "aws_region" {
  description = "The AWS region to create things in."
  default     = "eu-central-1"
}

variable "key_name" {
  description = "Name of AWS key pair"
}

variable "service_name" {
  description = "short service name. will become the first part of the fqdn eg. <service_name>.prod.ooni.io"
}

variable "stage" {
  default = "one of dev, stage, test, prod"
}

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

variable "service_desired_count" {
  description = "Desired numbers of instances in the ecs service"
  default     = 2
}

variable "task_cpu" {
  default     = 256
  description = "https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task_definition_parameters.html#task_size"
}

variable "task_memory" {
  default     = 512
  description = "https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task_definition_parameters.html#task_size"
}

variable "dns_zone_ooni_io" {
  description = "id of the DNS zone for ooni_io"
}

variable "default_docker_image_url" {
  description = "the url to the default docker image unless there is one already defined in the task definition"
}

variable "ecs_cluster_id" {
  description = "id of the cluster to deploy into"
}

variable "task_secrets" {
  default = {}
  type    = map(string)
}

variable "task_environment" {
  default = {}
  type    = map(string)
}

variable "oonith_service_security_groups" {
  description = "the shared web security group from the ecs cluster"
  type        = list(string)
}
