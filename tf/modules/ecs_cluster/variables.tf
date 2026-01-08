variable "aws_region" {
  description = "The AWS region to create things in."
  default     = "eu-central-1"
}

variable "key_name" {
  description = "Name of AWS key pair"
}

variable "stage" {
  default = "one of dev, stage, test, prod"
}

variable "vpc_id" {
  description = "the id of the VPC to deploy the instance into"
}

variable "subnet_ids" {
  description = "the ids of the subnet of the subnets to deploy the instance into"
  type        = list(string)
}

variable "tags" {
  description = "tags to apply to the resources"
  default     = {}
  type        = map(string)
}

variable "name" {
  description = "value of the ecs cluster name"
}

variable "asg_min" {
  description = <<EOT
                Min numbers of servers in ASG. Keep in mind the ENI restrictions,
                where small-large have a limit of 3 and micro has a limit of 2.
                This means that if you plan to run 3 tasks in the ECS cluster with a task count of 2,
                you need a minimum of 3  in the ASG
                EOT
  default     = 1
}

variable "asg_max" {
  description = "Max numbers of servers in ASG"
  default     = 6
}

variable "admin_cidr_ingress" {
  default = "0.0.0.0/0"
}

variable "instance_type" {
  default = "t3.small"
}

variable "instance_volume_size" {
  default = "5"
}

variable "monitoring_sg_ids" {
  default = []
  type = list(string)
}

variable "node_exporter_port" {
  default = "9100"
}

variable "monitoring_active" {
  description = "If the monitoring system should consider cluster machines. Set it to 'true' to activate it, anything else to deactivate it"
  default = "true"
  type = string
}
