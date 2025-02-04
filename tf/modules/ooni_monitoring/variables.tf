variable "tags" {
  description = "tags to apply to the resources"
  default     = {}
  type        = map(string)
}

variable "environment" {
  type = string
}

variable "task_memory" {
  description = "How much memory to allocate for this task"
  type = number
  default = 64
}

variable "aws_region" {
  description = "AWS region"
  type = string
}

variable "task_secrets" {
  type = map(string)
  default = {}
}

variable "cluster_id" {
  type = string
}

variable "cluster_name" {
  type = string
}