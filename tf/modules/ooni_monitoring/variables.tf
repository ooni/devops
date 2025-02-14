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
