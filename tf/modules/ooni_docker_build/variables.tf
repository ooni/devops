variable "aws_region" {
  description = "The AWS region to create things in."
  default     = "eu-central-1"
}

variable "service_name" {
  description = "short service name. will become the first part of the fqdn eg. <service_name>.prod.ooni.io"
}

variable "buildspec_path" {
  description = "relative path in the repo to the buildspec eg. api/fastapi/buildspec.yml"
}

variable "codepipeline_bucket" {
  description = "specify a unique bucket to store build artifacts"
}

variable "codestar_connection_arn" {
}

variable "branch_name" {
  default = "main"
}

variable "trigger_tag" {
  description = "tag filters to use to trigger pipeline eg. release-1.0"
}

variable "repo" {
  default = "ooni/backend"
}

variable "ecs_cluster_name" {
  description = "id of the cluster to deploy into"
}

variable "ecs_service_name" {
  description = "id of the service in the cluster to deploy"
}


variable "trigger_path" {
  description = "path filter for push changes which trigger the codepipeline eg. ooniapi/services/oonirun/**"
}