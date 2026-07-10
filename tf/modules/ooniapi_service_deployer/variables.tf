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

variable "repo" {
  default = "ooni/backend"
}

variable "trigger_path" {
  description = "path filter for push changes which trigger the codepipeline eg. ooniapi/services/oonirun/**"
}

variable "environment" {
  description = "Deployment environment (e.g., prod, dev)"
  type        = string
}

variable "deploy_mode" {
  description = <<-EOF
    Which Deploy stage implementation the pipeline uses:
      - "ecs"        (default) the existing ECS rolling-deploy stage.
      - "blue_green" Podman Quadlet blue/green deploy to dedicated Hetzner
                      hosts, driven by a CodeBuild "Deploy" action over SSH.
    This is opt-in per service so unmigrated services keep working unchanged.
  EOF
  type        = string
  default     = "ecs"

  validation {
    condition     = contains(["ecs", "blue_green"], var.deploy_mode)
    error_message = "deploy_mode must be either \"ecs\" or \"blue_green\"."
  }
}

# --- deploy_mode = "ecs" -----------------------------------------------

variable "ecs_cluster_name" {
  description = "id of the cluster to deploy into. Required when deploy_mode = \"ecs\"."
  type        = string
  default     = null
}

variable "ecs_service_name" {
  description = "id of the service in the cluster to deploy. Required when deploy_mode = \"ecs\"."
  type        = string
  default     = null
}

# --- deploy_mode = "blue_green" -----------------------------------------

variable "quadlet_units_bucket" {
  description = "S3 bucket that rendered Quadlet unit files and the nginx upstream conf snippet are uploaded to. Required when deploy_mode = \"blue_green\"."
  type        = string
  default     = null
}

variable "host_port_a" {
  description = "Host port bound to the \"a\" deploy slot. Required when deploy_mode = \"blue_green\"."
  type        = number
  default     = null
}

variable "host_port_b" {
  description = "Host port bound to the \"b\" deploy slot. Required when deploy_mode = \"blue_green\"."
  type        = number
  default     = null
}

variable "container_port" {
  description = "Port the service listens on inside the container. Required when deploy_mode = \"blue_green\"."
  type        = number
  default     = null
}

variable "network_name" {
  description = "Podman network the service's containers attach to. Required when deploy_mode = \"blue_green\"."
  type        = string
  default     = null
}

variable "secrets" {
  description = "Names of Podman secrets (created/updated on the host during deploy) to mount into the container. Values live in var.service_secrets_arn."
  type        = list(string)
  default     = []
}

variable "env_vars" {
  description = "Cleartext environment variables for the container. Same shape as ooniapi_service's task_environment (map(string))."
  type        = map(string)
  default     = {}
}

variable "service_secrets_arn" {
  description = "ARN of the Secrets Manager secret holding the service's runtime secrets as a flat JSON key/value object. Each key is pushed to the target hosts as a Podman secret during deploy. Required when deploy_mode = \"blue_green\"."
  type        = string
  default     = null
}

variable "deploy_ssh_key_secret_arn" {
  description = "ARN of the Secrets Manager secret holding the SSH private key the deploy CodeBuild job uses to reach the target hosts. Required when deploy_mode = \"blue_green\"."
  type        = string
  default     = null
}

variable "deploy_host_primary" {
  description = "Hostname/IP of the primary dedicated host to deploy to. Required when deploy_mode = \"blue_green\"."
  type        = string
  default     = null
}

variable "deploy_host_secondary" {
  description = "Hostname/IP of the secondary dedicated host to deploy to. Required when deploy_mode = \"blue_green\"."
  type        = string
  default     = null
}

variable "deploy_ssh_user" {
  description = "SSH user the deploy job connects as on the target hosts."
  type        = string
  default     = "deploy"
}
