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
      - "both"       the ECS deploy, then the blue/green deploy, of the same
                      image. For the migration: the ALB keeps serving the
                      current version until DNS moves to the hosts, and can
                      take traffic back if it has to.
    This is opt-in per service so unmigrated services keep working unchanged.
  EOF
  type        = string
  default     = "ecs"

  validation {
    condition     = contains(["ecs", "blue_green", "both"], var.deploy_mode)
    error_message = "deploy_mode must be \"ecs\", \"blue_green\" or \"both\"."
  }
}

# --- deploy_mode = "ecs" or "both" ---------------------------------------

variable "ecs_cluster_name" {
  description = "id of the cluster to deploy into. Required when deploy_mode is \"ecs\" or \"both\"."
  type        = string
  default     = null
}

variable "ecs_service_name" {
  description = "id of the service in the cluster to deploy. Required when deploy_mode is \"ecs\" or \"both\"."
  type        = string
  default     = null
}

# --- deploy_mode = "blue_green" or "both" --------------------------------

variable "deploy_bucket" {
  description = "S3 bucket that the rendered Quadlet units, the nginx upstream conf snippet, and deploy.py are uploaded to. Required when deploy_mode is \"blue_green\" or \"both\"."
  type        = string
  default     = null
}

variable "host_port_a" {
  description = "Host port bound to the \"a\" deploy slot. Required when deploy_mode is \"blue_green\" or \"both\"."
  type        = number
  default     = null
}

variable "host_port_b" {
  description = "Host port bound to the \"b\" deploy slot. Required when deploy_mode is \"blue_green\" or \"both\"."
  type        = number
  default     = null
}

variable "health_check_timeout" {
  description = "Seconds a new blue/green slot has to pass its /health check twice in a row before the deploy is aborted. The ECS target groups give a new task about 60 s."
  type        = number
  default     = 120
}

variable "drain_timeout" {
  description = "Seconds requests may keep draining from a blue/green slot after it is taken out of rotation; must match ooniapi_gateway_drain_timeout on the hosts. A deploy waits this long after the previous one before restarting that slot. Mirrors the ALB deregistration delay (AWS default, 300 s)."
  type        = number
  default     = 300
}

variable "container_port" {
  description = "Port the service listens on inside the container. Required when deploy_mode is \"blue_green\" or \"both\"."
  type        = number
  default     = null
}

variable "slice" {
  description = "systemd slice the slots run in, which caps their CPU and memory (roles/ooniapi_gateway's ooniapi_gateway_slices), e.g. \"ooniapi-dev.slice\". Empty: the default slice. The slots' network is ooniapi-<service_name>, which the role creates."
  type        = string
  default     = ""
}

variable "env_vars" {
  description = "Cleartext environment variables for the container. Same shape as ooniapi_service's task_environment (map(string)). Baked directly into the rendered Quadlet unit, since none of this is sensitive."
  type        = map(string)
  default     = {}
}

variable "secrets" {
  description = "Names of the keys in var.service_secrets_arn's JSON blob. deploy.py writes them to each slot's env file (root, mode 600), which the rendered Quadlet unit loads: environment variables in the container, where the services' settings read them. Required when deploy_mode is \"blue_green\" or \"both\"."
  type        = list(string)
  default     = []
}

variable "service_secrets_arn" {
  description = "ARN of the Secrets Manager secret holding the service's runtime secrets as a flat JSON key/value object. Every key goes into the slot's env file during deploy (see var.secrets). Required when deploy_mode is \"blue_green\" or \"both\"."
  type        = string
  default     = null
}

variable "deploy_ssh_key_secret_arn" {
  description = "ARN of the Secrets Manager secret holding the SSH private key the deploy CodeBuild job uses to reach the target hosts. Required when deploy_mode is \"blue_green\" or \"both\"."
  type        = string
  default     = null
}

variable "deploy_host_primary" {
  description = "Hostname/IP of the primary dedicated host to deploy to. Required when deploy_mode is \"blue_green\" or \"both\"."
  type        = string
  default     = null
}

variable "deploy_host_secondary" {
  description = "Hostname/IP of the secondary dedicated host to deploy to, after the primary. Optional: without it the service runs on the primary host alone, as dev does."
  type        = string
  default     = null
}

variable "deploy_ssh_user" {
  description = "SSH user the deploy job connects as on the target hosts."
  type        = string
  default     = "deploy"
}
