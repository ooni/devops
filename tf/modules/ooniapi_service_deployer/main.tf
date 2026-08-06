## CodeBuild and CodePipeline for OONI API Services

data "aws_caller_identity" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  env_label  = var.environment == "prod" ? "latest" : "dev"
}

resource "aws_iam_policy" "codebuild" {
  description = "Policy used in trust relationship with CodeBuild"
  name        = "codebuild-${var.service_name}-${var.aws_region}"
  path        = "/service-role/"

  policy = <<POLICY
{
  "Statement": [
    {
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ],
      "Effect": "Allow",
      "Resource": [
        "arn:aws:logs:${var.aws_region}:${local.account_id}:log-group:/aws/codebuild/ooniapi-${var.service_name}",
        "arn:aws:logs:${var.aws_region}:${local.account_id}:log-group:/aws/codebuild/ooniapi-${var.service_name}:*"
      ]
    },
    {
      "Action": [
        "s3:PutObject",
        "s3:GetObject",
        "s3:GetObjectVersion",
        "s3:GetBucketAcl",
        "s3:GetBucketLocation"
      ],
      "Effect": "Allow",
      "Resource": [
        "arn:aws:s3:::codepipeline-ooniapi-${var.aws_region}-*"
      ]
    },
    {
      "Effect": "Allow",
      "Action": [
        "ssmmessages:CreateControlChannel",
        "ssmmessages:CreateDataChannel",
        "ssmmessages:OpenControlChannel",
        "ssmmessages:OpenDataChannel"
      ],
      "Resource": "*"
    },
    {
      "Action": [
        "codebuild:CreateReportGroup",
        "codebuild:CreateReport",
        "codebuild:UpdateReport",
        "codebuild:BatchPutTestCases",
        "codebuild:BatchPutCodeCoverages"
      ],
      "Effect": "Allow",
      "Resource": [
        "arn:aws:codebuild:${var.aws_region}:${local.account_id}:report-group/ooniapi-${var.service_name}-*"
      ]
    },
    {
        "Effect": "Allow",
        "Action": "codestar-connections:UseConnection",
        "Resource": "${var.codestar_connection_arn}"
    }
  ],
  "Version": "2012-10-17"
}
POLICY
}

resource "aws_iam_role" "codebuild" {
  assume_role_policy = <<POLICY
{
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Effect": "Allow",
      "Principal": {
        "Service": "codebuild.amazonaws.com"
      }
    }
  ],
  "Version": "2012-10-17"
}
POLICY

  managed_policy_arns = [
    aws_iam_policy.codebuild.arn,
    "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryFullAccess",
    "arn:aws:iam::aws:policy/SecretsManagerReadWrite"
  ]
  max_session_duration = "3600"
  name                 = "codebuild-ooniapi-${var.service_name}"
  path                 = "/service-role/"
}

resource "aws_codebuild_project" "ooniapi" {
  artifacts {
    encryption_disabled    = "false"
    override_artifact_name = "false"
    type                   = "NO_ARTIFACTS"
  }

  badge_enabled = "false"
  build_timeout = "60"

  cache {
    type = "NO_CACHE"
  }

  concurrent_build_limit = "1"
  encryption_key         = "arn:aws:kms:${var.aws_region}:${local.account_id}:alias/aws/s3"

  environment {
    compute_type                = "BUILD_GENERAL1_SMALL"
    image                       = "aws/codebuild/standard:7.0"
    image_pull_credentials_type = "CODEBUILD"
    privileged_mode             = "true"
    type                        = "LINUX_CONTAINER"

    environment_variable {
      name  = "ENV_LABEL"
      value = local.env_label
    }
  }

  logs_config {
    cloudwatch_logs {
      status = "ENABLED"
    }

    s3_logs {
      encryption_disabled = "false"
      status              = "DISABLED"
    }
  }

  name               = "ooniapi-${var.service_name}"
  project_visibility = "PRIVATE"
  queued_timeout     = "480"
  service_role       = aws_iam_role.codebuild.arn

  source {
    buildspec       = var.buildspec_path
    git_clone_depth = "1"

    git_submodules_config {
      fetch_submodules = "false"
    }

    insecure_ssl        = "false"
    location            = "https://github.com/${var.repo}.git"
    report_build_status = "false"
    type                = "GITHUB"
  }
}

## Podman Quadlet blue/green deploy (deploy_mode = "blue_green")

resource "aws_s3_object" "quadlet_unit" {
  for_each = var.deploy_mode == "blue_green" ? { a = var.host_port_a, b = var.host_port_b } : {}

  bucket       = var.quadlet_units_bucket
  key          = "${var.service_name}/${var.service_name}-${each.key}.container"
  content_type = "text/plain"

  content = templatefile("${path.module}/templates/quadlet.container.tftpl", {
    service_name   = var.service_name
    slot           = each.key
    host_port      = each.value
    container_port = var.container_port
    network_name   = var.network_name
    env_vars       = var.env_vars
    secrets        = var.secrets
  })
}

resource "aws_s3_object" "nginx_upstream" {
  count = var.deploy_mode == "blue_green" ? 1 : 0

  bucket       = var.quadlet_units_bucket
  key          = "${var.service_name}/${var.service_name}-upstream.conf"
  content_type = "text/plain"

  content = templatefile("${path.module}/templates/nginx_upstream.conf.tftpl", {
    service_name = var.service_name
    host_port_a  = var.host_port_a
    host_port_b  = var.host_port_b
  })
}

resource "aws_iam_policy" "deploy" {
  count = var.deploy_mode == "blue_green" ? 1 : 0

  description = "Policy used in trust relationship with the blue/green deploy CodeBuild project"
  name        = "codebuild-deploy-${var.service_name}-${var.aws_region}"
  path        = "/service-role/"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = [
          "arn:aws:logs:${var.aws_region}:${local.account_id}:log-group:/aws/codebuild/ooniapi-${var.service_name}-deploy",
          "arn:aws:logs:${var.aws_region}:${local.account_id}:log-group:/aws/codebuild/ooniapi-${var.service_name}-deploy:*"
        ]
      },
      {
        # required for CodeBuild to read the CodePipeline BuildArtifact
        # (imagedefinitions.json), mirrors the grant on the build role
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:GetObjectVersion",
          "s3:GetBucketAcl",
          "s3:GetBucketLocation"
        ]
        Resource = [
          "arn:aws:s3:::${var.codepipeline_bucket}",
          "arn:aws:s3:::${var.codepipeline_bucket}/*"
        ]
      },
      {
        Effect   = "Allow"
        Action   = ["s3:GetObject"]
        Resource = ["arn:aws:s3:::${var.quadlet_units_bucket}/${var.service_name}/*"]
      },
      {
        Effect = "Allow"
        Action = ["secretsmanager:GetSecretValue"]
        Resource = [
          var.deploy_ssh_key_secret_arn,
          var.service_secrets_arn
        ]
      }
    ]
  })
}

resource "aws_iam_role" "deploy" {
  count = var.deploy_mode == "blue_green" ? 1 : 0

  assume_role_policy = <<POLICY
{
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Effect": "Allow",
      "Principal": {
        "Service": "codebuild.amazonaws.com"
      }
    }
  ],
  "Version": "2012-10-17"
}
POLICY

  managed_policy_arns = [
    aws_iam_policy.deploy[0].arn,
  ]
  max_session_duration = "3600"
  name                 = "codebuild-deploy-ooniapi-${var.service_name}"
  path                 = "/service-role/"
}

resource "aws_codebuild_project" "deploy" {
  count = var.deploy_mode == "blue_green" ? 1 : 0

  badge_enabled          = "false"
  build_timeout          = "20"
  concurrent_build_limit = "1"
  encryption_key         = "arn:aws:kms:${var.aws_region}:${local.account_id}:alias/aws/s3"
  name                   = "ooniapi-${var.service_name}-deploy"
  project_visibility     = "PRIVATE"
  queued_timeout         = "480"
  service_role           = aws_iam_role.deploy[0].arn

  artifacts {
    type = "CODEPIPELINE"
  }

  cache {
    type = "NO_CACHE"
  }

  environment {
    compute_type                = "BUILD_GENERAL1_SMALL"
    image                       = "aws/codebuild/standard:7.0"
    image_pull_credentials_type = "CODEBUILD"
    type                        = "LINUX_CONTAINER"

    environment_variable {
      name  = "SERVICE_NAME"
      value = var.service_name
    }
    environment_variable {
      name  = "HOST_PORT_A"
      value = tostring(var.host_port_a)
    }
    environment_variable {
      name  = "HOST_PORT_B"
      value = tostring(var.host_port_b)
    }
    environment_variable {
      name  = "CONTAINER_PORT"
      value = tostring(var.container_port)
    }
    environment_variable {
      name  = "NETWORK_NAME"
      value = var.network_name
    }
    environment_variable {
      name  = "QUADLET_BUCKET"
      value = var.quadlet_units_bucket
    }
    environment_variable {
      name  = "DEPLOY_HOST_PRIMARY"
      value = var.deploy_host_primary
    }
    environment_variable {
      name  = "DEPLOY_HOST_SECONDARY"
      value = var.deploy_host_secondary
    }
    environment_variable {
      name  = "DEPLOY_SSH_USER"
      value = var.deploy_ssh_user
    }
    environment_variable {
      name  = "SERVICE_SECRETS_ARN"
      value = var.service_secrets_arn
    }
    environment_variable {
      name  = "DEPLOY_SSH_KEY_SECRET_ARN"
      value = var.deploy_ssh_key_secret_arn
    }
  }

  logs_config {
    cloudwatch_logs {
      status = "ENABLED"
    }

    s3_logs {
      encryption_disabled = "false"
      status              = "DISABLED"
    }
  }

  source {
    type      = "CODEPIPELINE"
    buildspec = file("${path.module}/templates/buildspec_deploy.yml")
  }
}

resource "aws_iam_policy" "codepipeline" {
  description = "Policy used in trust relationship with CodePipeline"
  name        = "codepipeline-ooniapi-${var.service_name}"
  path        = "/service-role/"

  policy = templatefile("${path.module}/templates/codepipeline_policy.json", {})
}

resource "aws_iam_role" "codepipeline" {
  assume_role_policy = <<POLICY
{
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Effect": "Allow",
      "Principal": {
        "Service": "codepipeline.amazonaws.com"
      }
    }
  ],
  "Version": "2012-10-17"
}
POLICY

  managed_policy_arns = [
    aws_iam_policy.codepipeline.arn,
  ]
  max_session_duration = "3600"
  name                 = "codepipeline-ooniapi-${var.service_name}"
  path                 = "/service-role/"
}

resource "aws_codepipeline" "ooniapi" {
  name          = "ooniapi-${var.service_name}"
  pipeline_type = "V2"
  role_arn      = aws_iam_role.codepipeline.arn

  artifact_store {
    location = var.codepipeline_bucket
    type     = "S3"
  }

  depends_on = [
    aws_codebuild_project.ooniapi
  ]

  trigger {
    provider_type = "CodeStarSourceConnection"

    git_configuration {
      source_action_name = "Source"

      push {
        branches {
          includes = [var.branch_name]
        }
        file_paths {
          includes = [var.trigger_path]
          excludes = ["**/README.md"]
        }
      }
    }
  }

  stage {
    action {

      name             = "Source"
      category         = "Source"
      namespace        = "SourceVariables"
      output_artifacts = ["SourceArtifact"]
      owner            = "AWS"
      provider         = "CodeStarSourceConnection"
      region           = var.aws_region
      run_order        = "1"
      version          = "1"

      configuration = {
        ConnectionArn        = var.codestar_connection_arn
        FullRepositoryId     = var.repo
        BranchName           = var.branch_name
        DetectChanges        = "true"
        OutputArtifactFormat = "CODEBUILD_CLONE_REF"
      }
    }

    name = "Source"
  }

  stage {
    action {
      category = "Build"

      configuration = {
        ProjectName = "ooniapi-${var.service_name}"
      }

      input_artifacts  = ["SourceArtifact"]
      name             = "Build"
      namespace        = "BuildVariables"
      output_artifacts = ["BuildArtifact"]
      owner            = "AWS"
      provider         = "CodeBuild"
      region           = var.aws_region
      run_order        = "1"
      version          = "1"
    }

    name = "Build"
  }

  stage {
    name = "Deploy"

    dynamic "action" {
      for_each = var.deploy_mode == "ecs" ? [1] : []

      content {
        category = "Deploy"

        configuration = {
          ClusterName = var.ecs_cluster_name
          ServiceName = var.ecs_service_name
        }

        input_artifacts = ["BuildArtifact"]
        name            = "Deploy"
        namespace       = "DeployVariables"
        owner           = "AWS"
        provider        = "ECS"
        region          = var.aws_region
        run_order       = "1"
        version         = "1"
      }
    }

    dynamic "action" {
      for_each = var.deploy_mode == "blue_green" ? [1] : []

      content {
        category = "Build"

        configuration = {
          ProjectName = aws_codebuild_project.deploy[0].name
        }

        input_artifacts = ["BuildArtifact"]
        name            = "Deploy"
        namespace       = "DeployVariables"
        owner           = "AWS"
        provider        = "CodeBuild"
        region          = var.aws_region
        run_order       = "1"
        version         = "1"
      }
    }
  }
}
