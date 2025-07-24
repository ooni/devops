## CodeBuild and CodePipeline for OONI API Services

data "aws_caller_identity" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
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
        "arn:aws:logs:${var.aws_region}:${local.account_id}:log-group:/aws/codebuild/oonidkr-${var.service_name}",
        "arn:aws:logs:${var.aws_region}:${local.account_id}:log-group:/aws/codebuild/oonidkr-${var.service_name}:*"
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
        "arn:aws:codebuild:${var.aws_region}:${local.account_id}:report-group/oonidkr-${var.service_name}-*"
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
  name                 = "codebuild-oonidkr-${var.service_name}"
  path                 = "/service-role/"
}

resource "aws_codebuild_project" "oonidkr" {
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

  name               = "oonidkr-${var.service_name}"
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

resource "aws_iam_policy" "codepipeline" {
  description = "Policy used in trust relationship with CodePipeline"
  name        = "codepipeline-oonidkr-${var.service_name}"
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
  name                 = "codepipeline-oonidkr-${var.service_name}"
  path                 = "/service-role/"
}

resource "aws_codepipeline" "oonidkr" {
  name          = "oonidkr-${var.service_name}"
  pipeline_type = "V2"
  role_arn      = aws_iam_role.codepipeline.arn

  artifact_store {
    location = var.codepipeline_bucket
    type     = "S3"
  }

  depends_on = [
    aws_codebuild_project.oonidkr
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
        ProjectName = "oonidkr-${var.service_name}"
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
}
