data "aws_iam_policy_document" "assume_role" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "AWS"
      identifiers = var.authorized_accounts
    }
  }
}

resource "aws_iam_policy" "oonidevops" {
  name        = "OONIDevopsPolicy"
  path        = "/"
  description = "Policy used by the oonidevops role to perform all terraform and CI/CD related tasks."

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ec2:*",
        "ecs:*",
        "ecr:*",
        "ecr-public:*",
        "rds:*",
        "vpc-lattice:*",
        "appmesh:*",
        "autoscaling:*",
        "application-autoscaling:*",
        "elasticloadbalancing:*",
        "acm:*",
        "cloudformation:*",
        "cloudtrail:*",
        "cloudwatch:*",
        "codebuild:*",
        "codedeploy:*",
        "codepipeline:*",
        "codestar-connections:*",
        "codestar-notifications:*",
        "route53:*",
        "servicediscovery:*",
        "s3:*",
        "ses:*",
        "ssm:*",
        "logs:*",
        "iam:*",
        "dynamodb:*",
        "states:*",
        "organizations:*",
        "secretsmanager:*",
        "cloudhsm:*"
      ],
      "Resource": "*"
    }
  ]
}
EOF

  tags = var.tags
}

resource "aws_iam_role" "oonidevops" {
  name                = "oonidevops"
  assume_role_policy  = data.aws_iam_policy_document.assume_role.json
  managed_policy_arns = [aws_iam_policy.oonidevops.arn]
  tags                = var.tags
}

resource "tls_private_key" "oonidevops" {
  algorithm = "ED25519"
}

resource "aws_key_pair" "oonidevops" {
  key_name   = "oonidevops"
  public_key = tls_private_key.oonidevops.public_key_openssh
  tags       = var.tags
}

resource "aws_secretsmanager_secret" "oonidevops_deploy_key" {
  name = "oonidevops/deploy_key"
  tags = var.tags
}

resource "aws_secretsmanager_secret_version" "oonidevops_deploy_key" {
  secret_id = aws_secretsmanager_secret.oonidevops_deploy_key.id
  secret_string = jsonencode({
    private_key = tls_private_key.oonidevops.private_key_openssh,
    public_key  = tls_private_key.oonidevops.public_key_openssh,
  })
}

