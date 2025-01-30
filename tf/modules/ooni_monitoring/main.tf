resource "aws_iam_user" "ooni_monitoring" {
  name = "oonidevops-monitoring"
}

resource "aws_iam_user_policy" "ooni_monitoring" {
  name = "oonidevops-monitoring-policy"
  user = aws_iam_user.ooni_monitoring.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "ec2:DescribeInstances",
        ]
        Effect   = "Allow"
        Resource = "*"
      },
    ]
  })
}

resource "aws_iam_access_key" "ooni_monitoring" {
  user = aws_iam_user.ooni_monitoring.name
}

resource "aws_ssm_parameter" "ooni_monitoring" {
  name = "/oonidevops/secrets/ooni_monitoring/access_key"
  type = "SecureString"
  value = aws_iam_access_key.ooni_monitoring.id
}

resource "aws_ssm_parameter" "ooni_monitoring" {
  name = "/oonidevops/secrets/ooni_monitoring/secret_key"
  type = "SecureString"
  value = aws_iam_access_key.ooni_monitoring.secret
}