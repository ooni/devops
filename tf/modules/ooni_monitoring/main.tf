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