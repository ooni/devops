locals {
  name = "ecs-service-discovery-${var.environment}"

  tags = {
    Name = local.name
    Environment = var.environment
  }
}
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

resource "aws_ssm_parameter" "ooni_monitoring_access_key" {
  name = "/oonidevops/secrets/ooni_monitoring/access_key"
  type = "SecureString"
  value = aws_iam_access_key.ooni_monitoring.id
}

resource "aws_ssm_parameter" "ooni_monitoring_secret_key" {
  name = "/oonidevops/secrets/ooni_monitoring/secret_key"
  type = "SecureString"
  value = aws_iam_access_key.ooni_monitoring.secret
}

resource "aws_ecs_task_definition" "ooni_service_discovery" {
  family       = "ecs-sd-td"
  network_mode = "bridge"

  container_definitions = jsonencode([
    {
      memoryReservation = var.task_memory,
      essential         = true,
      image = "apptality/aws-ecs-cloudmap-prometheus-discovery:latest",
      name = local.name,

      portMappings = [
        {
          containerPort = 9001
          protocol = "tcp"
        }
      ],

      environment = [
        {
          name = "AWS_REGION"
          value = var.aws_region
        }
      ]
      secrets = [
        for k, v in var.task_secrets : {
          name      = k,
          valueFrom = v
        }
      ],
      logConfiguration = {
        logDriver = "awslogs",
        options = {
          awslogs-group  = aws_cloudwatch_log_group.ooni_ecs_sd.name,
          awslogs-region = var.aws_region
        }
      }
    }
  ])
  
  # TODO I think this should have its own role
  task_role_arn = aws_iam_role.ecs_sd_task.arn
  execution_role_arn = aws_iam_role.ecs_sd_task.arn
  tags               = var.tags
  track_latest       = true
}

resource "aws_ecs_service" "service" {
  name            = local.name
  cluster         = var.cluster_id
  launch_type     = "EC2"
  task_definition = aws_ecs_task_definition.ooni_service_discovery.id
  desired_count   = 1

  # Required to SSH into the container
  enable_execute_command = true

  # Below are required to enforce a new deployment to be ready before the old one is stopped
  deployment_minimum_healthy_percent = 0
  deployment_maximum_percent         = 100

  # lifecycle {
  #   ignore_changes = [
  #     desired_count
  #   ]
  # }

  tags = var.tags
}

resource "aws_iam_role" "ecs_sd_task" {
  name = "${local.name}-task-role"

  tags = var.tags

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "",
      "Effect": "Allow",
      "Principal": {
        "Service": "ecs-tasks.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF
}

resource "aws_cloudwatch_log_group" "ooni_ecs_sd" {
  name = "ooni-ecs-group/${local.name}"
}