locals {
  name = "scheduled-service-${var.service_name}"
  # We construct a stripped name that is without the "ooni" substring and all
  # vocals are stripped.
  stripped_name = replace(replace(var.service_name, "ooni", ""), "[aeiou]", "")
  # Short prefix should be less than 5 characters
  short_prefix = "O${substr(local.stripped_name, 0, 3)}"
}

resource "aws_iam_role" "scheduled_service_task" {
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

resource "aws_iam_role_policy" "scheduled_service_task" {
  name = "${local.name}-task-role"
  role = aws_iam_role.scheduled_service_task.name

  policy = templatefile("${path.module}/templates/profile_policy.json", {})
}

resource "aws_iam_role" "events_run_task" {
  name = "${local.name}-events-run-task-role"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"Service": "events.amazonaws.com"},
    "Action": "sts:AssumeRole"
  }]
}
EOF

  tags = var.tags
}

resource "aws_iam_role_policy" "events_run_task_policy" {
  name = "${local.name}-events-run-task-policy"
  role = aws_iam_role.events_run_task.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ecs:RunTask",
          "iam:PassRole",
          "ecs:StartTask",
          "ecs:DescribeClusters",
          "ecs:DescribeTasks",
          "events:TagResource",
          "events:PutRule",
          "events:PutTargets",
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_cloudwatch_event_rule" "scheduled_run" {
  name                = "${local.name}-schedule"
  schedule_expression = var.schedule_expression
  tags                = var.tags
}

resource "aws_cloudwatch_event_target" "run_ecs_task" {
  rule = aws_cloudwatch_event_rule.scheduled_run.name
  arn  = data.aws_ecs_cluster.target.arn

  role_arn = aws_iam_role.events_run_task.arn

  ecs_target {
    task_definition_arn = aws_ecs_task_definition.scheduled_service.arn
    task_count          = 1
  }
}

data "aws_ecs_cluster" "target" {
  cluster_name = var.scheduled_task_cluster
}

resource "aws_cloudwatch_log_group" "scheduled_service" {
  name = "ooni-ecs-group/${local.name}"
}

// This is done to retrieve the image name of the current task definition
// It's important to keep aligned the container_name and task_definitions
data "aws_ecs_container_definition" "scheduled_service_current" {
  task_definition = "${local.name}-td"
  container_name  = local.name
  count           = var.first_run ? 0 : 1
}

resource "aws_ecs_task_definition" "scheduled_service" {
  family       = "${local.name}-td"
  network_mode = "bridge"

  container_definitions = jsonencode([
    {
      memoryReservation = var.task_memory,
      memory            = var.memory_hard_limit
      essential         = true,
      image = try(
        data.aws_ecs_container_definition.scheduled_service_current[0].image,
        var.default_docker_image_url
      ),
      name = local.name,

      environment = [
        for k, v in var.task_environment : {
          name  = k,
          value = v
        }
      ],
      secrets = [
        for k, v in var.task_secrets : {
          name      = k,
          valueFrom = v
        }
      ],
      logConfiguration = {
        logDriver = "awslogs",
        options = {
          awslogs-group  = aws_cloudwatch_log_group.scheduled_service.name,
          awslogs-region = var.aws_region
        }
      }
    }
  ])
  task_role_arn      = aws_iam_role.scheduled_service_task.arn
  execution_role_arn = aws_iam_role.scheduled_service_task.arn
  tags               = var.tags
  track_latest       = true
}
