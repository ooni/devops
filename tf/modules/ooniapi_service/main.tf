locals {
  name = "ooniapi-service-${var.service_name}"
  # We construct a stripped name that is without the "ooni" substring and all
  # vocals are stripped.
  stripped_name = replace(replace(var.service_name, "ooni", ""), "[aeiou]", "")
  # Short prefix should be less than 5 characters
  short_prefix = "O${substr(local.stripped_name, 0, 3)}"
}

resource "aws_iam_role" "ooniapi_service_task" {
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

resource "aws_iam_role_policy" "ooniapi_service_task" {
  name = "${local.name}-task-role"
  role = aws_iam_role.ooniapi_service_task.name

  policy = templatefile("${path.module}/templates/profile_policy.json", {})
}

resource "aws_cloudwatch_log_group" "ooniapi_service" {
  name = "ooni-ecs-group/${local.name}"
}

// This is done to retrieve the image name of the current task definition
// It's important to keep aligned the container_name and task_definitions
data "aws_ecs_container_definition" "ooniapi_service_current" {
  task_definition = "${local.name}-td"
  container_name  = local.name
  count           = var.first_run ? 0 : 1
}

resource "aws_ecs_task_definition" "ooniapi_service" {
  family       = "${local.name}-td"
  network_mode = "bridge"

  container_definitions = jsonencode([
    {
      memoryReservation = var.task_memory,
      essential         = true,
      image = try(
        data.aws_ecs_container_definition.ooniapi_service_current[0].image,
        var.default_docker_image_url
      ),
      name = local.name,

      portMappings = [
        {
          containerPort = 80
        }
      ],

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
          awslogs-group  = aws_cloudwatch_log_group.ooniapi_service.name,
          awslogs-region = var.aws_region
        }
      }
    }
  ])
  execution_role_arn = aws_iam_role.ooniapi_service_task.arn
  tags               = var.tags
  track_latest       = true
}

resource "aws_ecs_service" "ooniapi_service" {
  name            = local.name
  cluster         = var.ecs_cluster_id
  task_definition = aws_ecs_task_definition.ooniapi_service.arn
  desired_count   = var.service_desired_count

  deployment_minimum_healthy_percent = 50
  deployment_maximum_percent         = 200

  ordered_placement_strategy {
    type  = "spread"
    field = "attribute:ecs.availability-zone"
  }

  ordered_placement_strategy {
    type  = "spread"
    field = "instanceId"
  }

  load_balancer {
    target_group_arn = aws_alb_target_group.ooniapi_service.id
    container_name   = local.name
    container_port   = "80"
  }

  lifecycle {
    create_before_destroy = true
  }

  force_new_deployment = true

  tags = var.tags
}

resource "aws_alb_target_group" "ooniapi_service" {
  name_prefix = "${local.short_prefix}M-"
  port        = 80
  protocol    = "HTTP"
  vpc_id      = var.vpc_id
  target_type = "instance"

  lifecycle {
    create_before_destroy = true
  }

  tags = var.tags
}
