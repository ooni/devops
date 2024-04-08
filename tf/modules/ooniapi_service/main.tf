locals {
  name = "ooniapi-service-${var.service_name}"
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


locals {
  container_port = 80
}

data "aws_ecs_task_definition" "ooniapi_service_current" {
  task_definition = "${local.name}-td"
  count           = var.first_run ? 0 : 1
}

resource "aws_ecs_task_definition" "ooniapi_service" {
  family = "${local.name}-td"
  container_definitions = jsonencode([
    {
      cpu       = var.task_cpu,
      essential = true,
      image = try(
        jsondecode(data.aws_ecs_task_definition.ooniapi_service_current.0.task_definition).ContainerDefinitions[0].image,
        var.default_docker_image_url
      ),
      memory = var.task_memory,
      name   = local.name,
      portMappings = [
        {
          containerPort = local.container_port,
          hostPort      = 0
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
  deployment_maximum_percent         = 100

  load_balancer {
    target_group_arn = aws_alb_target_group.ooniapi_service_direct.id
    container_name   = local.name
    container_port   = "80"
  }

  load_balancer {
    target_group_arn = aws_alb_target_group.ooniapi_service_mapped.id
    container_name   = local.name
    container_port   = "80"
  }

  depends_on = [
    aws_alb_listener.ooniapi_service_http,
  ]

  force_new_deployment = true

  tags = var.tags
}

# The direct target group is used for the direct domain name mapping
resource "aws_alb_target_group" "ooniapi_service_direct" {
  name     = "${local.name}-direct"
  port     = 80
  protocol = "HTTP"
  vpc_id   = var.vpc_id

  tags = var.tags
}

# The mapped target group is used for mapping it in the main API load balancer
resource "aws_alb_target_group" "ooniapi_service_mapped" {
  name     = "${local.name}-mapped"
  port     = 80
  protocol = "HTTP"
  vpc_id   = var.vpc_id

  tags = var.tags
}

resource "aws_alb" "ooniapi_service" {
  name            = local.name
  subnets         = var.subnet_ids
  security_groups = var.ooniapi_service_security_groups

  tags = var.tags
}

resource "aws_alb_listener" "ooniapi_service_http" {
  load_balancer_arn = aws_alb.ooniapi_service.id
  port              = "80"
  protocol          = "HTTP"

  default_action {
    target_group_arn = aws_alb_target_group.ooniapi_service_direct.id
    type             = "forward"
  }

  tags = var.tags
}

resource "aws_alb_listener" "front_end_https" {
  load_balancer_arn = aws_alb.ooniapi_service.id
  port              = "443"
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-2016-08"
  certificate_arn   = aws_acm_certificate.ooniapi_service.arn

  default_action {
    target_group_arn = aws_alb_target_group.ooniapi_service_direct.id
    type             = "forward"
  }

  tags = var.tags
}

resource "aws_route53_record" "ooniapi_service" {
  zone_id = var.dns_zone_ooni_io
  name    = "${var.service_name}.api.${var.stage}.ooni.io"
  type    = "A"

  alias {
    name                   = aws_alb.ooniapi_service.dns_name
    zone_id                = aws_alb.ooniapi_service.zone_id
    evaluate_target_health = true
  }
}

resource "aws_acm_certificate" "ooniapi_service" {
  domain_name       = "${var.service_name}.api.${var.stage}.ooni.io"
  validation_method = "DNS"

  tags = var.tags

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_route53_record" "ooniapi_service_validation" {
  for_each = {
    for dvo in aws_acm_certificate.ooniapi_service.domain_validation_options : dvo.domain_name => {
      name   = dvo.resource_record_name
      record = dvo.resource_record_value
      type   = dvo.resource_record_type
    }
  }

  allow_overwrite = true
  name            = each.value.name
  records         = [each.value.record]
  ttl             = 60
  type            = each.value.type
  zone_id         = var.dns_zone_ooni_io
}

resource "aws_acm_certificate_validation" "ooniapi_service" {
  certificate_arn         = aws_acm_certificate.ooniapi_service.arn
  validation_record_fqdns = [for record in aws_route53_record.ooniapi_service_validation : record.fqdn]
  depends_on = [
    aws_route53_record.ooniapi_service
  ]
}
