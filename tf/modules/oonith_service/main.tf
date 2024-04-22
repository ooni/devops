locals {
  name = "oonith-service-${var.service_name}"
  # We construct a stripped name that is without the "ooni" substring and all
  # vocals are stripped.
  stripped_name = replace(replace(var.service_name, "ooni", ""), "[aeiou]", "")
  # Short prefix should be less than 5 characters
  short_prefix = "oo${substr(var.service_name, 0, 3)}"
}

resource "aws_iam_role" "oonith_service_task" {
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

resource "aws_iam_role_policy" "oonith_service_task" {
  name = "${local.name}-task-role"
  role = aws_iam_role.oonith_service_task.name

  policy = templatefile("${path.module}/templates/profile_policy.json", {})
}

resource "aws_cloudwatch_log_group" "oonith_service" {
  name = "ooni-ecs-group/${local.name}"
}


locals {
  container_port = 80
}

data "aws_ecs_task_definition" "oonith_service_current" {
  task_definition = "${local.name}-td"
  count           = var.first_run ? 0 : 1
}

resource "aws_ecs_task_definition" "oonith_service" {
  family = "${local.name}-td"

  network_mode = "awsvpc"

  container_definitions = jsonencode([
    {
      cpu       = var.task_cpu,
      essential = true,
      image = try(
        jsondecode(data.aws_ecs_task_definition.oonith_service_current.0.task_definition).ContainerDefinitions[0].image,
        var.default_docker_image_url
      ),
      memory = var.task_memory,
      name   = local.name,

      portMappings = [
        {
          containerPort = local.container_port,
          hostPort      = local.container_port,
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
          awslogs-group  = aws_cloudwatch_log_group.oonith_service.name,
          awslogs-region = var.aws_region
        }
      }
    }
  ])
  execution_role_arn = aws_iam_role.oonith_service_task.arn
  tags               = var.tags
  track_latest       = true
}

resource "aws_security_group" "oonith_service_ecs" {
  name_prefix = "oonith-service"
  description = "Allow all traffic"
  vpc_id      = var.vpc_id

  ingress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }

  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_ecs_service" "oonith_service" {
  name            = local.name
  cluster         = var.ecs_cluster_id
  task_definition = aws_ecs_task_definition.oonith_service.arn
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
    target_group_arn = aws_alb_target_group.oonith_service_direct.id
    container_name   = local.name
    container_port   = "80"
  }

  network_configuration {
    subnets         = var.private_subnet_ids
    security_groups = [aws_security_group.oonith_service_ecs.id]
  }

  depends_on = [
    aws_alb_listener.oonith_service_http,
  ]

  force_new_deployment = true

  tags = var.tags
}

# The direct
resource "aws_alb_target_group" "oonith_service_direct" {
  name_prefix = "${local.short_prefix}D"
  port        = 80
  protocol    = "HTTP"
  vpc_id      = var.vpc_id
  target_type = "ip"

  lifecycle {
    create_before_destroy = true
  }

  tags = var.tags
}

# TODO(DecFox): Uncomment after we have evaluated how we want to direct 
# traffic from th.{var.stage}.ooni.io to a specific target group

# The mapped target group is used for mapping it in the main TH load balancer
# resource "aws_alb_target_group" "oonith_service_mapped" {
# name     = "${local.name}-mapped"
# port     = 80
# protocol = "HTTP"
# vpc_id   = var.vpc_id

# tags = var.tags
# }

resource "aws_alb" "oonith_service" {
  name            = local.name
  subnets         = var.public_subnet_ids
  security_groups = var.oonith_service_security_groups

  lifecycle {
    create_before_destroy = true
  }

  tags = var.tags
}

resource "aws_alb_listener" "oonith_service_http" {
  load_balancer_arn = aws_alb.oonith_service.id
  port              = "80"
  protocol          = "HTTP"

  default_action {
    target_group_arn = aws_alb_target_group.oonith_service_direct.id
    type             = "forward"
  }

  tags = var.tags
}

resource "aws_alb_listener" "front_end_https" {
  load_balancer_arn = aws_alb.oonith_service.id
  port              = "443"
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-2016-08"
  certificate_arn   = aws_acm_certificate.oonith_service.arn

  default_action {
    target_group_arn = aws_alb_target_group.oonith_service_direct.id
    type             = "forward"
  }

  tags = var.tags
}

resource "aws_route53_record" "oonith_service" {
  zone_id = var.dns_zone_ooni_io
  name    = "${var.service_name}.th.${var.stage}.ooni.io"
  type    = "A"

  alias {
    name                   = aws_alb.oonith_service.dns_name
    zone_id                = aws_alb.oonith_service.zone_id
    evaluate_target_health = true
  }
}

resource "aws_acm_certificate" "oonith_service" {
  domain_name       = "${var.service_name}.th.${var.stage}.ooni.io"
  validation_method = "DNS"

  subject_alternative_names = keys(var.alternative_names)

  tags = var.tags

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_route53_record" "oonith_service_validation" {
  for_each = {
    for dvo in aws_acm_certificate.oonith_service.domain_validation_options : dvo.domain_name => {
      name        = dvo.resource_record_name
      record      = dvo.resource_record_value
      type        = dvo.resource_record_type
      domain_name = dvo.domain_name
    }
  }

  allow_overwrite = true
  name            = each.value.name
  records         = [each.value.record]
  ttl             = 60
  type            = each.value.type
  zone_id         = lookup(var.alternative_names, each.value.domain_name, var.dns_zone_ooni_io)
}

resource "aws_acm_certificate_validation" "oonith_service" {
  certificate_arn         = aws_acm_certificate.oonith_service.arn
  validation_record_fqdns = [for record in aws_route53_record.oonith_service_validation : record.fqdn]
  depends_on = [
    aws_route53_record.oonith_service,
    aws_route53_record.oonith_service_alias
  ]
}

resource "aws_route53_record" "oonith_service_alias" {
  for_each = var.alternative_names

  zone_id = each.value
  name    = each.key
  type    = "A"

  alias {
    name                   = aws_alb.oonith_service.dns_name
    zone_id                = aws_alb.oonith_service.zone_id
    evaluate_target_health = true
  }
}
