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

// This is done to retrieve the image name of the current task definition
// It's important to keep aligned the container_name and task_definitions
data "aws_ecs_container_definition" "oonith_service_current" {
  task_definition = "${local.name}-td"
  container_name  = local.name
  count           = var.first_run ? 0 : 1
}

resource "aws_ecs_task_definition" "oonith_service" {
  family = "${local.name}-td"

  network_mode = "bridge"

  container_definitions = jsonencode([
    {
      cpu       = var.task_cpu,
      essential = true,
      image = try(
        data.aws_ecs_container_definition.oonith_service_current[0].image,
        var.default_docker_image_url
      ),
      memory = var.task_memory,
      name   = local.name,

      portMappings = [
        {
          containerPort = local.container_port,
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
  target_type = "instance"

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
  name_prefix     = "ooth"
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

module "oonith_nginx_cache" {
  source = "../nginx_reverseproxy"

  vpc_id        = var.vpc_id
  subnet_ids    = var.public_subnet_ids
  key_name      = var.key_name
  instance_type = "t2.micro"
  tags          = var.tags

  name                     = "oonith-nginx-cache"
  proxy_pass_url           = "http://${aws_alb.oonith_service.dns_name}/"
  nginx_extra_path_config  = <<EOT
      proxy_cache thcache;
      proxy_cache_min_uses 1;
      proxy_cache_lock on;
      proxy_cache_lock_timeout 30;
      proxy_cache_lock_age 30;
      proxy_cache_use_stale error timeout invalid_header updating;
      # Cache POST without headers set by the test helper!
      proxy_cache_methods POST;
      proxy_cache_key "\$request_uri|\$request_body";
      proxy_cache_valid 200 10m;
      proxy_cache_valid any 0;
      add_header X-Cache-Status \$upstream_cache_status;
      EOT
  nginx_extra_nginx_config = "proxy_cache_path /var/cache/nginx levels=1:2 keys_zone=thcache:100M max_size=5g inactive=24h use_temp_path=off;"
}

resource "aws_alb" "front_end" {
  name_prefix     = "front"
  subnets         = var.public_subnet_ids
  security_groups = var.oonith_service_security_groups

  tags = var.tags
}

resource "aws_alb_listener" "front_end_http" {
  load_balancer_arn = aws_alb.front_end.id
  port              = "80"
  protocol          = "HTTP"

  default_action {
    target_group_arn = module.oonith_nginx_cache.alb_target_group_id
    type             = "forward"
  }

  tags = var.tags
}

resource "aws_alb_listener" "front_end_https" {
  load_balancer_arn = aws_alb.front_end.id
  port              = "443"
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-2016-08"
  certificate_arn   = aws_acm_certificate.oonith_service.arn

  default_action {
    target_group_arn = module.oonith_nginx_cache.alb_target_group_id
    type             = "forward"
  }

  tags = var.tags
}

resource "aws_route53_record" "oonith_service" {
  zone_id = var.dns_zone_ooni_io
  name    = "${var.service_name}.th.${var.stage}.ooni.io"
  type    = "A"

  alias {
    name                   = aws_alb.front_end.dns_name
    zone_id                = aws_alb.front_end.zone_id
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
    name                   = aws_alb.front_end.dns_name
    zone_id                = aws_alb.front_end.zone_id
    evaluate_target_health = true
  }
}
