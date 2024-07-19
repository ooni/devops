locals {
  name = "ooni-tier0-api-frontend"
}

resource "aws_alb" "ooniapi" {
  name            = local.name
  subnets         = var.subnet_ids
  security_groups = var.ooniapi_service_security_groups

  tags = var.tags
}

resource "aws_alb_listener" "ooniapi_listener_http" {
  load_balancer_arn = aws_alb.ooniapi.id
  port              = "80"
  protocol          = "HTTP"

  default_action {
    type = "redirect"

    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }

  tags = var.tags
}

resource "aws_alb_listener" "ooniapi_listener_https" {
  load_balancer_arn = aws_alb.ooniapi.id
  port              = "443"
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-2016-08"
  certificate_arn   = aws_acm_certificate_validation.ooniapi.certificate_arn

  default_action {
    target_group_arn = var.oonibackend_proxy_target_group_arn
    type             = "forward"
  }

  tags = var.tags
}

resource "aws_lb_listener_rule" "ooniapi_oonirun_rule" {
  listener_arn = aws_alb_listener.ooniapi_listener_https.arn
  priority     = 100

  action {
    type             = "forward"
    target_group_arn = var.ooniapi_oonirun_target_group_arn
  }

  condition {
    path_pattern {
      values = ["/api/v2/oonirun/*"]
    }
  }
}

resource "aws_lb_listener_rule" "ooniapi_ooniauth_rule" {
  listener_arn = aws_alb_listener.ooniapi_listener_https.arn
  priority     = 101

  action {
    type             = "forward"
    target_group_arn = var.ooniapi_ooniauth_target_group_arn
  }

  condition {
    path_pattern {
      values = [
        "/api/v2/ooniauth/*",
        "/api/v1/user_register",
        "/api/v1/user_login",
        "/api/v1/user_refresh_token",
        "/api/_/account_metadata",
      ]
    }
  }
}

resource "aws_lb_listener_rule" "ooniapi_ooniprobe_rule" {
  listener_arn = aws_alb_listener.ooniapi_listener_https.arn
  priority     = 102

  action {
    type             = "forward"
    target_group_arn = var.ooniapi_ooniprobe_target_group_arn
  }

  condition {
    path_pattern {
      values = [
        "/api/v2/ooniprobe/*",
      ]
    }
  }
}

resource "aws_lb_listener_rule" "ooniapi_oonifindings_rule" {
  listener_arn = aws_alb_listener.ooniapi_listener_https.arn
  priority     = 100

  action {
    type             = "forward"
    target_group_arn = var.ooniapi_oonifindings_target_group_arn
  }

  condition {
    path_pattern {
      values = ["/api/v1/incidents/*"]
    }
  }
}

## DNS

resource "aws_route53_record" "ooniapi" {
  zone_id = var.dns_zone_ooni_io
  name    = "api.${var.stage}.ooni.io"
  type    = "A"

  alias {
    name                   = aws_alb.ooniapi.dns_name
    zone_id                = aws_alb.ooniapi.zone_id
    evaluate_target_health = true
  }
}

resource "aws_acm_certificate" "ooniapi" {
  domain_name       = "api.${var.stage}.ooni.io"
  validation_method = "DNS"

  tags = var.tags

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_route53_record" "ooniapi_cert_validation" {
  for_each = {
    for dvo in aws_acm_certificate.ooniapi.domain_validation_options : dvo.domain_name => {
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

resource "aws_acm_certificate_validation" "ooniapi" {
  certificate_arn         = aws_acm_certificate.ooniapi.arn
  validation_record_fqdns = [for record in aws_route53_record.ooniapi_cert_validation : record.fqdn]
}
