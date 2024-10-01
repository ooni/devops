locals {
  name                 = "ooni-tier0-api-frontend"
  direct_domain_suffix = "${var.stage}.ooni.io"
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
  certificate_arn   = var.ooniapi_acm_certificate_arn
  # In prod this has been manually applied

  default_action {
    target_group_arn = var.oonibackend_proxy_target_group_arn
    type             = "forward"
  }

  tags = var.tags
}

resource "aws_alb_listener_rule" "ooniapi_th" {
  listener_arn = aws_alb_listener.ooniapi_listener_https.arn
  priority     = 90

  action {
    type             = "forward"
    target_group_arn = var.oonibackend_proxy_target_group_arn
  }

  condition {
    host_header {
      values = var.oonith_domains
    }
  }

  tags = var.tags
}

resource "aws_lb_listener_rule" "ooniapi_ooniauth_rule" {
  listener_arn = aws_alb_listener.ooniapi_listener_https.arn
  priority     = 108

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

resource "aws_lb_listener_rule" "ooniapi_ooniauth_rule_host" {
  listener_arn = aws_alb_listener.ooniapi_listener_https.arn
  priority     = 109

  action {
    type             = "forward"
    target_group_arn = var.ooniapi_ooniauth_target_group_arn
  }

  condition {
    host_header {
      values = ["ooniauth.${local.direct_domain_suffix}"]
    }
  }
}

resource "aws_lb_listener_rule" "ooniapi_oonirun_rule" {
  listener_arn = aws_alb_listener.ooniapi_listener_https.arn
  priority     = 110

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

resource "aws_lb_listener_rule" "ooniapi_oonirun_rule_host" {
  listener_arn = aws_alb_listener.ooniapi_listener_https.arn
  priority     = 111

  action {
    type             = "forward"
    target_group_arn = var.ooniapi_oonirun_target_group_arn
  }

  condition {
    host_header {
      values = ["oonirun.${local.direct_domain_suffix}"]
    }
  }

}

resource "aws_lb_listener_rule" "ooniapi_ooniprobe_rule" {
  listener_arn = aws_alb_listener.ooniapi_listener_https.arn
  priority     = 120

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

resource "aws_lb_listener_rule" "ooniapi_ooniprobe_rule_host" {
  listener_arn = aws_alb_listener.ooniapi_listener_https.arn
  priority     = 121

  action {
    type             = "forward"
    target_group_arn = var.ooniapi_ooniprobe_target_group_arn
  }


  condition {
    host_header {
      values = ["ooniprobe.${local.direct_domain_suffix}"]
    }
  }

}

resource "aws_lb_listener_rule" "ooniapi_oonifindings_rule" {
  listener_arn = aws_alb_listener.ooniapi_listener_https.arn
  priority     = 130

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

resource "aws_lb_listener_rule" "ooniapi_oonifindings_rule_host" {
  listener_arn = aws_alb_listener.ooniapi_listener_https.arn
  priority     = 131

  action {
    type             = "forward"
    target_group_arn = var.ooniapi_oonifindings_target_group_arn
  }
  condition {
    host_header {
      values = ["oonifindings.${local.direct_domain_suffix}"]
    }
  }
}