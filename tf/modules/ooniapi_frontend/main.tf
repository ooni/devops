locals {
  direct_domain_suffix = "${var.stage}.ooni.io"
}

resource "aws_alb" "ooniapi" {
  name            = "ooni-api-frontend"
  subnets         = var.subnet_ids
  security_groups = var.ooniapi_service_security_groups

  lifecycle {
    create_before_destroy = true
  }

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
        "/api/v1/login",
        "/api/v1/register",
        "/api/v1/update/*",
        # Activate this when the DB is connected in prod
        "/api/v1/check-in*",
      ]
    }
  }
}

resource "aws_lb_listener_rule" "ooniapi_ooniprobe_rule_2" {
  listener_arn = aws_alb_listener.ooniapi_listener_https.arn
  priority     = 121

  action {
    type             = "forward"
    target_group_arn = var.ooniapi_ooniprobe_target_group_arn
  }

  condition {
    path_pattern {
      values = [
        "/api/v1/test-helpers*",
        # "/report*"
      ]
    }
  }
}

resource "aws_lb_listener_rule" "ooniapi_ooniprobe_rule_host" {
  listener_arn = aws_alb_listener.ooniapi_listener_https.arn
  priority     = 125

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
      values = [
        "/api/v1/incidents/*",
      ]
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

resource "aws_lb_listener_rule" "ooniapi_oonimeasurements_rule_host" {
  # hotfix: to allow us to deploy the frontend without the measurements service
  count = var.ooniapi_oonimeasurements_target_group_arn != null ? 1 : 0

  listener_arn = aws_alb_listener.ooniapi_listener_https.arn
  priority     = 139

  action {
    type             = "forward"
    target_group_arn = var.ooniapi_oonimeasurements_target_group_arn
  }
  condition {
    host_header {
      values = ["oonimeasurements.${local.direct_domain_suffix}"]
    }
  }
}

resource "aws_lb_listener_rule" "ooniapi_oonimeasurements_rule_1" {
  # hotfix: to allow us to deploy the frontend without the measurements service
  count = var.ooniapi_oonimeasurements_target_group_arn != null ? 1 : 0

  listener_arn = aws_alb_listener.ooniapi_listener_https.arn
  priority     = 140

  action {
    type             = "forward"
    target_group_arn = var.ooniapi_oonimeasurements_target_group_arn
  }

  condition {
    path_pattern {
      values = [
        "/unimplemented"
        # "/api/v1/measurements/*",
        # "/api/v1/raw_measurement",
        # "/api/v1/measurement_meta",
        # "/api/v1/measurements",
        # "/api/v1/torsf_stats"
      ]
    }
  }
}

resource "aws_lb_listener_rule" "ooniapi_oonimeasurements_rule_2" {
  # hotfix: to allow us to deploy the frontend without the measurements service
  count = var.ooniapi_oonimeasurements_target_group_arn != null ? 1 : 0

  listener_arn = aws_alb_listener.ooniapi_listener_https.arn
  priority     = 142

  action {
    type             = "forward"
    target_group_arn = var.ooniapi_oonimeasurements_target_group_arn
  }

  condition {
    path_pattern {
      values = [
        "/unimplemented",
        # "/api/v1/aggregation",
        # "/api/v1/aggregation/*",
        # "/api/v1/observations",
        # "/api/v1/analysis",
      ]
    }
  }
}
