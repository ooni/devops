locals {
  direct_domain_suffix = "${var.stage}.ooni.io"
}

resource "aws_alb" "ooniapi" {
  name            = "ooni-api-frontend"
  subnets         = var.subnet_ids
  security_groups = var.ooniapi_service_security_groups

  access_logs {
    bucket  = aws_s3_bucket.load_balancer_logs.bucket
    enabled = true
  }

  lifecycle {
    create_before_destroy = true
  }

  tags = var.tags
}

resource "random_id" "artifact_id" {
  byte_length = 4
}

// -- Logs Configuration -------------------------------------------------
resource "aws_s3_bucket" "load_balancer_logs" {
  bucket = "lb-logs-${var.aws_region}-${random_id.artifact_id.hex}"
}

resource "aws_s3_bucket_ownership_controls" "load_balancer_logs" {
  bucket = aws_s3_bucket.load_balancer_logs.id
  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "load_balancer_logs" {
  bucket = aws_s3_bucket.load_balancer_logs.id

  rule {
    id     = "expire-old-logs"
    status = "Enabled"

    expiration {
      days = 15
    }

    filter {
      prefix = "" // All objects
    }
  }
}

variable "region_to_account_id" {
  // We need a different id depending on the region, see:
  // https://docs.aws.amazon.com/elasticloadbalancing/latest/application/enable-access-logging.html#attach-bucket-policy
  type = map(string)
  default = {
    "eu-central-1" = "054676820928"
  }
}

resource "aws_s3_bucket_policy" "alb_logs_policy" {
  bucket = aws_s3_bucket.load_balancer_logs.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AWSLoadBalancerLogging"
        Effect    = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${var.region_to_account_id[var.aws_region]}:root"
        }
        Action = "s3:PutObject"
        Resource = "${aws_s3_bucket.load_balancer_logs.arn}/*"
      }
    ]
  })
}

// Athena DB for logs browsing
resource "aws_s3_bucket" "athena_results" {
  bucket = "ooni-athena-results-${random_id.artifact_id.hex}"
}

resource "aws_s3_bucket_lifecycle_configuration" "athena_results" {
  bucket = aws_s3_bucket.athena_results.id

  rule {
    id     = "expire-old-results"
    status = "Enabled"

    expiration {
      days = 90
    }

    filter {
      prefix = "output/"
    }
  }
}

resource "aws_athena_database" "load_balancer_logs" {
  name   = "load_balancer_logs"
  bucket = aws_s3_bucket.athena_results.bucket
}

resource "aws_athena_named_query" "create_alb_logs_table" {
  name      = "create_alb_logs_table"
  database  = aws_athena_database.load_balancer_logs.name

  query     = <<EOT
CREATE EXTERNAL TABLE IF NOT EXISTS alb_access_logs (
            type string,
            time string,
            elb string,
            client_ip string,
            client_port int,
            target_ip string,
            target_port int,
            request_processing_time double,
            target_processing_time double,
            response_processing_time double,
            elb_status_code int,
            target_status_code string,
            received_bytes bigint,
            sent_bytes bigint,
            request_verb string,
            request_url string,
            request_proto string,
            user_agent string,
            ssl_cipher string,
            ssl_protocol string,
            target_group_arn string,
            trace_id string,
            domain_name string,
            chosen_cert_arn string,
            matched_rule_priority string,
            request_creation_time string,
            actions_executed string,
            redirect_url string,
            lambda_error_reason string,
            target_port_list string,
            target_status_code_list string,
            classification string,
            classification_reason string,
            conn_trace_id string
            )
            ROW FORMAT SERDE 'org.apache.hadoop.hive.serde2.RegexSerDe'
            WITH SERDEPROPERTIES (
            'serialization.format' = '1',
            'input.regex' =
        '([^ ]*) ([^ ]*) ([^ ]*) ([^ ]*):([0-9]*) ([^ ]*)[:-]([0-9]*) ([-.0-9]*) ([-.0-9]*) ([-.0-9]*) (|[-0-9]*) (-|[-0-9]*) ([-0-9]*) ([-0-9]*) \"([^ ]*) (.*) (- |[^ ]*)\" \"([^\"]*)\" ([A-Z0-9-_]+) ([A-Za-z0-9.-]*) ([^ ]*) \"([^\"]*)\" \"([^\"]*)\" \"([^\"]*)\" ([-.0-9]*) ([^ ]*) \"([^\"]*)\" \"([^\"]*)\" \"([^ ]*)\" \"([^\\s]+?)\" \"([^\\s]+)\" \"([^ ]*)\" \"([^ ]*)\" ?([^ ]*)?'
            )
        LOCATION 's3://${aws_s3_bucket.load_balancer_logs.bucket}/AWSLogs/'
        EOT
    workgroup = aws_athena_workgroup.ooni_workgroup.name
}

resource "aws_athena_workgroup" "ooni_workgroup" {
  name = "ooni-workgroup"

  configuration {
    enforce_workgroup_configuration    = true
    publish_cloudwatch_metrics_enabled = true

    result_configuration {
      output_location = "s3://${aws_s3_bucket.athena_results.bucket}/output/"
    }
  }
}

// -- Listener rules -------------------------------------

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
        "/report*"
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
        # "/unimplemented"
        "/api/v1/measurements/*",
        "/api/v1/raw_measurement",
        "/api/v1/measurement_meta",
        "/api/v1/measurements",
        "/api/v1/torsf_stats"
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
         "/api/v1/aggregation",
         "/api/v1/aggregation/*",
         "/api/v1/observations",
         "/api/v1/analysis",
      ]
    }
  }
}
