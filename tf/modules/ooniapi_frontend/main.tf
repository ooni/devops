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

  connection_logs {
    bucket  = aws_s3_bucket.load_balancer_logs.bucket
    enabled = true
    prefix  = "connection_log"
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
        Sid    = "AWSLoadBalancerLogging"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${var.region_to_account_id[var.aws_region]}:root"
        }
        Action   = "s3:PutObject"
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

resource "aws_athena_named_query" "create_alb_connection_logs_table" {
  name     = "create_alb_connection_logs_table"
  database = aws_athena_database.load_balancer_logs.name

  query     = <<EOT
CREATE EXTERNAL TABLE IF NOT EXISTS alb_connection_logs (
         time string,
         client_ip string,
         client_port int,
         listener_port int,
         tls_protocol string,
         tls_cipher string,
         tls_handshake_latency double,
         leaf_client_cert_subject string,
         leaf_client_cert_validity string,
         leaf_client_cert_serial_number string,
         tls_verify_status string,
         conn_trace_id string
         )
         ROW FORMAT SERDE 'org.apache.hadoop.hive.serde2.RegexSerDe'
         WITH SERDEPROPERTIES (
         'serialization.format' = '1',
         'input.regex' =
          '([^ ]*) ([^ ]*) ([0-9]*) ([0-9]*) ([A-Za-z0-9.-]*) ([^ ]*) ([-.0-9]*) \"([^\"]*)\" ([^ ]*) ([^ ]*) ([^ ]*) ?([^ ]*)?( .*)?'
         )
         LOCATION 's3://${aws_s3_bucket.load_balancer_logs.bucket}/connection_log/AWSLogs/'
    EOT
  workgroup = aws_athena_workgroup.ooni_workgroup.name
}

resource "aws_athena_named_query" "create_alb_logs_table" {
  name     = "create_alb_logs_table"
  database = aws_athena_database.load_balancer_logs.name

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
        '([^ ]*) ([^ ]*) ([^ ]*) ([^ ]*):([0-9]*) ([^ ]*)[:-]([0-9]*) ([-.0-9]*) ([-.0-9]*) ([-.0-9]*) (|[-0-9]*) (-|[-0-9]*) ([-0-9]*) ([-0-9]*) \"([^ ]*) (.*) (- |[^ ]*)\" \"([^\"]*)\" ([A-Z0-9-_]+) ([A-Za-z0-9.-]*) ([^ ]*) \"([^\"]*)\" \"([^\"]*)\" \"([^\"]*)\" ([-.0-9]*) ([^ ]*) \"([^\"]*)\" \"([^\"]*)\" \"([^ ]*)\" \"([^\\s]+?)\" \"([^\\s]+)\" \"([^ ]*)\" \"([^ ]*)\" ?([^ ]*)?.*'
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

locals {
  # routes.yaml is shared with the gateway on the Hetzner hosts
  # (ansible/roles/ooniapi_gateway), so both serve the same routes
  routes = yamldecode(file("${path.module}/routes.yaml"))

  target_groups = {
    ooniauth         = var.ooniapi_ooniauth_target_group_arn
    oonirun          = var.ooniapi_oonirun_target_group_arn
    ooniprobe        = var.ooniapi_ooniprobe_target_group_arn
    ooniprobe_legacy = var.ooniapi_ooniprobe_legacy_target_group_arn
    oonifindings     = var.ooniapi_oonifindings_target_group_arn
    oonimeasurements = var.ooniapi_oonimeasurements_target_group_arn
    testlists        = var.ooniapi_testlists_target_group_arn
  }

  listener_rules = { for r in local.routes : r.name => r }
}

resource "aws_lb_listener_rule" "route" {
  for_each = local.listener_rules

  listener_arn = aws_alb_listener.ooniapi_listener_https.arn
  priority     = each.value.priority

  action {
    type             = "forward"
    target_group_arn = local.target_groups[each.value.service]
  }

  dynamic "condition" {
    for_each = can(each.value.paths) ? [each.value.paths] : []
    content {
      path_pattern {
        values = condition.value
      }
    }
  }

  dynamic "condition" {
    for_each = try(each.value.direct_host, false) ? [each.value.service] : []
    content {
      host_header {
        values = ["${condition.value}.${local.direct_domain_suffix}"]
      }
    }
  }

  dynamic "condition" {
    for_each = can(each.value.http_header) ? [each.value.http_header] : []
    content {
      http_header {
        http_header_name = condition.value.name
        values           = condition.value.values
      }
    }
  }
}

# the rules were one resource each before routes.yaml
moved {
  from = aws_lb_listener_rule.ooniapi_ooniauth_rule
  to   = aws_lb_listener_rule.route["ooniauth_rule"]
}

moved {
  from = aws_lb_listener_rule.ooniapi_ooniauth_rule_host
  to   = aws_lb_listener_rule.route["ooniauth_rule_host"]
}

moved {
  from = aws_lb_listener_rule.ooniapi_oonirun_rule
  to   = aws_lb_listener_rule.route["oonirun_rule"]
}

moved {
  from = aws_lb_listener_rule.ooniapi_oonirun_rule_host
  to   = aws_lb_listener_rule.route["oonirun_rule_host"]
}

moved {
  from = aws_lb_listener_rule.ooniapi_ooniprobe_rule
  to   = aws_lb_listener_rule.route["ooniprobe_rule"]
}

moved {
  from = aws_lb_listener_rule.ooniapi_ooniprobe_rule_2
  to   = aws_lb_listener_rule.route["ooniprobe_rule_2"]
}

moved {
  from = aws_lb_listener_rule.ooniapi_ooniprobe_rule_3_legacy_version
  to   = aws_lb_listener_rule.route["ooniprobe_rule_3_legacy_version"]
}

moved {
  from = aws_lb_listener_rule.ooniapi_ooniprobe_rule_4
  to   = aws_lb_listener_rule.route["ooniprobe_rule_4"]
}

moved {
  from = aws_lb_listener_rule.ooniapi_ooniprobe_rule_3_current_version
  to   = aws_lb_listener_rule.route["ooniprobe_rule_3_current_version"]
}

moved {
  from = aws_lb_listener_rule.ooniapi_ooniprobe_rule_host
  to   = aws_lb_listener_rule.route["ooniprobe_rule_host"]
}

moved {
  from = aws_lb_listener_rule.ooniapi_ooniprobe_rule_3_no_version
  to   = aws_lb_listener_rule.route["ooniprobe_rule_3_no_version"]
}

moved {
  from = aws_lb_listener_rule.ooniapi_oonifindings_rule
  to   = aws_lb_listener_rule.route["oonifindings_rule"]
}

moved {
  from = aws_lb_listener_rule.ooniapi_oonifindings_rule_host
  to   = aws_lb_listener_rule.route["oonifindings_rule_host"]
}

moved {
  from = aws_lb_listener_rule.ooniapi_oonimeasurements_rule_host[0]
  to   = aws_lb_listener_rule.route["oonimeasurements_rule_host"]
}

moved {
  from = aws_lb_listener_rule.ooniapi_oonimeasurements_rule_1[0]
  to   = aws_lb_listener_rule.route["oonimeasurements_rule_1"]
}

moved {
  from = aws_lb_listener_rule.ooniapi_oonimeasurements_rule_2[0]
  to   = aws_lb_listener_rule.route["oonimeasurements_rule_2"]
}

moved {
  from = aws_lb_listener_rule.ooniapi_oonimeasurements_rule_3
  to   = aws_lb_listener_rule.route["oonimeasurements_rule_3"]
}

moved {
  from = aws_lb_listener_rule.ooniapi_testlists_rule[0]
  to   = aws_lb_listener_rule.route["testlists_rule"]
}
