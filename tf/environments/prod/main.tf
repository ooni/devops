# Store terraform state in s3
terraform {
  backend "s3" {
    region  = "eu-central-1"
    bucket  = "ooni-production-terraform-state"
    key     = "terraform.tfstate"
    profile = ""
    encrypt = "true"

    dynamodb_table = "ooni-production-terraform-state-lock"
  }
}

# You cannot create a new backend by simply defining this and then
# immediately proceeding to "terraform apply". The S3 backend must
# be bootstrapped according to the simple yet essential procedure in
# https://github.com/cloudposse/terraform-aws-tfstate-backend#usage
module "terraform_state_backend" {
  source     = "cloudposse/tfstate-backend/aws"
  version    = "1.4.0"
  namespace  = "ooni"
  stage      = "production"
  name       = "terraform"
  attributes = ["state"]

  #terraform_backend_config_file_path = "."
  terraform_backend_config_file_name = "backend.tf"
  force_destroy                      = false
}

## Ansible inventory

resource "local_file" "ansible_inventory" {
  depends_on = [
    # Commented out because module is disabled
    # module.clickhouse.server_ip
  ]

  content = templatefile("${path.module}/templates/ansible-inventory.tpl", {
    clickhouse_servers = [
      # module.clickhouse.server_fqdm
    ]
  })
  filename = "${path.module}/ansible/inventory.ini"
}

resource "null_resource" "ansible_update_known_hosts" {
  depends_on = [local_file.ansible_inventory]

  provisioner "local-exec" {
    command = "./scripts/update_known_hosts.sh"
    environment = {
      INVENTORY_FILE   = "ansible/inventory.ini"
      KNOWN_HOSTS_FILE = "ansible/known_hosts"
    }
  }
}

# Local variable definitions
locals {
  environment      = "prod"
  name             = "ooni-${local.environment}"
  ecs_cluster_name = "ooni-ecs-cluster"
  dns_zone_ooni_nu = "Z035992527R8VEIX2UVO0" # ooni.nu hosted zone
  dns_zone_ooni_io = "Z02418652BOD91LFA5S9X" # ooni.io hosted zone

  tags = {
    Name        = local.name
    Environment = local.environment
    Repository  = "https://github.com/ooni/devops"
  }
}

## AWS Setup

provider "aws" {
  region     = var.aws_region
  access_key = var.aws_access_key_id
  secret_key = var.aws_secret_access_key
}

module "network" {
  source = "../../modules/network"

  aws_access_key_id     = var.aws_access_key_id
  aws_secret_access_key = var.aws_secret_access_key
  aws_region            = var.aws_region
  az_count              = var.az_count
  vpc_main_cidr_block   = "10.0.0.0/16"
}

moved {
  from = aws_vpc.main
  to   = module.network.aws_vpc.main
}

moved {
  from = aws_internet_gateway.gw
  to   = module.network.aws_internet_gateway.gw
}

moved {
  from = aws_internet_gateway.gw
  to   = module.network.aws_internet_gateway.gw
}

moved {
  from = aws_subnet.main
  to   = module.network.aws_subnet.main
}

moved {
  from = aws_route_table.r
  to   = module.network.aws_route_table.r
}

moved {
  from = aws_route_table_association.a
  to   = module.network.aws_route_table_association.a
}

#
### OONI Modules

# Temporarily disabled, since production OONI clickhouse is not on AWS atm
#module "clickhouse" {
#  source = "../../modules/clickhouse"
#
#  aws_vpc_id            = aws_vpc.main.id
#  aws_subnet_id         = aws_subnet.main[0].id
#  aws_access_key_id     = var.aws_access_key_id
#  aws_secret_access_key = var.aws_secret_access_key
#  key_name              = var.key_name
#  admin_cidr_ingress    = var.admin_cidr_ingress
#}

### AWS RDS for PostgreSQL

module "postgresql" {
  source = "../../modules/postgresql"

  name                  = "ooni-prod-tier0-postgres"
  aws_access_key_id     = var.aws_access_key_id
  aws_secret_access_key = var.aws_secret_access_key
  aws_region            = var.aws_region
  vpc_id                = module.network.vpc_id
  subnet_ids            = [module.network.vpc_subnet[0].id, module.network.vpc_subnet[1].id]
  pg_password           = var.ooni_pg_password
  tags                  = local.tags
}

moved {
  from = aws_db_instance.ooni_pg
  to   = module.postgresql.aws_db_instance.pg
}

moved {
  from = aws_db_subnet_group.main
  to   = module.postgresql.aws_db_subnet_group.pg
}

moved {
  from = aws_security_group.pg_sg
  to   = module.postgresql.aws_security_group.pg
}

## EC2

data "aws_ssm_parameter" "ubuntu_22_ami" {
  name = "/aws/service/canonical/ubuntu/server/22.04/stable/current/amd64/hvm/ebs-gp2/ami-id"
}

resource "aws_security_group" "ooni_nginx_sg" {
  description = "security group for OONI Nginx. Allow port 80 and 22"

  vpc_id = module.network.vpc_id
  name   = "ooni-tier0-prod-nginx-sg"

  ingress {
    protocol    = "tcp"
    from_port   = 80
    to_port     = 80
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    protocol    = "tcp"
    from_port   = 22
    to_port     = 22
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port = 0
    to_port   = 0
    protocol  = "-1"

    cidr_blocks = [
      "0.0.0.0/0",
    ]
  }

  tags = local.tags
}


resource "aws_launch_template" "ooni_backendproxy" {
  name_prefix   = "ooni-backendproxy-nginx-template-"
  image_id      = data.aws_ssm_parameter.ubuntu_22_ami.value
  instance_type = "t2.micro"
  key_name      = var.key_name

  user_data = filebase64("${path.module}/templates/setup-backend-proxy.sh")

  lifecycle {
    create_before_destroy = true
  }

  network_interfaces {
    delete_on_termination       = true
    associate_public_ip_address = true
    security_groups = [
      aws_security_group.ooni_nginx_sg.id,
    ]
  }

  tag_specifications {
    resource_type = "instance"
    tags = {
      Name = "ooni-tier0-prod-backendproxy"
    }
  }
}

resource "aws_autoscaling_group" "oonibackend_proxy" {
  launch_template {
    id      = aws_launch_template.ooni_backendproxy.id
    version = "$Latest"
  }

  lifecycle {
    create_before_destroy = true
  }

  name_prefix = "ooni-tier0-prod-oldbackend-proxy"

  min_size            = 1
  max_size            = 2
  desired_capacity    = 1
  vpc_zone_identifier = module.network.vpc_subnet[*].id

  instance_refresh {
    strategy = "Rolling"
    preferences {
      min_healthy_percentage = 50
    }
  }
}

### Compute for ECS

data "aws_ssm_parameter" "ecs_optimized_ami" {
  name = "/aws/service/ecs/optimized-ami/amazon-linux-2/recommended"
}

resource "aws_launch_template" "app" {
  name_prefix = "ooni-tier1-production-backend-lt"

  key_name      = var.key_name
  image_id      = jsondecode(data.aws_ssm_parameter.ecs_optimized_ami.value)["image_id"]
  instance_type = "t2.micro"

  user_data = base64encode(templatefile("${path.module}/templates/ecs-setup.sh", {
    ecs_cluster_name = local.ecs_cluster_name,
    ecs_cluster_tags = local.tags
  }))

  update_default_version               = true
  instance_initiated_shutdown_behavior = "terminate"

  iam_instance_profile {
    name = aws_iam_instance_profile.app.name
  }

  network_interfaces {
    associate_public_ip_address = true
    delete_on_termination       = true
    security_groups = [
      aws_security_group.instance_sg.id,
    ]
  }

  block_device_mappings {
    device_name = "/dev/sdf"

    ebs {
      delete_on_termination = true
    }
  }

  tag_specifications {
    resource_type = "instance"
    tags = {
      Name = "ooni-tier1-production-backend"
    }
  }
}

resource "aws_autoscaling_group" "app" {
  name_prefix         = "ooni-tier1-production-backend-asg"
  vpc_zone_identifier = module.network.vpc_subnet[*].id
  min_size            = var.asg_min
  max_size            = var.asg_max
  desired_capacity    = var.asg_desired

  launch_template {
    id      = aws_launch_template.app.id
    version = "$Latest"
  }

  instance_refresh {
    strategy = "Rolling"
    preferences {
      min_healthy_percentage = 50
    }

    triggers = ["tag"]
  }
}

### Security

resource "aws_security_group" "lb_sg" {
  description = "controls access to the application ELB"

  vpc_id = module.network.vpc_id
  name   = "tf-ecs-lbsg"

  ingress {
    protocol    = "tcp"
    from_port   = 80
    to_port     = 80
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    protocol    = "tcp"
    from_port   = 443
    to_port     = 443
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port = 0
    to_port   = 0
    protocol  = "-1"

    cidr_blocks = [
      "0.0.0.0/0",
    ]
  }

  tags = local.tags
}

resource "aws_security_group" "instance_sg" {
  description = "controls direct access to application instances"
  vpc_id      = module.network.vpc_id
  name        = "tf-ecs-instsg"

  ingress {
    protocol  = "tcp"
    from_port = 22
    to_port   = 22

    cidr_blocks = [
      var.admin_cidr_ingress,
    ]
  }

  ingress {
    protocol  = "tcp"
    from_port = 32768
    to_port   = 61000

    security_groups = [
      aws_security_group.lb_sg.id,
    ]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = local.tags
}

## ECS

resource "aws_ecs_cluster" "main" {
  name = local.ecs_cluster_name
  tags = local.tags
}


locals {
  container_name = "ooni_dataapi"
}

resource "aws_ecs_task_definition" "oonidataapi" {
  family = "ooni-dataapi-production-td"
  container_definitions = templatefile("${path.module}/templates/task_definition.json", {
    # Image URL is updated via code build and code pipeline
    image_url        = "ooni/dataapi:latest",
    container_name   = local.container_name,
    container_port   = 80,
    log_group_region = var.aws_region,
    log_group_name   = aws_cloudwatch_log_group.app.name,
  })

  execution_role_arn = aws_iam_role.ecs_task.arn
  tags               = local.tags
}

resource "aws_ecs_service" "oonidataapi" {
  name            = "ooni-ecs-dataapi-production"
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.oonidataapi.arn
  desired_count   = var.service_desired
  iam_role        = aws_iam_role.ecs_service.name

  deployment_minimum_healthy_percent = 50
  deployment_maximum_percent         = 100

  load_balancer {
    target_group_arn = aws_alb_target_group.oonidataapi.id
    container_name   = local.container_name
    container_port   = "80"
  }

  depends_on = [
    aws_iam_role_policy.ecs_service,
    aws_alb_listener.front_end,
  ]

  lifecycle {
    ignore_changes = [
      task_definition,
    ]
  }

  force_new_deployment = true

  tags = local.tags
}

## IAM

resource "aws_iam_role" "ecs_task" {
  name = "ooni_ecs_task_role"

  tags = local.tags

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

resource "aws_iam_role_policy" "ecs_task" {
  name = "ooni_ecs_task_policy"
  role = aws_iam_role.ecs_task.name

  policy = templatefile("${path.module}/templates/instance_profile_policy.json", {})
}

resource "aws_iam_role" "ecs_service" {
  name = "ooni_ecs_role"

  tags = local.tags

  assume_role_policy = <<EOF
{
  "Version": "2008-10-17",
  "Statement": [
    {
      "Sid": "",
      "Effect": "Allow",
      "Principal": {
        "Service": "ecs.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF
}

resource "aws_iam_role_policy" "ecs_service" {
  name = "ooni_ecs_policy"
  role = aws_iam_role.ecs_service.name

  policy = templatefile("${path.module}/templates/instance_profile_policy.json", {})
}

resource "aws_iam_instance_profile" "app" {
  name = "tf-ecs-instprofile"
  role = aws_iam_role.app_instance.name

  tags = local.tags
}

resource "aws_iam_role" "app_instance" {
  name = "tf-ecs-ooni-instance-role"

  tags = local.tags

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "",
      "Effect": "Allow",
      "Principal": {
        "Service": "ec2.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF
}

resource "aws_iam_role_policy" "instance" {
  name   = "TfEcsOONIInstanceRole"
  role   = aws_iam_role.app_instance.name
  policy = templatefile("${path.module}/templates/instance_profile_policy.json", {})
}

## ALB

resource "aws_alb_target_group" "oonidataapi" {
  name     = "ooni-tier1-oonidataapi"
  port     = 80
  protocol = "HTTP"
  vpc_id   = module.network.vpc_id

  tags = local.tags
}

resource "aws_alb" "oonidataapi" {
  name            = "ooni-tier1-oonidataapi"
  subnets         = module.network.vpc_subnet[*].id
  security_groups = [aws_security_group.lb_sg.id]

  tags = local.tags
}

resource "aws_alb_listener" "front_end" {
  load_balancer_arn = aws_alb.oonidataapi.id
  port              = "80"
  protocol          = "HTTP"

  default_action {
    target_group_arn = aws_alb_target_group.oonidataapi.id
    type             = "forward"
  }

  tags = local.tags
}

resource "aws_alb_listener" "front_end_https" {
  load_balancer_arn = aws_alb.oonidataapi.id
  port              = "443"
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-2016-08"
  certificate_arn   = aws_acm_certificate_validation.oonidataapi.certificate_arn

  default_action {
    target_group_arn = aws_alb_target_group.oonidataapi.id
    type             = "forward"
  }

  tags = local.tags
}

### OONI API ALB

resource "aws_alb" "ooniapi" {
  name            = "ooni-tier0-api"
  subnets         = module.network.vpc_subnet[*].id
  security_groups = [aws_security_group.lb_sg.id]

  tags = local.tags
}

resource "aws_alb_target_group" "oonibackend_proxy" {
  name     = "ooni-tier0-oldbackend-proxy"
  port     = 80
  protocol = "HTTP"
  vpc_id   = module.network.vpc_id

  tags = local.tags
}

resource "aws_autoscaling_attachment" "oonibackend_proxy" {
  autoscaling_group_name = aws_autoscaling_group.oonibackend_proxy.id
  lb_target_group_arn    = aws_alb_target_group.oonibackend_proxy.arn
}

resource "aws_alb_listener" "ooniapi_listener_http" {
  load_balancer_arn = aws_alb.ooniapi.id
  port              = "80"
  protocol          = "HTTP"

  default_action {
    target_group_arn = aws_alb_target_group.oonibackend_proxy.id
    type             = "forward"
  }

  tags = local.tags
}

resource "aws_alb_listener" "ooniapi_listener_https" {
  load_balancer_arn = aws_alb.ooniapi.id
  port              = "443"
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-2016-08"
  certificate_arn   = aws_acm_certificate_validation.ooniapi.certificate_arn

  default_action {
    target_group_arn = aws_alb_target_group.oonibackend_proxy.id
    type             = "forward"
  }

  tags = local.tags
}

# resource "aws_lb_listener_rule" "rule" {
#   listener_arn = aws_lb_listener.ooniapi_listener_https.arn
#   priority     = 100

#   action {
#     type             = "forward"
#     target_group_arn = aws_lb_target_group.tg.arn
#   }

#   condition {
#     path_pattern {
#       values = ["/api/v1/*"]
#     }
#   }
# }

# Route53

resource "aws_route53_record" "postgres_dns" {
  zone_id = local.dns_zone_ooni_nu
  name    = "postgres.tier0.prod.ooni.nu"
  type    = "CNAME"
  ttl     = "300"
  records = [module.postgresql.address]
}

resource "aws_route53_record" "alb_dns" {
  zone_id = local.dns_zone_ooni_io
  name    = "dataapi.prod.ooni.io"
  type    = "A"

  alias {
    name                   = aws_alb.oonidataapi.dns_name
    zone_id                = aws_alb.oonidataapi.zone_id
    evaluate_target_health = true
  }
}

resource "aws_route53_record" "ooniapi_alb_dns" {
  zone_id = local.dns_zone_ooni_io
  name    = "api.prod.ooni.io"
  type    = "A"

  alias {
    name                   = aws_alb.ooniapi.dns_name
    zone_id                = aws_alb.ooniapi.zone_id
    evaluate_target_health = true
  }
}

# ACM TLS

resource "aws_acm_certificate" "oonidataapi" {
  domain_name       = "dataapi.prod.ooni.io"
  validation_method = "DNS"

  tags = local.tags

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_route53_record" "oonidataapi_cert_validation" {
  for_each = {
    for dvo in aws_acm_certificate.oonidataapi.domain_validation_options : dvo.domain_name => {
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
  zone_id         = local.dns_zone_ooni_io
}

resource "aws_acm_certificate_validation" "oonidataapi" {
  certificate_arn         = aws_acm_certificate.oonidataapi.arn
  validation_record_fqdns = [for record in aws_route53_record.oonidataapi_cert_validation : record.fqdn]
  depends_on = [
    aws_route53_record.ooniapi_alb_dns
  ]
}

resource "aws_acm_certificate" "ooniapi" {
  domain_name       = "api.prod.ooni.io"
  validation_method = "DNS"

  tags = local.tags


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
  zone_id         = local.dns_zone_ooni_io
}

resource "aws_acm_certificate_validation" "ooniapi" {
  certificate_arn         = aws_acm_certificate.ooniapi.arn
  validation_record_fqdns = [for record in aws_route53_record.ooniapi_cert_validation : record.fqdn]
}


## CloudWatch Logs

resource "aws_cloudwatch_log_group" "ecs" {
  name = "tf-ecs-group/ecs-agent"
}

resource "aws_cloudwatch_log_group" "app" {
  name = "tf-ecs-group/app-dataapi"
}
