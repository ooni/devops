resource "aws_cloudwatch_log_group" "ooniapi_services" {
  name = "ooni-ecs-group/${var.name}"
}

resource "aws_ecs_cluster" "main" {
  name = var.name
  configuration {
    execute_command_configuration {
      logging = "OVERRIDE"

      log_configuration {
        cloud_watch_log_group_name = aws_cloudwatch_log_group.ooniapi_services.name
      }
    }
  }

  tags = var.tags
}


data "aws_ssm_parameter" "ecs_optimized_ami" {
  name = "/aws/service/ecs/optimized-ami/amazon-linux-2/recommended"
}

resource "aws_iam_role" "container_host" {
  name = "${var.name}-container-host-role"

  tags = var.tags

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

resource "aws_security_group" "web" {
  description = "controls access to the applications ELB web endpoint"

  vpc_id      = var.vpc_id
  name_prefix = "ooni-ecs-web"

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
    ipv6_cidr_blocks = ["::/0"]
  }

  lifecycle {
    create_before_destroy = true
  }

  tags = var.tags
}

resource "aws_iam_instance_profile" "container_host" {
  name = var.name
  role = aws_iam_role.container_host.name

  tags = var.tags
}

resource "aws_iam_role_policy" "container_host" {
  name   = "${var.name}-instance-role-policy"
  role   = aws_iam_role.container_host.name
  policy = templatefile("${path.module}/templates/profile_policy.json", {})
}

resource "aws_security_group" "container_host" {
  description = "controls direct access to application instances"
  vpc_id      = var.vpc_id
  name_prefix = "ooni-ecs-container"

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

    security_groups = concat([
      aws_security_group.web.id,
    ],
    var.monitoring_sg_ids)
  }

  ingress {
    protocol = "tcp"
    from_port = 9100
    to_port = 9100

    security_groups = var.monitoring_sg_ids
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

  tags = var.tags
}

resource "aws_launch_template" "container_host" {
  name_prefix = var.name

  key_name      = var.key_name
  image_id      = jsondecode(data.aws_ssm_parameter.ecs_optimized_ami.value)["image_id"]
  instance_type = var.instance_type

  user_data = base64encode(templatefile("${path.module}/templates/ecs-setup.sh", {
    ecs_cluster_name = var.name,
    ecs_cluster_tags = var.tags
    node_exporter_port = var.node_exporter_port
  }))

  update_default_version               = true
  instance_initiated_shutdown_behavior = "terminate"

  iam_instance_profile {
    name = aws_iam_instance_profile.container_host.name
  }

  network_interfaces {
    associate_public_ip_address = true
    delete_on_termination       = true
    security_groups = [
      aws_security_group.container_host.id,
    ]
  }

  block_device_mappings {
    device_name = "/dev/sdf"

    ebs {
      volume_size           = var.instance_volume_size
      delete_on_termination = true
    }
  }

  tag_specifications {
    resource_type = "instance"
    tags = merge(
      {
        MonitoringActive : var.monitoring_active
      },
      var.tags
    )
  }
}

resource "aws_autoscaling_group" "container_host" {
  name_prefix         = var.name
  vpc_zone_identifier = var.subnet_ids
  min_size            = var.asg_min
  max_size            = var.asg_max
  desired_capacity    = var.asg_desired

  launch_template {
    id      = aws_launch_template.container_host.id
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

resource "aws_ecs_capacity_provider" "capacity_provider" {
  name = "${var.name}-capacity-provider"

  auto_scaling_group_provider {
      auto_scaling_group_arn         = aws_autoscaling_group.container_host.arn
      managed_draining = "ENABLED"
      managed_termination_protection = "ENABLED"

      managed_scaling {
        maximum_scaling_step_size = 1000
        minimum_scaling_step_size = 1
        status                    = "ENABLED"
        target_capacity           = 100
      }
    }
}
