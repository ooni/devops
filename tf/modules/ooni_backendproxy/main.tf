data "aws_ssm_parameter" "ubuntu_22_ami" {
  name = "/aws/service/canonical/ubuntu/server/22.04/stable/current/amd64/hvm/ebs-gp2/ami-id"
}

# Important note about security groups:
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group#recreating-a-security-group
resource "aws_security_group" "nginx_sg" {
  description = "security group for nginx"
  name_prefix = "ooni-bckprx"

  vpc_id = var.vpc_id

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

  lifecycle {
    create_before_destroy = true
  }

  tags = var.tags
}

resource "aws_launch_template" "ooni_backendproxy" {
  name_prefix   = "${var.name}-nginx-tmpl-"
  image_id      = data.aws_ssm_parameter.ubuntu_22_ami.value
  instance_type = var.instance_type
  key_name      = var.key_name

  user_data = filebase64("${path.module}/templates/setup-backend-proxy.sh")

  lifecycle {
    create_before_destroy = true
  }

  network_interfaces {
    delete_on_termination       = true
    associate_public_ip_address = true
    security_groups = [
      aws_security_group.nginx_sg.id,
    ]
  }

  tag_specifications {
    resource_type = "instance"
    tags          = var.tags
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

  name_prefix = "${var.name}-asg-"

  min_size            = 1
  max_size            = 2
  desired_capacity    = 1
  vpc_zone_identifier = var.subnet_ids

  instance_refresh {
    strategy = "Rolling"
    preferences {
      min_healthy_percentage = 50
    }
  }
}

resource "aws_alb_target_group" "oonibackend_proxy" {
  name_prefix = "oobpx"
  port        = 80
  protocol    = "HTTP"
  vpc_id      = var.vpc_id

  lifecycle {
    create_before_destroy = true
  }

  tags = var.tags
}

resource "aws_autoscaling_attachment" "oonibackend_proxy" {
  autoscaling_group_name = aws_autoscaling_group.oonibackend_proxy.id
  lb_target_group_arn    = aws_alb_target_group.oonibackend_proxy.arn
}
