data "aws_ssm_parameter" "ubuntu_24_ami" {
  name = "/aws/service/canonical/ubuntu/server/24.04/stable/current/amd64/hvm/ebs-gp3/ami-id"
}

# Important note about security groups:
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group#recreating-a-security-group
resource "aws_security_group" "nginx_sg" {
  description = "security group for nginx"
  name_prefix = "ooni-bckprx"

  vpc_id = var.vpc_id

  ingress {
    protocol    = "tcp"
    from_port   = 9000
    to_port     = 9000
  }

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

  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    ipv6_cidr_blocks = ["::/0"]
  }

  lifecycle {
    create_before_destroy = true
  }

  tags = var.tags
}

data "cloudinit_config" "ooni_backendproxy" {
  base64_encode = true

  part {
    filename     = "init.cfg"
    content_type = "text/cloud-config"
    content = templatefile("${path.module}/templates/cloud-init.yml", {
      wcth_addresses     = var.wcth_addresses,
      wcth_domain_suffix = var.wcth_domain_suffix,
      backend_url        = var.backend_url,
      clickhouse_url     = var.clickhouse_url,
      clickhouse_port    = var.clickhouse_port
    })
  }

}

resource "aws_launch_template" "ooni_backendproxy" {
  name_prefix   = "${var.name}-bkprx-tmpl-"
  image_id      = data.aws_ssm_parameter.ubuntu_24_ami.value
  instance_type = var.instance_type
  key_name      = var.key_name

  user_data = data.cloudinit_config.ooni_backendproxy.rendered

  lifecycle {
    create_before_destroy = true
  }

  network_interfaces {
    delete_on_termination       = true
    associate_public_ip_address = true
    subnet_id                   = var.subnet_id
    security_groups = [
      aws_security_group.nginx_sg.id,
    ]
  }

  tag_specifications {
    resource_type = "instance"
    tags          = var.tags
  }
}

resource "aws_instance" "oonibackend_proxy" {
  launch_template {
    id      = aws_launch_template.ooni_backendproxy.id
    version = "$Latest"
  }

  lifecycle {
    create_before_destroy = true
  }

  tags = var.tags
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

resource "aws_lb_target_group_attachment" "oonibackend_proxy" {
  target_id        = aws_instance.oonibackend_proxy.id
  target_group_arn = aws_alb_target_group.oonibackend_proxy.arn
}

resource "aws_route53_record" "clickhouse_proxy_alias" {
  zone_id = var.dns_zone_ooni_io
  name    = "clickhouseproxy.${var.stage}.ooni.io"
  type    = "CNAME"
  ttl     = 300

  records = [
    aws_instance.oonibackend_proxy.public_dns
  ]
}
