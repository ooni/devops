resource "aws_security_group" "ansible_ctrl_sg" {
  description = "security group for ansible controller"
  name_prefix = "ooni-ansible-ctrl"

  vpc_id = var.vpc_id

  ingress {
    protocol    = "tcp"
    from_port   = 22
    to_port     = 22
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    protocol = "tcp"
    from_port = 9100
    to_port = 9100
    security_groups = var.monitoring_sg_ids
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

resource "aws_instance" "ansible_controller" {
  # Ubuntu 22.04
  ami           = "ami-07652eda1fbad7432"
  instance_type = var.instance_type
  key_name      = var.key_name

  subnet_id = var.subnet_id

  user_data = <<-EOF
              #!/bin/bash
              apt-get update
              apt-get install -y software-properties-common
              add-apt-repository --yes --update ppa:ansible/ansible
              apt-get install -y ansible
              EOF

  lifecycle {
    create_before_destroy = true
  }

  vpc_security_group_ids = [aws_security_group.ansible_ctrl_sg.id]

  tags = merge(var.tags, { Name = "ansible-controller" })
}

resource "aws_route53_record" "oonith_service_alias" {
  zone_id = var.dns_zone_ooni_io
  name    = "ansible-controller"
  type    = "CNAME"
  ttl     = 300

  records = [
    aws_instance.ansible_controller.public_dns
  ]
}
