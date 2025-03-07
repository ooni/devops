data "aws_cloudhsm_v2_cluster" "hsm_cluster" {
  cluster_id = "cluster-qsvghm4oqok"
}

## Temporarily disabled, see: https://github.com/ooni/devops/issues/55
#resource "aws_cloudhsm_v2_hsm" "hsm" {
#  count      = length(var.subnet_ids)
#  subnet_id  = var.subnet_ids[count.index]
#  cluster_id = data.aws_cloudhsm_v2_cluster.hsm_cluster.cluster_id
#}

resource "aws_security_group" "hsm" {
  vpc_id = var.vpc_id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 2223 # Port for CloudHSM
    to_port     = 2225
    protocol    = "tcp"
    cidr_blocks = var.subnet_cidr_blocks
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_instance" "codesign_box" {
  # Amazon linux
  ami = "ami-03bb61bfa8e4d149e"

  key_name      = var.key_name
  instance_type = "t3.micro"

  subnet_id              = var.subnet_ids[0]
  vpc_security_group_ids = [aws_security_group.hsm.id]

  associate_public_ip_address = true

  user_data = <<-EOF
                #!/bin/bash
                sudo yum update -y
                curl -o cloudhsm-cli.rpm https://s3.amazonaws.com/cloudhsmv2-software/CloudHsmClient/Amzn2023/cloudhsm-cli-latest.amzn2023.x86_64.rpm
                sudo yum install -y ./cloudhsm-cli.rpm
                rm cloudhsm-cli.rpm

                curl -o  cloudhsm-pkcs11.rpm https://s3.amazonaws.com/cloudhsmv2-software/CloudHsmClient/Amzn2023/cloudhsm-pkcs11-latest.amzn2023.x86_64.rpm
                sudo yum install -y ./cloudhsm-pkcs11.rpm
                rm cloudhsm-pkcs11.rpm
                EOF

  tags = merge(var.tags, { Name = "codesign-box" , MonitoringActive = var.monitoring_active})

  // NOTE: remove the ignore_changes rule to deploy 
  lifecycle {
    ignore_changes = all
  }
}

resource "aws_launch_template" "codesign_box_template" {
  name = "codesign-box"
  # Ubuntu 22.04
  image_id = "ami-0a43b9fc420cabb27"

  instance_type = "t3.micro"

  key_name = var.key_name

  network_interfaces {
    subnet_id                   = var.subnet_ids[0]
    security_groups             = [aws_security_group.hsm.id]
    associate_public_ip_address = true
  }

  update_default_version = true

  tag_specifications {
    resource_type = "instance"

    tags = {
      Name = "codesign-box"
      MonitoringActive = var.monitoring_active
    }
  }

  tags = merge(var.tags, { Name = "codesign-box-template" })
}
