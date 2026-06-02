locals {
  vpc_cidrs = concat(var.private_subnet_cidr, var.public_subnet_cidr)

  ingress_rules = [
    {
      from_port   = 22
      to_port     = 22
      protocol    = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
    },
    {
      from_port   = 8472
      to_port     = 8472
      protocol    = "tcp"
      cidr_blocks = local.vpc_cidrs
    },
    {
      from_port   = 8475 # for serving jsonl files
      to_port     = 8475
      protocol    = "tcp"
      cidr_blocks = local.vpc_cidrs
    },
    {
      from_port   = 9100
      to_port     = 9100
      protocol    = "tcp"
      cidr_blocks = ["${var.monitoring_proxy_private_ip}/32"]
    },
    {
      from_port = 9102 # For fastpath metrics
      to_port   = 9102
      protocol  = "tcp"
      cidr_blocks = [
        "${var.monitoring_proxy_private_ip}/32",
        "${var.monitoring_proxy_public_ip}/32",
      ]
    },
  ]

  egress_rules = [
    {
      from_port   = 0
      to_port     = 0
      protocol    = "-1"
      cidr_blocks = ["0.0.0.0/0"]
    },
    {
      from_port        = 0
      to_port          = 0
      protocol         = "-1"
      ipv6_cidr_blocks = ["::/0"]
    },
  ]
}

module "ec2" {
  source = "../ec2"

  stage = var.env

  vpc_id              = var.vpc_id
  subnet_id           = var.subnet_id
  private_subnet_cidr = var.private_subnet_cidr
  dns_zone_ooni_io    = var.dns_zone_ooni_io

  key_name      = var.key_name
  instance_type = var.instance_type

  name          = "ooni${var.name}"
  ingress_rules = local.ingress_rules
  egress_rules  = local.egress_rules

  sg_prefix = var.sg_prefix
  tg_prefix = var.tg_prefix

  disk_size = var.disk_size

  tags = merge(
    var.tags,
    { Name = "ooni-tier0-${var.name}" },
  )
}

resource "aws_route53_record" "fastpath_alias" {
  zone_id = var.dns_zone_ooni_io
  name    = "${var.name}.${var.env}.ooni.io"
  type    = "CNAME"
  ttl     = 300

  records = [
    module.ec2.aws_instance_public_dns
  ]
}
