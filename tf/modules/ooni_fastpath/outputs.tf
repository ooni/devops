output "aws_instance_id" {
  value = module.ec2.aws_instance_id
}

output "aws_instance_private_ip" {
  value = module.ec2.aws_instance_private_ip
}

output "aws_instance_public_ip" {
  value = module.ec2.aws_instance_public_ip
}

output "aws_instance_public_dns" {
  value = module.ec2.aws_instance_public_dns
}

output "ec2_sg_id" {
  value = module.ec2.ec2_sg_id
}

output "alb_target_group_id" {
  value = module.ec2.alb_target_group_id
}

output "dns_name" {
  value = aws_route53_record.fastpath_alias.name
}
