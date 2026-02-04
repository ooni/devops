output "aws_instance_id" {
  value = aws_instance.ooni_ec2.id
}

output "aws_instance_public_dns" {
    value = aws_instance.ooni_ec2.public_dns
}

output "ec2_sg_id" {
  value = aws_security_group.ec2_sg.id
}

output "aws_instance_private_ip" {
  value = aws_instance.ooni_ec2.private_ip
}

output "aws_instance_public_ip" {
  value = aws_instance.ooni_ec2.public_ip
}

output "alb_target_group_id" {
  value = aws_alb_target_group.ooni_ec2.id
}
