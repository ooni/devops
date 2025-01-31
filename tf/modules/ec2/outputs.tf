output "aws_instance_id" {
  value = aws_instance.ooni_ec2.id
}

output "aws_instance_public_dns" {
    value = aws_instance.ooni_ec2.public_dns
}

output "ec2_sg_id" {
  value = aws_security_group.ec2_sg.id
}