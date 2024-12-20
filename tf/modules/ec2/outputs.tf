output "aws_instance_id" {
  value = aws_instance.ooni_ec2.id
}

output "aws_instance_public_dns" {
    value = aws_instance.ooni_ec2.public_dns
}
