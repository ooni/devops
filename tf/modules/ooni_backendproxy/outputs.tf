output "aws_instance_id" {
  value = aws_instance.oonibackend_proxy.id
}

output "alb_target_group_id" {
  value = aws_alb_target_group.oonibackend_proxy.id
}
