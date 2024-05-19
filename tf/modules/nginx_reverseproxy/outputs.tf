output "autoscaling_group_id" {
  value = aws_autoscaling_group.nginx.id
}
output "alb_target_group_id" {
  value = aws_alb_target_group.nginx.id
}
