output "ecs_service_name" {
  value = aws_ecs_service.ooniapi_service.name
}

output "alb_target_group_id" {
  value = aws_alb_target_group.ooniapi_service.id
}
