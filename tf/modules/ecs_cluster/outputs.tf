output "cluster_name" {
  value = aws_ecs_cluster.main.name
}

output "cluster_arn" {
  value = aws_ecs_cluster.main.arn
}

output "cluster_id" {
  value = aws_ecs_cluster.main.id
}

output "web_security_group_id" {
  value = aws_security_group.web.id
}

output "container_security_group_id" {
  value = aws_security_group.container_host.id
}
