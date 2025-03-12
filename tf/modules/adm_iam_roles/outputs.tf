output "oonidevops_role_arn" {
  value = aws_iam_role.oonidevops.arn
}

output "oonidevops_key_name" {
  value = aws_key_pair.oonidevops.key_name
}

output "oonidevops_deploy_key_arn" {
  value = aws_secretsmanager_secret.oonidevops_deploy_key.id
}
