output "oonidevops_role_arn" {
  value = aws_iam_role.oonidevops.arn
}

output "oonidevops_key_name" {
  value = aws_key_pair.oonidevops.key_name
}

output "oonidevops_deploy_key_arn" {
  value = aws_secretsmanager_secret.oonidevops_deploy_key.id
}

output "ooniansible_access_key_id" {
  value = aws_iam_access_key.ooniansible_key.id
}

output "secret_access_key" {
  value = aws_iam_access_key.ooniansible_key.secret
  sensitive = true
}

