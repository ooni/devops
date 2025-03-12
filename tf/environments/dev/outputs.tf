output "oonidevops_role_arn" {
  value = module.adm_iam_roles.oonidevops_role_arn
}

output "oonidevops_key_name" {
  value = module.adm_iam_roles.oonidevops_key_name
}

output "oonidevops_deploy_key_arn" {
  value = module.adm_iam_roles.oonidevops_deploy_key_arn
}

output "oonipg_pg_login_arn" {
  value = module.oonipg.secrets_manager_pg_login_id
}

# output "oonidataapi_alb_hostname" {
#   value = module.ooni_dataapi.alb_dns_name
# }

# output "db_instance_endpoint" {
#   value = module.postgresql.endpoint
# }
