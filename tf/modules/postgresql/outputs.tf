output "pg_address" {
  description = "The address of the postgres instance"
  value       = aws_db_instance.pg.address
}

output "pg_endpoint" {
  description = "The address of the postgres instance"
  value       = aws_db_instance.pg.endpoint
}

output "pg_db_name" {
  description = "The name of the postgres database"
  value       = aws_db_instance.pg.db_name
}

output "secrets_manager_pg_login_id" {
  description = "The postgres password to login as pg_username into pg_db_name as a secrets_manager_id"
  # Due to: https://github.com/hashicorp/terraform-provider-aws/issues/34094
  # If changing this on an old instance you have to run it manually
  value = aws_db_instance.pg.master_user_secret[0].secret_arn
}
