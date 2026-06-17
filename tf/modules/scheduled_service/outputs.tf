output "task_role_name" {
description = "IAM role name used for scheduled task"
value       = aws_iam_role.scheduled_service_task.name
}

output "task_role_id" {
description = "IAM role ID for the scheduled task"
value       = aws_iam_role.scheduled_service_task.id
}

output "task_role_arn" {
description = "IAM role ARN for the scheduled task"
value       = aws_iam_role.scheduled_service_task.arn
}
