output "bucket_name" {
  value = aws_s3_bucket.bucket.bucket
}

output "bucket_arn" {
  value = aws_s3_bucket.bucket.arn
}

output "iam_user_name" {
  value       = try(aws_iam_user.bucket_user[0].name, null)
  description = "IAM user name if created"
}
