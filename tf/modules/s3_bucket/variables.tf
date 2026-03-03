variable "bucket_name" {
  type        = string
  description = "S3 bucket name"
}

variable "object_lock_enabled" {
  type    = bool
  default = false
}

variable "versioning_enabled" {
  type    = bool
  default = true
}

variable "public_read" {
  type        = bool
  default     = false
  description = "Allow public read and list access"
}

variable "public_bucket_actions" {
  type    = list(string)
  default = ["s3:ListBucket"]
}

variable "public_object_actions" {
  type    = list(string)
  default = ["s3:GetObject"]
}

variable "create_iam_user" {
  type    = bool
  default = false
}

variable "iam_user_permissions" {
  type    = list(string)
  default = ["s3:*"]
}
