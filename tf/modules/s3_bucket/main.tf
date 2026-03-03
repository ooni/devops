resource "aws_s3_bucket" "bucket" {
  bucket              = var.bucket_name
  object_lock_enabled = var.object_lock_enabled
}

resource "aws_s3_bucket_versioning" "bucket" {
  bucket = aws_s3_bucket.bucket.id

  versioning_configuration {
    status = var.versioning_enabled ? "Enabled" : "Suspended"
  }
}

resource "aws_s3_bucket_ownership_controls" "bucket" {
  bucket = aws_s3_bucket.bucket.id

  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

resource "aws_s3_bucket_public_access_block" "bucket" {
  bucket = aws_s3_bucket.bucket.id

  block_public_acls       = !var.public_read
  block_public_policy     = !var.public_read
  ignore_public_acls      = !var.public_read
  restrict_public_buckets = !var.public_read
}

resource "aws_s3_bucket_acl" "bucket" {
  count = var.public_read ? 1 : 0

  bucket = aws_s3_bucket.bucket.id
  acl    = "public-read"

  depends_on = [
    aws_s3_bucket_ownership_controls.bucket,
    aws_s3_bucket_public_access_block.bucket,
  ]
}

resource "aws_s3_bucket_policy" "public" {
  count  = var.public_read ? 1 : 0
  bucket = aws_s3_bucket.bucket.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat(
      [
        for action in var.public_bucket_actions : {
          Sid       = replace(action, ":", "")
          Effect    = "Allow"
          Principal = "*"
          Action    = action
          Resource  = aws_s3_bucket.bucket.arn
        }
      ],
      [
        for action in var.public_object_actions : {
          Sid       = replace(action, ":", "")
          Effect    = "Allow"
          Principal = "*"
          Action    = action
          Resource  = "${aws_s3_bucket.bucket.arn}/*"
        }
      ]
    )
  })
}

resource "aws_iam_user" "bucket_user" {
  count = var.create_iam_user ? 1 : 0
  name  = "${var.bucket_name}-user"
}

resource "aws_iam_user_policy" "s3_access" {
  count = var.create_iam_user ? 1 : 0
  user  = aws_iam_user.bucket_user[0].name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = var.iam_user_permissions
        Resource = [
          aws_s3_bucket.bucket.arn,
          "${aws_s3_bucket.bucket.arn}/*"
        ]
      }
    ]
  })
}

resource "aws_s3_bucket_policy" "bucket_iam_permissions" {
  count  = var.create_iam_user ? 1 : 0
  bucket = aws_s3_bucket.bucket.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "IAMUserBucketPolicy",
        Effect = "Allow",
        Principal = {
          AWS = aws_iam_user.bucket_user[0].arn
        },
        Action = var.iam_user_permissions,
        Resource = [
          aws_s3_bucket.bucket.arn,
          "${aws_s3_bucket.bucket.arn}/*"
        ]
      }
    ]
  })
}

resource "aws_iam_access_key" "user_access_key" {
  count = var.create_iam_user ? 1 : 0
  user  = aws_iam_user.bucket_user[0].name
}

resource "aws_ssm_parameter" "access_key_id" {
  count = var.create_iam_user ? 1 : 0

  name  = "/s3/${var.bucket_name}-user/access_key_id"
  type  = "SecureString"
  value = aws_iam_access_key.user_access_key[0].id
}

resource "aws_ssm_parameter" "secret_access_key" {
  count = var.create_iam_user ? 1 : 0

  name  = "/s3/${var.bucket_name}-user/secret_access_key"
  type  = "SecureString"
  value = aws_iam_access_key.user_access_key[0].secret
}
