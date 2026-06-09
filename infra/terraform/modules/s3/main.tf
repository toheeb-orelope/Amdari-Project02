variable "project" { type = string }
variable "region" { type = string }

# IV-09 — S3 buckets without server-side encryption, with public access blocks
# disabled, and no versioning. Remediation: add aws_s3_bucket_server_side_encryption_configuration,
# aws_s3_bucket_public_access_block with all four flags true, and aws_s3_bucket_versioning.

data "aws_caller_identity" "current" {}

resource "aws_s3_bucket" "s3_access_logs" {
  bucket = "${var.project}-s3-access-logs"

  tags = {
    Purpose = "Centralized S3 access logs"
  }
}

resource "aws_s3_bucket_versioning" "s3_access_logs" {
  bucket = aws_s3_bucket.s3_access_logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_public_access_block" "s3_access_logs" {
  bucket = aws_s3_bucket.s3_access_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Lifecycle for log bucket only
resource "aws_s3_bucket_lifecycle_configuration" "s3_access_logs" {
  bucket = aws_s3_bucket.s3_access_logs.id

  rule {
    id     = "expire-old-logs"
    status = "Enabled"
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }

    expiration {
      days = 90
    }
  }
}

# KMS key for audit logs (more sensitive data)
resource "aws_kms_key" "s3_access_logs" {
  description             = "Key for encrypting CI/CD artifacts"
  deletion_window_in_days = 10
  enable_key_rotation     = true
}

resource "aws_kms_key_policy" "s3_access_logs" {
  key_id = aws_kms_key.s3_access_logs.id
  policy = jsonencode({
    Id = "s3-access-logs-kms-policy"
    Statement = [
      {
        Sid    = "Allow S3 to use the key"
        Effect = "Allow"
        Principal = {
          Service = "s3.amazonaws.com"
        }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "kms:ViaService" = "s3.${var.region}.amazonaws.com" # Add region restriction
          }
        }
      }
    ]
    Version = "2012-10-17"
  })
}

# Server-side encryption for log bucket
resource "aws_s3_bucket_server_side_encryption_configuration" "s3_access_logs" {
  bucket = aws_s3_bucket.s3_access_logs.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.s3_access_logs.arn
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket" "artifacts" {
  bucket = "${var.project}-artifacts"

  tags = {
    Purpose = "CI/CD artifacts and SBOMs"
  }
}

# Versioning for artifacts (important for immutable artifacts)
resource "aws_s3_bucket_versioning" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id

  rule {
    id     = "transition-to-glacier"
    status = "Enabled"
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }

    transition {
      days          = 30
      storage_class = "GLACIER"
    }

    expiration {
      days = 365 # Keep audit logs for 1 year
    }
  }
}

# KMS key for artifacts (more sensitive data)
resource "aws_kms_key" "artifacts" {
  description             = "Key for encrypting CI/CD artifacts"
  deletion_window_in_days = 10
  enable_key_rotation     = true
}

resource "aws_kms_key_policy" "artifacts" {
  key_id = aws_kms_key.artifacts.id
  policy = jsonencode({
    Id = "artifacts-kms-policy"
    Statement = [
      {
        Sid    = "Allow S3 to use the key"
        Effect = "Allow"
        Principal = {
          Service = "s3.amazonaws.com"
        }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "kms:ViaService" = "s3.${var.region}.amazonaws.com" # Add region restriction
          }
        }
      }
    ]
    Version = "2012-10-17"
  })
}

# Server-side encryption for artifacts
resource "aws_s3_bucket_server_side_encryption_configuration" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.artifacts.arn
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

# Public access block for artifacts
resource "aws_s3_bucket_public_access_block" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Logging for artifacts bucket (to dedicated log bucket)
resource "aws_s3_bucket_logging" "artifacts" {
  bucket        = aws_s3_bucket.artifacts.id
  target_bucket = aws_s3_bucket.s3_access_logs.id
  target_prefix = "artifacts-bucket-logs/"
}
# Audit logs bucket
resource "aws_s3_bucket" "audit_logs" {
  bucket = "${var.project}-audit-logs"

  tags = {
    Purpose = "Falco / Vault audit output"
  }
}

# Versioning for audit logs (important for immutable logs)
resource "aws_s3_bucket_versioning" "audit_logs" {
  bucket = aws_s3_bucket.audit_logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

# Lifecycle for audit logs (keep for 1 year, with multipart upload cleanup)
resource "aws_s3_bucket_lifecycle_configuration" "audit_logs" {
  bucket = aws_s3_bucket.audit_logs.id

  rule {
    id     = "transition-to-glacier"
    status = "Enabled"
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }

    transition {
      days          = 30
      storage_class = "GLACIER"
    }

    expiration {
      days = 365 # Keep audit logs for 1 year
    }
  }
}

# KMS key for audit logs (more sensitive data)
resource "aws_kms_key" "audit_logs" {
  description             = "Key for encrypting CI/CD artifacts"
  deletion_window_in_days = 10
  enable_key_rotation     = true
}

resource "aws_kms_key_policy" "audit_logs" {
  key_id = aws_kms_key.audit_logs.id
  policy = jsonencode({
    Id = "audit-logs-kms-policy"
    Statement = [
      {
        Sid    = "Allow S3 to use the key"
        Effect = "Allow"
        Principal = {
          Service = "s3.amazonaws.com"
        }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "kms:ViaService" = "s3.${var.region}.amazonaws.com" # Add region restriction
          }
        }
      }
    ]
    Version = "2012-10-17"
  })
}

# Server-side encryption for audit logs
resource "aws_s3_bucket_server_side_encryption_configuration" "audit_logs" {
  bucket = aws_s3_bucket.audit_logs.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.audit_logs.arn
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

# Public access block for audit logs
resource "aws_s3_bucket_public_access_block" "audit_logs" {
  bucket = aws_s3_bucket.audit_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Logging for audit_logs bucket (to dedicated log bucket)
resource "aws_s3_bucket_logging" "audit_logs" {
  bucket        = aws_s3_bucket.audit_logs.id
  target_bucket = aws_s3_bucket.s3_access_logs.id
  target_prefix = "audit-logs-bucket-logs/"
}


# SNS topics for each bucket
resource "aws_sns_topic" "s3_access_logs_notifications" {
  name              = "${var.project}-s3-access-logs-notifications"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic" "artifacts_notifications" {
  name              = "${var.project}-artifacts-notifications"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic" "audit_logs_notifications" {
  name              = "${var.project}-audit-logs-notifications"
  kms_master_key_id = "alias/aws/sns"
}

# Bucket notifications
resource "aws_s3_bucket_notification" "s3_access_logs" {
  bucket = aws_s3_bucket.s3_access_logs.id

  topic {
    topic_arn = aws_sns_topic.s3_access_logs_notifications.arn
    events    = ["s3:ObjectCreated:*"]
  }
}

resource "aws_s3_bucket_notification" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id

  topic {
    topic_arn = aws_sns_topic.artifacts_notifications.arn
    events    = ["s3:ObjectCreated:*", "s3:ObjectRemoved:*"]
  }
}

resource "aws_s3_bucket_notification" "audit_logs" {
  bucket = aws_s3_bucket.audit_logs.id

  topic {
    topic_arn = aws_sns_topic.audit_logs_notifications.arn
    events    = ["s3:ObjectCreated:*"]
  }
}


# Outputs
output "artifacts_bucket" {
  value = aws_s3_bucket.artifacts.id
}

output "audit_logs_bucket" {
  value = aws_s3_bucket.audit_logs.id
}

output "s3_access_logs_bucket" {
  value = aws_s3_bucket.s3_access_logs.id
}
