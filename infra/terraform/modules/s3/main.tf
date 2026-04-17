variable "project" { type = string }

# IV-09 — S3 buckets without server-side encryption, with public access blocks
# disabled, and no versioning. Remediation: add aws_s3_bucket_server_side_encryption_configuration,
# aws_s3_bucket_public_access_block with all four flags true, and aws_s3_bucket_versioning.

resource "aws_s3_bucket" "artifacts" {
  bucket = "${var.project}-artifacts"

  tags = {
    Purpose = "CI/CD artifacts and SBOMs"
  }
}

# Deliberately missing: aws_s3_bucket_server_side_encryption_configuration
# Deliberately missing: aws_s3_bucket_versioning
# Deliberately missing: aws_s3_bucket_logging

# IV-09 — public access block with all four flags set to false.
resource "aws_s3_bucket_public_access_block" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_s3_bucket" "audit_logs" {
  bucket = "${var.project}-audit-logs"
}

# Same issues — this one will hold Falco / Vault audit output in a real deployment.
resource "aws_s3_bucket_public_access_block" "audit_logs" {
  bucket = aws_s3_bucket.audit_logs.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

output "artifacts_bucket" {
  value = aws_s3_bucket.artifacts.id
}
