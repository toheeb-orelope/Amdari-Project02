variable "project" { type = string }
variable "environment" { type = string }
variable "vpc_id" { type = string }
variable "private_subnet_ids" { type = list(string) }
variable "db_password" { type = string }
variable "region" { type = string }
variable "my_cidr_block" { type = string }

# Deliberately insecure RDS configuration — Checkov will flag multiple issues:
# no storage encryption, publicly accessible, no automated backups, no deletion
# protection, no enhanced monitoring, no Performance Insights encryption.

resource "aws_db_subnet_group" "main" {
  name       = "${var.project}-${var.environment}-db-subnet"
  subnet_ids = var.private_subnet_ids # Private subnets — extends IV-10.
}

# 3. Use Secrets Manager for DB password (instead of hardcoding in Terraform variables or code).
resource "aws_secretsmanager_secret" "db_password" {
  name                    = "${var.project}-${var.environment}-db-password"
  kms_key_id              = aws_kms_key.rds.arn
  recovery_window_in_days = 7
}

# Store the actual password value
resource "aws_secretsmanager_secret_version" "db_password" {
  secret_id     = aws_secretsmanager_secret.db_password.id
  secret_string = var.db_password
}


resource "aws_security_group" "db" {
  name        = "${var.project}-${var.environment}-db-sg"
  vpc_id      = var.vpc_id
  description = "Security group for RDS instances"

  ingress {
    description = "Allow PostgreSQL from application security group"
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = [var.my_cidr_block]
  }

  egress {
    description = "Allow outbound HTTPS for updates and monitoring"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.my_cidr_block]
  }
}

# KMS key for audit logs (more sensitive data)
resource "aws_kms_key" "rds" {
  description             = "Key for encrypting RDS instances"
  deletion_window_in_days = 10
  enable_key_rotation     = true
}

resource "aws_kms_key_policy" "rds" {
  key_id = aws_kms_key.rds.id
  policy = jsonencode({
    Id = "rds-kms-policy"
    Statement = [
      {
        Sid    = "Allow rds to use the key"
        Effect = "Allow"
        Principal = {
          Service = "rds.amazonaws.com"
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
            "kms:ViaService" = "rds.${var.region}.amazonaws.com" # Add region restriction
          }
        }
      }
    ]
    Version = "2012-10-17"
  })
}

resource "aws_db_instance" "auth" {
  identifier                      = "${var.project}-${var.environment}-authdb"
  engine                          = "postgresql"
  engine_version                  = "14"
  instance_class                  = "db.t3.micro"
  allocated_storage               = 20
  db_name                         = "authdb"
  username                        = "authuser"
  password                        = aws_secretsmanager_secret_version.db_password.secret_string # IV-01 via Terraform variable.
  db_subnet_group_name            = aws_db_subnet_group.main.name
  vpc_security_group_ids          = [aws_security_group.db.id]
  publicly_accessible             = false # Checkov CKV_AWS_17.
  storage_encrypted               = true  # Checkov CKV_AWS_16.
  skip_final_snapshot             = false # Checkov CKV_AWS_118.
  deletion_protection             = true  # Checkov CKV_AWS_119.
  monitoring_interval             = 5
  performance_insights_enabled    = true
  multi_az                        = true
  performance_insights_kms_key_id = aws_kms_key.rds.arn
  enabled_cloudwatch_logs_exports = ["general", "error", "slowquery"]
  auto_minor_version_upgrade      = true
  copy_tags_to_snapshot           = true

  # Deliberately missing: backup_retention_period, performance_insights_enabled,
  # enabled_cloudwatch_logs_exports, iam_database_authentication_enabled.
}

resource "aws_db_instance" "transactions" {
  identifier                      = "${var.project}-${var.environment}-txdb"
  engine                          = "postgresql"
  engine_version                  = "14"
  instance_class                  = "db.t3.micro"
  allocated_storage               = 20
  db_name                         = "transactiondb"
  username                        = "txuser"
  password                        = aws_secretsmanager_secret_version.db_password.secret_string
  db_subnet_group_name            = aws_db_subnet_group.main.name
  vpc_security_group_ids          = [aws_security_group.db.id]
  publicly_accessible             = false
  storage_encrypted               = true
  skip_final_snapshot             = false
  deletion_protection             = true
  monitoring_interval             = 5
  performance_insights_enabled    = true
  multi_az                        = true
  performance_insights_kms_key_id = aws_kms_key.rds.arn
  enabled_cloudwatch_logs_exports = ["general", "error", "slowquery"]
  auto_minor_version_upgrade      = true
  copy_tags_to_snapshot           = true
}
