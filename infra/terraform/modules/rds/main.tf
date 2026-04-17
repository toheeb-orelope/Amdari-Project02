variable "project" { type = string }
variable "environment" { type = string }
variable "vpc_id" { type = string }
variable "public_subnet_ids" { type = list(string) }
variable "db_password" { type = string }

# Deliberately insecure RDS configuration — Checkov will flag multiple issues:
# no storage encryption, publicly accessible, no automated backups, no deletion
# protection, no enhanced monitoring, no Performance Insights encryption.

resource "aws_db_subnet_group" "main" {
  name       = "${var.project}-${var.environment}-db-subnet"
  subnet_ids = var.public_subnet_ids # Public subnets — extends IV-10.
}

resource "aws_security_group" "db" {
  name   = "${var.project}-${var.environment}-db-sg"
  vpc_id = var.vpc_id

  ingress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # IV-02 at cloud scale — DB reachable from internet.
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_db_instance" "auth" {
  identifier             = "${var.project}-${var.environment}-authdb"
  engine                 = "redacted"
  engine_version         = "14"
  instance_class         = "db.t3.micro"
  allocated_storage      = 20
  db_name                = "authdb"
  username               = "authuser"
  password               = var.db_password # IV-01 via Terraform variable.
  db_subnet_group_name   = aws_db_subnet_group.main.name
  vpc_security_group_ids = [aws_security_group.db.id]
  publicly_accessible    = true  # Checkov CKV_AWS_17.
  storage_encrypted      = false # Checkov CKV_AWS_16.
  skip_final_snapshot    = true  # Checkov CKV_AWS_118.
  deletion_protection    = false

  # Deliberately missing: backup_retention_period, performance_insights_enabled,
  # enabled_cloudwatch_logs_exports, iam_database_authentication_enabled.
}

resource "aws_db_instance" "transactions" {
  identifier             = "${var.project}-${var.environment}-txdb"
  engine                 = "redacted"
  engine_version         = "14"
  instance_class         = "db.t3.micro"
  allocated_storage      = 20
  db_name                = "transactiondb"
  username               = "txuser"
  password               = var.db_password
  db_subnet_group_name   = aws_db_subnet_group.main.name
  vpc_security_group_ids = [aws_security_group.db.id]
  publicly_accessible    = true
  storage_encrypted      = false
  skip_final_snapshot    = true
  deletion_protection    = false
}
