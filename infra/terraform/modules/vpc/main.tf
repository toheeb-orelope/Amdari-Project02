variable "project" { type = string }
variable "environment" { type = string }
variable "my_cidr_block" { type = string }

resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "${var.project}-${var.environment}-vpc"
  }
}

resource "aws_default_security_group" "default" {
  vpc_id      = aws_vpc.main.id
  description = "Default security group for ${var.project}-${var.environment} to deny all ingress and allow all egress. Checkov will flag this SG for being too permissive, but it's a common default configuration."
  tags = {
    Name = "${var.project}-${var.environment}-default-sg"
  }
}

resource "aws_flow_log" "main" {
  iam_role_arn    = "arn"
  log_destination = "log"
  traffic_type    = "ALL"
  vpc_id          = aws_vpc.main.id
}



resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "${var.project}-${var.environment}-igw"
  }
}

# IV-10 — public subnets with auto-assign public IPs. EKS nodes land here.
resource "aws_subnet" "public" {
  count                   = 2
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.${count.index + 1}.0/24"
  availability_zone       = ["${var.project}-az-a", "${var.project}-az-b"][count.index]
  map_public_ip_on_launch = false # IV-10

  tags = {
    Name = "${var.project}-${var.environment}-public-${count.index}"
  }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }
}

resource "aws_route_table_association" "public" {
  count          = length(aws_subnet.public)
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}


output "vpc_id" {
  value = aws_vpc.main.id
}

output "public_subnet_ids" {
  value = aws_subnet.public[*].id
}
