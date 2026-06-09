# SecureFlow Terraform — INTENTIONALLY VULNERABLE baseline.
# Planted vulnerabilities are tagged with their Vulnerability Index ID.
# DO NOT `terraform apply` this against a real AWS account — Checkov should
# block it in the pipeline. The purpose of this tree is to give interns
# something Checkov can flag.

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }

    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.30"
    }

    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.15"
    }
  }
}

provider "aws" {
  region = var.region
}

variable "region" {
  type    = string
  default = "eu-west-2"
}

provider "aws" {
  region = var.region
  alias  = "primary"
}

provider "aws" {
  region = var.replication_region
  alias  = "secondary"
}

variable "replication_region" {
  type    = string
  default = "us-east-1"
}

variable "project" {
  type    = string
  default = "secureflow"
}

variable "environment" {
  type    = string
  default = "dev"
}

module "vpc" {
  source        = "./modules/vpc"
  project       = var.project
  environment   = var.environment
  my_cidr_block = "10.0.0.0/16"
}

module "iam" {
  source  = "./modules/iam"
  project = var.project
}

module "s3" {
  source  = "./modules/s3"
  project = var.project
  region  = var.region
}

module "eks" {
  source             = "./modules/eks"
  project            = var.project
  environment        = var.environment
  vpc_id             = module.vpc.vpc_id
  private_subnet_ids = module.vpc.private_subnet_ids
  region             = var.region
  my_cidr_block      = var.my_cidr_block
}

module "rds" {
  source             = "./modules/rds"
  project            = var.project
  environment        = var.environment
  vpc_id             = module.vpc.vpc_id
  private_subnet_ids = module.vpc.private_subnet_ids
  db_password        = var.db_password # IV-01 — hardcoded DB password reused from docker-compose.
  region             = var.region
  my_cidr_block      = var.my_cidr_block
}
