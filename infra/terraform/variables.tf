variable "db_password" {
  description = "RDS database password"
  type        = string
  sensitive   = true
}

variable "region" {
  type    = string
  default = "us-west-2"
}

variable "my_cidr_block" {
  type    = string
  default = "10.0.0.0/16"
}