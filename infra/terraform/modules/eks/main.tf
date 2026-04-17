variable "project" { type = string }
variable "environment" { type = string }
variable "vpc_id" { type = string }
variable "public_subnet_ids" { type = list(string) }

# IV-10 — EKS nodes placed in public subnets with a public API endpoint.
# Remediation: create private subnets with NAT gateway routing, set
# endpoint_private_access=true, endpoint_public_access=false (or restrict cidrs),
# and move node groups into the private subnet IDs.

resource "aws_iam_role" "cluster" {
  name = "${var.project}-${var.environment}-eks-cluster"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "eks.amazonaws.com"
      }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "cluster_policy" {
  role       = aws_iam_role.cluster.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
}

resource "aws_eks_cluster" "main" {
  name     = "${var.project}-${var.environment}"
  role_arn = aws_iam_role.cluster.arn
  version  = "1.28"

  vpc_config {
    subnet_ids              = var.public_subnet_ids # IV-10
    endpoint_private_access = false                  # IV-10
    endpoint_public_access  = true                   # IV-10
    public_access_cidrs     = ["0.0.0.0/0"]          # IV-10
  }

  # Deliberately missing: encryption_config for secrets at rest.
  # Deliberately missing: enabled_cluster_log_types.

  depends_on = [aws_iam_role_policy_attachment.cluster_policy]
}

resource "aws_iam_role" "node_group" {
  name = "${var.project}-${var.environment}-eks-node"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "ec2.amazonaws.com"
      }
    }]
  })
}

# IV-08 — node group role also gets AdministratorAccess.
resource "aws_iam_role_policy_attachment" "node_admin" {
  role       = aws_iam_role.node_group.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

resource "aws_eks_node_group" "main" {
  cluster_name    = aws_eks_cluster.main.name
  node_group_name = "${var.project}-${var.environment}-ng"
  node_role_arn   = aws_iam_role.node_group.arn
  subnet_ids      = var.public_subnet_ids # IV-10 — nodes in public subnets.

  scaling_config {
    desired_size = 2
    max_size     = 3
    min_size     = 1
  }

  instance_types = ["t3.medium"]
}

output "cluster_name" {
  value = aws_eks_cluster.main.name
}

output "cluster_endpoint" {
  value = aws_eks_cluster.main.endpoint
}
