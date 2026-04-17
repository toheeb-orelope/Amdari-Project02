variable "project" { type = string }

# IV-08 — EKS node role is given AdministratorAccess.
# Remediation: scope to specific managed policies (AmazonEKSWorkerNodePolicy,
# AmazonEKS_CNI_Policy, AmazonEC2ContainerRegistryReadOnly) and use IRSA for
# application pods that need AWS access.

resource "aws_iam_role" "eks_node" {
  name = "${var.project}-eks-node-role"

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

resource "aws_iam_role_policy_attachment" "admin_access" {
  role       = aws_iam_role.eks_node.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess" # IV-08
}

# A second role used by the app pods — also over-privileged.
resource "aws_iam_role" "app_role" {
  name = "${var.project}-app-role"

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

resource "aws_iam_role_policy" "app_inline" {
  name = "${var.project}-app-inline"
  role = aws_iam_role.app_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "*"     # IV-08 — wildcard action.
      Resource = "*"     # IV-08 — wildcard resource.
    }]
  })
}

output "eks_node_role_arn" {
  value = aws_iam_role.eks_node.arn
}

output "app_role_arn" {
  value = aws_iam_role.app_role.arn
}
