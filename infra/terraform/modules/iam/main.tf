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

resource "aws_iam_role_policy_attachment" "eks_worker_policy" {
  role       = aws_iam_role.eks_node.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy" # IV-08 fixed to specific managed policy.
}

# Missing - CNI policy (networking)
resource "aws_iam_role_policy_attachment" "eks_cni_policy" {
  role       = aws_iam_role.eks_node.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
}

# Missing - ECR access (pulling container images)
resource "aws_iam_role_policy_attachment" "eks_ecr_policy" {
  role       = aws_iam_role.eks_node.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
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
        Federated = aws_iam_openid_connect_provider.eks.arn
      }
      Condition = {
        StringEquals = {
          # Restrict to a specific service account in a specific namespace
          "${replace(data.aws_iam_openid_connect_provider.eks.url, "https://", "")}:sub" = "system:serviceaccount:secureflow:app-sa"
          "${replace(data.aws_iam_openid_connect_provider.eks.url, "https://", "")}:aud" = "sts.amazonaws.com"
        }
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
      Effect = "Allow"
      Action = ["s3:ListAllMyBuckets",
      "s3:GetBucketLocation"]     # IV-08 — wildcard action. fixed to specific actions.
      Resource = "arn:aws:s3:::*" # IV-08 — wildcard resource. fixed to specific resources.
    }]
  })
}

output "eks_node_role_arn" {
  value = aws_iam_role.eks_node.arn
}

output "app_role_arn" {
  value = aws_iam_role.app_role.arn
}
