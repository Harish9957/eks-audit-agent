resource "aws_iam_role" "eks_audit_agent" {
  name = "eks-audit-agent"
  path = "/service-roles/"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${var.aws_account_id}:root"
        }
        Action = "sts:AssumeRole"
        Condition = {
          StringEquals = {
            "aws:PrincipalTag/team" = "platform-engineering"
          }
        }
      }
    ]
  })

  tags = {
    Purpose   = "EKS Audit Agent - read-only CloudWatch Logs access"
    ManagedBy = "terraform"
    Team      = "platform-engineering"
  }
}

resource "aws_iam_role_policy" "eks_audit_agent_logs" {
  name = "eks-audit-agent-cloudwatch-logs-readonly"
  role = aws_iam_role.eks_audit_agent.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowEKSAuditLogQueries"
        Effect = "Allow"
        Action = [
          "logs:StartQuery",
          "logs:GetQueryResults",
          "logs:StopQuery",
          "logs:DescribeLogGroups"
        ]
        Resource = "arn:aws:logs:*:${var.aws_account_id}:log-group:/aws/eks/*/cluster:*"
      }
    ]
  })
}

variable "aws_account_id" {
  type        = string
  description = "AWS account ID where EKS clusters run"
}

output "eks_audit_agent_role_arn" {
  value       = aws_iam_role.eks_audit_agent.arn
  description = "ARN to assume when running the EKS audit agent locally"
}
