# GitHub Actionsからロールを引き受けるためのモジュール
variable "role_name" {
  description = "Name of the IAM role"
  type        = string
  default     = "github-actions-role"
}
variable "target_repository" {
  description = "GitHub repository in format org/repo"
  type        = string
}
variable "target_refs" {
  description = "List of GitHub refs that can assume this role"
  type        = list(string)
  default     = ["refs/heads/main"]
}
variable "policies" {
  description = "List of IAM policy ARNs to attach to the role"
  type        = list(string)
  default     = []
}
variable "openid_connect_provider_github_arn" {
  description = "ARN of the GitHub OIDC provider"
  type        = string
}
variable "default_tags" {
  description = "Default tags to be applied to all resources"
  type        = map(string)
  default     = {}
}

# GitHub ActionsがAssumeできるIAMロール
resource "aws_iam_role" "github_actions" {
  name = var.role_name

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Principal = {
          Federated = var.openid_connect_provider_github_arn
        },
        Action = "sts:AssumeRoleWithWebIdentity",
        Condition = {
          StringEquals = {
            "token.actions.githubusercontent.com:aud" : "sts.amazonaws.com"
          },
          StringLike = {
            "token.actions.githubusercontent.com:sub" : [
              for ref in var.target_refs :
              "repo:${var.target_repository}:${ref}"
            ]
          }
        }
      }
    ]
  })

  tags = var.default_tags
}

# ポリシーのアタッチメント
resource "aws_iam_role_policy_attachment" "role_policy_attachments" {
  count      = length(var.policies)
  role       = aws_iam_role.github_actions.name
  policy_arn = var.policies[count.index]
}

output "role_arn" {
  description = "ARN of the created IAM role"
  value       = aws_iam_role.github_actions.arn
}

output "role_name" {
  description = "Name of the created IAM role"
  value       = aws_iam_role.github_actions.name
}