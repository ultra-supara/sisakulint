# GitHub ActionsからIAMロールを引き受けるための共通モジュール

module "iam_role_from_github" {
  source = "./modules/iam_role_from_github"

  target_repository = var.github_repo
  target_refs       = var.github_allowed_refs

  policies          = []  # 各利用側で具体的なポリシーを指定

  openid_connect_provider_github_arn = aws_iam_openid_connect_provider.github.arn

  default_tags = var.default_tags
}

# 変数定義
variable "github_repo" {
  description = "GitHub repository in format org/repo"
  type        = string
  default     = "myorg/myrepo"
}

variable "github_allowed_refs" {
  description = "GitHub refs that are allowed to assume the role"
  type        = list(string)
  default     = ["refs/heads/main"]
}