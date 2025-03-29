# 共通変数定義

variable "aws_region" {
  description = "AWS region for all resources"
  type        = string
  default     = "ap-northeast-1"
}

variable "github_repo" {
  description = "GitHub repository in format org/repo"
  type        = string
  default     = "myorg/myrepo"
}

variable "github_allowed_refs" {
  description = "GitHub refs that are allowed to assume the role"
  type        = list(string)
  default     = ["refs/heads/main", "refs/heads/develop"]
}

variable "default_tags" {
  description = "Default tags to be applied to all resources"
  type        = map(string)
  default = {
    Environment = "production"
    ManagedBy   = "terraform"
    Project     = "myproject"
  }
}