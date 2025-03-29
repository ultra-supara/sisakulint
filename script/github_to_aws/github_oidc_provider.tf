# GitHub Actions用のOIDC IDプロバイダー設定

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 4.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

data "aws_caller_identity" "current" {}

# GitHub ActionsのOIDCプロバイダー
resource "aws_iam_openid_connect_provider" "github" {
  url             = "https://token.actions.githubusercontent.com"
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = ["6938fd4d98bab03faadb97b34396831e3780aea1"]  # GitHub OIDC最新のサムプリント

  tags = var.default_tags
}

# 変数定義
variable "aws_region" {
  description = "AWS region for all resources"
  type        = string
  default     = "ap-northeast-1"
}

variable "default_tags" {
  description = "Default tags to be applied to all resources"
  type        = map(string)
  default = {
    Environment = "production"
    ManagedBy   = "terraform"
  }
}