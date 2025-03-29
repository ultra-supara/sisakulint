# Lambda関数デプロイ用のIAM設定

# Lambda関数デプロイ用GitHub Actions IAMロール
module "github_actions_lambda_deploy" {
  source = "./modules/iam_role_from_github"

  role_name         = "github-actions-lambda-deploy"
  target_repository = var.github_repo
  target_refs       = var.github_allowed_refs

  policies = [
    aws_iam_policy.lambda_deploy.arn
  ]

  openid_connect_provider_github_arn = aws_iam_openid_connect_provider.github.arn

  default_tags = var.default_tags
}

# 参照するECRリポジトリの定義
resource "aws_ecr_repository" "lambda_repo" {
  name                 = var.lambda_ecr_repo_name
  image_tag_mutability = "MUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }

  tags = var.default_tags
}

# 参照するLambda関数の定義（実際の詳細な定義は別ファイルにあると想定）
resource "aws_lambda_function" "app_function" {
  function_name = var.lambda_function_name
  image_uri     = "${aws_ecr_repository.lambda_repo.repository_url}:latest"
  package_type  = "Image"
  role          = aws_iam_role.lambda_execution_role.arn

  tags = var.default_tags
}

# Lambda実行ロール
resource "aws_iam_role" "lambda_execution_role" {
  name = "${var.lambda_function_name}-execution-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Action = "sts:AssumeRole",
        Principal = {
          Service = "lambda.amazonaws.com"
        },
        Effect = "Allow",
        Sid    = ""
      }
    ]
  })

  tags = var.default_tags
}

# 変数定義
variable "lambda_ecr_repo_name" {
  description = "Name of the ECR repository for Lambda container images"
  type        = string
  default     = "lambda-app-repo"
}

variable "lambda_function_name" {
  description = "Name of the Lambda function"
  type        = string
  default     = "app-function"
}