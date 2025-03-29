# S3コンテンツデプロイ用のIAM設定

resource "aws_iam_policy" "s3_deploy" {
  name        = "s3-deploy-policy"
  path        = "/"
  description = "Policy for deploying content to S3 and invalidating CloudFront"

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Action = [
          "s3:ListBucket",
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject"
        ],
        Effect = "Allow",
        Resource = [
          aws_s3_bucket.website_bucket.arn,
          "${aws_s3_bucket.website_bucket.arn}/*"
        ]
      },
      {
        Action = [
          "cloudfront:CreateInvalidation"
        ],
        Effect = "Allow",
        Resource = [
          "arn:aws:cloudfront::${data.aws_caller_identity.current.account_id}:distribution/*"
        ]
      }
    ]
  })

  tags = var.default_tags
}

# S3デプロイ用GitHub Actions IAMロール
module "github_actions_s3_deploy" {
  source = "./modules/iam_role_from_github"

  role_name         = "github-actions-s3-deploy"
  target_repository = var.github_repo
  target_refs       = var.github_allowed_refs

  policies = [
    aws_iam_policy.s3_deploy.arn
  ]

  openid_connect_provider_github_arn = aws_iam_openid_connect_provider.github.arn

  default_tags = var.default_tags
}

# アクセスするS3バケットのデータリソース（実際の定義は別ファイルにあると想定）
resource "aws_s3_bucket" "website_bucket" {
  bucket = var.website_bucket_name

  tags = var.default_tags
}

variable "website_bucket_name" {
  description = "Name of the S3 bucket for website content"
  type        = string
  default     = "my-website-bucket"
}