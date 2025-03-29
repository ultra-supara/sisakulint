# ECSデプロイ用のIAM設定

# ECSデプロイ用のポリシー
resource "aws_iam_policy" "ecs_deploy" {
  name = "ecs-deploy-policy"
  path = "/"
  description = "Policy for deploying to ECS"
  policy = jsonencode({
    Version = "2012-10-17",
    Statement =[
      {
        Action =[
          "ecr:GetDownloadUrlForLayer",
          "ecr:BatchGetImage",
          "ecr:BatchCheckLayerAvailability",
          "ecr:InitiateLayerUpload",
          "ecr:UploadLayerPart",
          "ecr:CompleteLayerUpload",
          "ecr:PutImage",
        ],
        Effect = "Allow",
        Resource =[
          aws_ecr_repository.app_repo.arn,
        ]
      },
      {
        Action =[
          "ecr:GetAuthorizationToken",
        ],
        Effect   = "Allow",
        Resource = "*"
      },
      # ECSデプロイ用のIAM設定
      {
        Effect = "Allow",
        Action = [
          "ecs:DescribeServices",
          "ecs:UpdateService",
        ],
        Resource = [
          "arn:aws:ecs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:service/${var.ecs_cluster_name}/${var.ecs_service_name}",
        ]
      },
      {
        Effect = "Allow",
        Action = [
          "ecs:DescribeTaskDefinition",
          "ecs:RegisterTaskDefinition",
        ],
        Resource = "*"
      },
      {
        Effect = "Allow",
        Action = "ecs:RunTask",
        Resource = [
          "arn:aws:ecs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:task-definition/${var.task_definition_family_name}:*",
        ]
      },
      {
        Effect = "Allow",
        Action = "ecs:DescribeTasks",
        Resource = [
          "arn:aws:ecs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:task/${var.ecs_cluster_name}/*"
        ]
      },
      {
        Effect = "Allow",
        Action = "iam:PassRole",
        Resource = [
          aws_iam_role.task_role.arn,
          aws_iam_role.task_execution_role.arn,
        ],
        Condition = {
          StringEquals = {
            "iam:PassedToService" = [
              "ecs-tasks.amazonaws.com"
            ]
          },
          ArnLike = {
            "iam:AssociatedResourceARN" = [
              "arn:aws:ecs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:task-definition/${var.task_definition_family_name}",
              "arn:aws:ecs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:task-definition/${var.task_definition_family_name}:*",
            ]
          }
        }
      }
    ]
  })
  tags = var.default_tags
}
# ECSデプロイ用GitHub Actions IAMロール
module "github_actions_ecs_deploy" {
  source = "./modules/iam_role_from_github"
  role_name         = "github-actions-ecs-deploy"
  target_repository = var.github_repo
  target_refs       = var.github_allowed_refs
  policies = [
    aws_iam_policy.ecs_deploy.arn
  ]
  openid_connect_provider_github_arn = aws_iam_openid_connect_provider.github.arn
  default_tags = var.default_tags
}
# ECRリポジトリ
resource "aws_ecr_repository" "app_repo" {
  name                 = var.app_repo_name
  image_tag_mutability = "MUTABLE"
  image_scanning_configuration {
    scan_on_push = true
  }
  tags = var.default_tags
}

# ECSタスクロール
resource "aws_iam_role" "task_role" {
  name = "${var.ecs_service_name}-task-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Action = "sts:AssumeRole",
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        },
        Effect = "Allow",
        Sid    = ""
      }
    ]
  })

  tags = var.default_tags
}

# ECSタスク実行ロール
resource "aws_iam_role" "task_execution_role" {
  name = "${var.ecs_service_name}-task-execution-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Action = "sts:AssumeRole",
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        },
        Effect = "Allow",
        Sid    = ""
      }
    ]
  })

  tags = var.default_tags
}

# 基本的なタスク実行ポリシーのアタッチ
resource "aws_iam_role_policy_attachment" "task_execution_role_policy" {
  role       = aws_iam_role.task_execution_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

# 変数定義
variable "ecs_cluster_name" {
  description = "Name of the ECS cluster"
  type        = string
  default     = "app-cluster"
}

variable "ecs_service_name" {
  description = "Name of the ECS service"
  type        = string
  default     = "app-service"
}

variable "task_definition_family_name" {
  description = "Family name of the task definition"
  type        = string
  default     = "app-task"
}

variable "app_repo_name" {
  description = "Name of the ECR repository for the application"
  type        = string
  default     = "app-repo"
}