# 出力値の定義
output "github_oidc_provider_arn" {
  description = "ARN of the GitHub OIDC provider"
  value       = aws_iam_openid_connect_provider.github.arn
}
output "s3_deploy_role_arn" {
  description = "ARN of the S3 deployment role"
  value       = module.github_actions_s3_deploy.role_arn
}
output "lambda_deploy_role_arn" {
  description = "ARN of the Lambda deployment role"
  value       = module.github_actions_lambda_deploy.role_arn
}
output "ecs_deploy_role_arn" {
  description = "ARN of the ECS deployment role"
  value       = module.github_actions_ecs_deploy.role_arn
}
output "website_bucket_name" {
  description = "Name of the S3 bucket for website content"
  value       = aws_s3_bucket.website_bucket.bucket
}

output "lambda_function_name" {
  description = "Name of the Lambda function"
  value       = aws_lambda_function.app_function.function_name
}

output "ecr_repository_url" {
  description = "URL of the ECR repository for the application"
  value       = aws_ecr_repository.app_repo.repository_url
}

output "lambda_ecr_repository_url" {
  description = "URL of the ECR repository for Lambda container images"
  value       = aws_ecr_repository.lambda_repo.repository_url
}

output "ecs_service_name" {
  description = "Name of the ECS service"
  value       = var.ecs_service_name
}

output "ecs_cluster_name" {
  description = "Name of the ECS cluster"
  value       = var.ecs_cluster_name
}
