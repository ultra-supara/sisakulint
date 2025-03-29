# Brief README

## actions

## github_to_aws（GitHub Actions CI/CD infrastructure for AWS ）
This repository contains Terraform code for the IAM configuration needed to deploy from GitHub Actions to AWS resources (S3, Lambda, ECS).
### Features 
- Secure AWS authentication using GitHub OIDC authentication 
- Short term token-based authentication without client secret 
- IAM role for S3 website deployment 
- IAM role for Lambda function updates 
- IAM role for ECS service updates
 
### Architecture 
This infrastructure setup federates GitHub Actions' OpenID Connect (OIDC) with AWS to obtain temporary credentials during workflow execution. Create dedicated IAM roles based on the principle of least privilege for various deployment tasks.

### Prerequisites 
- AWS account 
- Local environment with Terraform installed (version 1.0 or higher) 
- Local environment with AWS CLI installed and configured 
- Administrative rights to GitHub repository 

### Setup instructions 

#### 1. Clone repository 

#### 2. Set up variables 
Edit the variables.tf file and set up the following variables for your environment: 
- github_repo: your GitHub repository (in the form of "org/repo") 
- github_allowed_refs: roles you can take on GitHub references (branches or tags) 
- other variables as needed 
or you can create a `terraform.tfvars` file and set variables

```hcl
aws_region = "us-west-2" 
github_repo = "myorg/ myrepo" 
github_allowed_refs = ["refs/heads/main", "refs/heads/develop"] 
website_bucket_name = "my-website-bucket" 
lambda_function_name = "my -function" 
ecs_cluster_name = "my-cluster" 
ecs_service_name = "my-service"
```

#### 3. Initialize and apply Terraform

```bash
terraform init 
terraform plan 
terraform apply
```

#### 4. Configure GitHub Secrets 
Set the GitHub repository secret to the role ARN, etc. output after Terraform execution. You can check the output values with the following command: 
```bash
terraform output
```

## GitHub Actions workflow examples 

これらのIAMロールを使用する際のGitHub Actionsワークフローの例です。

### S3デプロイワークフローの例

```yaml
name: Deploy to S3

on:
  push:
    branches: [ main ]

jobs:
  deploy:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
      contents: read
    
    steps:
      - uses: actions/checkout@v3
      
      - name: Configure AWS Credentials
        uses: aws-actions/configure-aws-credentials@v2
        with:
          role-to-assume: ${{ secrets.AWS_ROLE_ARN_S3_DEPLOY }}
          aws-region: ap-northeast-1
      
      - name: Build website
        run: |
          npm ci
          npm run build
      
      - name: Deploy to S3
        run: aws s3 sync ./build s3://${{ secrets.S3_BUCKET_NAME }} --delete
      
      - name: Invalidate CloudFront
        run: |
          aws cloudfront create-invalidation \
            --distribution-id ${{ secrets.CLOUDFRONT_DISTRIBUTION_ID }} \
            --paths "/*"
```

### Lambdaデプロイワークフローの例
```yaml
name: Deploy Lambda Function
on:
  push:
    branches: [ main ]
jobs:
  deploy:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
      contents: read
    steps:
      - uses: actions/checkout@v3
      - name: Configure AWS Credentials
        uses: aws-actions/configure-aws-credentials@v2
        with:
          role-to-assume: ${{ secrets.AWS_ROLE_ARN_LAMBDA_DEPLOY }}
          aws-region: ap-northeast-1
      - name: Login to Amazon ECR
        id: login-ecr
        uses: aws-actions/amazon-ecr-login@v1
      - name: Build, tag, and push image to Amazon ECR
        env:
          ECR_REGISTRY: ${{ steps.login-ecr.outputs.registry }}
          ECR_REPOSITORY: ${{ secrets.LAMBDA_ECR_REPO_NAME }}
          IMAGE_TAG: ${{ github.sha }}
        run: |
          docker build -t $ECR_REGISTRY/$ECR_REPOSITORY:$IMAGE_TAG -t $ECR_REGISTRY/$ECR_REPOSITORY:latest .
          docker push $ECR_REGISTRY/$ECR_REPOSITORY:$IMAGE_TAG
          docker push $ECR_REGISTRY/$ECR_REPOSITORY:latest
      
      - name: Update Lambda Function
        run: |
          aws lambda update-function-code \
            --function-name ${{ secrets.LAMBDA_FUNCTION_NAME }} \
            --image-uri ${{ steps.login-ecr.outputs.registry }}/${{ secrets.LAMBDA_ECR_REPO_NAME }}:${{ github.sha }} \
            --publish
      
      - name: Update Lambda Alias
        run: |
          VERSION=$(aws lambda publish-version \
            --function-name ${{ secrets.LAMBDA_FUNCTION_NAME }} \
            --description "Deployed via GitHub Actions" \
            --query "Version" --output text)
            
          aws lambda update-alias \
            --function-name ${{ secrets.LAMBDA_FUNCTION_NAME }} \
            --name production \
            --function-version $VERSION
```

### ECSデプロイワークフローの例
```yaml
name: Deploy to ECS
on:
  push:
    branches: [ main ]
jobs:
  deploy:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
      contents: read
    steps:
      - uses: actions/checkout@v3
      - name: Configure AWS Credentials
        uses: aws-actions/configure-aws-credentials@v2
        with:
          role-to-assume: ${{ secrets.AWS_ROLE_ARN_ECS_DEPLOY }}
          aws-region: ap-northeast-1
      - name: Login to Amazon ECR
        id: login-ecr
        uses: aws-actions/amazon-ecr-login@v1
      - name: Build, tag, and push image to Amazon ECR
        env:
          ECR_REGISTRY: ${{ steps.login-ecr.outputs.registry }}
          ECR_REPOSITORY: ${{ secrets.ECR_REPOSITORY_NAME }}
          IMAGE_TAG: ${{ github.sha }}
        run: |
          docker build -t $ECR_REGISTRY/$ECR_REPOSITORY:$IMAGE_TAG .
          docker push $ECR_REGISTRY/$ECR_REPOSITORY:$IMAGE_TAG
      - name: Get current task definition
        run: |
          aws ecs describe-task-definition \
            --task-definition ${{ secrets.ECS_TASK_FAMILY }} \
            --query taskDefinition > task-definition.json
      - name: Update container image in task definition
        run: |
          jq --arg IMAGE "${{ steps.login-ecr.outputs.registry }}/${{ secrets.ECR_REPOSITORY_NAME }}:${{ github.sha }}" \
            '.containerDefinitions[0].image = $IMAGE' task-definition.json > new-task-definition.json
      - name: Register new task definition
        id: register-task-definition
        run: |
          NEW_TASK_DEF=$(aws ecs register-task-definition \
            --cli-input-json file://new-task-definition.json \
            --query 'taskDefinition.taskDefinitionArn' --output text)
          echo "::set-output name=task_definition_arn::$NEW_TASK_DEF"
      - name: Update ECS service
        run: |
          aws ecs update-service \
            --cluster ${{ secrets.ECS_CLUSTER_NAME }} \
            --service ${{ secrets.ECS_SERVICE_NAME }} \
            --task-definition ${{ steps.register-task-definition.outputs.task_definition_arn }} \
            --force-new-deployment
      - name: Wait for service to be stable
        run: |
          aws ecs wait services-stable \
            --cluster ${{ secrets.ECS_CLUSTER_NAME }} \
            --services ${{ secrets.ECS_SERVICE_NAME }}
```

### 複合ワークフローの例（フロントエンドとバックエンド両方のデプロイ）
```yaml
name: Full Stack Deployment
on:
  push:
    branches: [ main ]
jobs:
  deploy-backend:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
      contents: read
    steps:
      - uses: actions/checkout@v3
      - name: Configure AWS Credentials for Backend
        uses: aws-actions/configure-aws-credentials@v2
        with:
          role-to-assume: ${{ secrets.AWS_ROLE_ARN_ECS_DEPLOY }}
          aws-region: ap-northeast-1
      - name: Login to Amazon ECR
        id: login-ecr
        uses: aws-actions/amazon-ecr-login@v1
      - name: Build, tag, and push backend image
        env:
          ECR_REGISTRY: ${{ steps.login-ecr.outputs.registry }}
          ECR_REPOSITORY: ${{ secrets.BACKEND_ECR_REPO }}
          IMAGE_TAG: ${{ github.sha }}
        run: |
          cd backend
          docker build -t $ECR_REGISTRY/$ECR_REPOSITORY:$IMAGE_TAG .
          docker push $ECR_REGISTRY/$ECR_REPOSITORY:$IMAGE_TAG
      - name: Update ECS Service
        run: |
          cd backend/infrastructure
          # Get current task definition
          aws ecs describe-task-definition \
            --task-definition ${{ secrets.BACKEND_TASK_FAMILY }} \
            --query taskDefinition > task-definition.json
          # Update container image in task definition
          jq --arg IMAGE "${{ steps.login-ecr.outputs.registry }}/${{ secrets.BACKEND_ECR_REPO }}:${{ github.sha }}" \
            '.containerDefinitions[0].image = $IMAGE' task-definition.json > new-task-definition.json
          # Register new task definition
          NEW_TASK_DEF=$(aws ecs register-task-definition \
            --cli-input-json file://new-task-definition.json \
            --query 'taskDefinition.taskDefinitionArn' --output text)
          # Update service with new task definition
          aws ecs update-service \
            --cluster ${{ secrets.ECS_CLUSTER_NAME }} \
            --service ${{ secrets.BACKEND_SERVICE_NAME }} \
            --task-definition $NEW_TASK_DEF \
            --force-new-deployment
  deploy-frontend:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
      contents: read
    needs: deploy-backend # Make sure backend is deployed first
    steps:
      - uses: actions/checkout@v3
      - name: Configure AWS Credentials for Frontend
        uses: aws-actions/configure-aws-credentials@v2
        with:
          role-to-assume: ${{ secrets.AWS_ROLE_ARN_S3_DEPLOY }}
          aws-region: ap-northeast-1
      - name: Setup Node.js
        uses: actions/setup-node@v3
        with:
          node-version: '16'
          cache: 'npm'
          cache-dependency-path: frontend/package-lock.json
      - name: Build Frontend
        run: |
          cd frontend
          npm ci
          # Pass backend URL to the build process
          REACT_APP_API_URL=${{ secrets.BACKEND_API_URL }} npm run build
      - name: Deploy to S3
        run: |
          cd frontend
          aws s3 sync ./build s3://${{ secrets.FRONTEND_S3_BUCKET }} --delete
      
      - name: Invalidate CloudFront
        run: |
          aws cloudfront create-invalidation \
            --distribution-id ${{ secrets.CLOUDFRONT_DISTRIBUTION_ID }} \
            --paths "/*"
```

### Guidelines for setting up the secret 
Set the following secret in the GitHub repository
1. For S3 deployments: 
 - `AWS_ROLE_ARN_S3_DEPLOY`: ARN of the IAM role for S3 deployments 
 - `S3_BUCKET_NAME`: Name of the S3 bucket to deploy to 
 - `CLOUDFRONT_DISTRIBUTION_ID`: CloudFront distribution ID 
2. for Lambda function deployment: 
 - `AWS_ROLE_ARN_LAMBDA_DEPLOY`: ARN of IAM role for Lambda update 
 - `LAMBDA_ECR_REPO_ NAME`: ECR repository name of container image for Lambda 
 - `LAMBDA_FUNCTION_NAME`: Lambda function name to update 
3. For ECS deployment: 
 - `AWS_ROLE_ARN_ECS_DEPLOY`: ARN of IAM role for ECS deployment 
 - `ECR_ REPOSITORY_NAME`: ECR repository name for application image 
 - `ECS_TASK_FAMILY`: ECS task definition family name 
 - `ECS_CLUSTER_NAME`: ECS cluster name 
 - `ECS_SERVICE_NAME`: ECS service name for update 
4. For composite deployments: 
 - `BACKEND_ECR_REPO`: ECR repository name for backend apps 
 - `BACKEND_TASK_FAMILY`: Family name for backend task definition 
 - `BACKEND_SERVICE_NAME`: ECS service name for backend 
 - `FRONTEND _S3_BUCKET`: Front-end S3 bucket name 
 - `BACKEND_API_URL`: Back-end API URL (used during front-end build)


#### ref
- [AWS IAM OIDC with GitHub Actions](https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/configuring-openid-connect-in-amazon-web-services)
- [AWS IAM Documentation](https://docs.aws.amazon.com/IAM/latest/UserGuide/introduction.html)
- [Terraform AWS Provider Documentation](https://registry.terraform.io/providers/hashicorp/aws/latest/docs)