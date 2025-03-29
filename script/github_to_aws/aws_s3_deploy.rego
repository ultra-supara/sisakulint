package aws.lambda_deploy
# Lambda更新ポリシーが最小特権を実現しているか
deny[msg] {
  input.resource.aws_iam_policy[name]
  policy := input.resource.aws_iam_policy[name]
  # 名前にlambdaを含むポリシーに適用
  contains(lower(name), "lambda")
  # ポリシードキュメントをパース
  doc := json.unmarshal(policy.policy)
  statements := doc.Statement
  # 必要な最小権限セットが含まれているかチェック
  required_actions := {
    "lambda:UpdateFunctionCode",
    "lambda:GetFunction"
  }
  lambda_actions_found := false
  some i
  statement := statements[i]
  statement.Effect == "Allow"
  actions := to_set(statement.Action)
  # statement.Action が配列でない場合の処理
  actions = {statement.Action} {
    is_string(statement.Action)
  }
  # Lambda関連の権限があるかチェック
  some action in actions
  startswith(action, "lambda:")
  lambda_actions_found = true
  missing := required_actions - actions
  count(missing) > 0
  msg := sprintf("Lambda deploy policy %v is missing required permissions: %v", [name, missing])
}

# ECRの権限があるかチェック (コンテナLambda用)
warn[msg] {
  input.resource.aws_iam_policy[name]
  policy := input.resource.aws_iam_policy[name]

  # 名前にlambdaとecrを含むポリシーに適用
  contains(lower(name), "lambda")
  contains(lower(name), "ecr")

  # ポリシードキュメントをパース
  doc := json.unmarshal(policy.policy)
  statements := doc.Statement

  # 必要なECR権限セット
  required_ecr_actions := {
    "ecr:GetDownloadUrlForLayer",
    "ecr:BatchGetImage",
    "ecr:BatchCheckLayerAvailability"
  }

  ecr_actions_found := false

  some i
  statement := statements[i]
  statement.Effect == "Allow"

  actions := to_set(statement.Action)
  # statement.Action が配列でない場合の処理
  actions = {statement.Action} {
    is_string(statement.Action)
  }

  # ECR関連の権限があるかチェック
  some action in actions
  startswith(action, "ecr:")
  ecr_actions_found = true

  missing := required_ecr_actions - actions
  count(missing) > 0

  msg := sprintf("Lambda with ECR policy %v is missing required ECR permissions: %v", [name, missing])
}

# Lambda関数のリソース制限をチェック
deny[msg] {
  input.resource.aws_iam_policy[name]
  policy := input.resource.aws_iam_policy[name]

  # 名前にlambdaを含むポリシーに適用
  contains(lower(name), "lambda")

  # ポリシードキュメントをパース
  doc := json.unmarshal(policy.policy)
  statements := doc.Statement

  statement := statements[_]
  statement.Effect == "Allow"
  statement.Resource == "*"

  some action in to_set(statement.Action)
  startswith(action, "lambda:")

  # アクションが特定のLambda関数操作のみを許可しているか確認
  action != "lambda:ListFunctions"
  action != "lambda:GetAccountSettings"

  msg := sprintf("Lambda policy %v should restrict Lambda actions to specific functions, not '*'", [name])
}