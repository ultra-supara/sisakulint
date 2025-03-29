ackage aws.ecs_deploy
# ECSデプロイポリシーが最小特権を実現しているか
deny[msg] {
  input.resource.aws_iam_policy[name]
  policy := input.resource.aws_iam_policy[name]
  # 名前にecsを含むポリシーに適用
  contains(lower(name), "ecs")
  # ポリシードキュメントをパース
  doc := json.unmarshal(policy.policy)
  statements := doc.Statement
  # 必要な最小権限セットが含まれているかチェック
  required_actions := {
    "ecs:DescribeServices",
    "ecs:UpdateService",
    "ecs:DescribeTaskDefinition",
    "ecs:RegisterTaskDefinition"
  }
  ecs_actions_found := false
  some i
  statement := statements[i]
  statement.Effect == "Allow"

  actions := to_set(statement.Action)
  # statement.Action が配列でない場合の処理
  actions = {statement.Action} {
    is_string(statement.Action)
  }
  # ECS関連の権限があるかチェック
  some action in actions
  startswith(action, "ecs:")
  ecs_actions_found = true
  missing := required_actions - actions
  count(missing) > 0
  msg := sprintf("ECS deploy policy %v is missing required permissions: %v", [name, missing])
}
# ECRの権限があるかチェック (ECSデプロイ用)
deny[msg] {
  input.resource.aws_iam_policy[name]
  policy := input.resource.aws_iam_policy[name]
  # 名前にecsとecrを含むポリシーに適用
  contains(lower(name), "ecs")
  # ポリシードキュメントをパース
  doc := json.unmarshal(policy.policy)
  statements := doc.Statement
  # ECS権限があるかチェック
  ecs_permissions_found := false
  some i
  statement := statements[i]
  statement.Effect == "Allow"
  actions := to_set(statement.Action)
  # statement.Action が配列でない場合の処理
  actions = {statement.Action} {
    is_string(statement.Action)
  }
  # ECSのデプロイアクションがあるかチェック
  some action in actions
  action == "ecs:UpdateService"
  ecs_permissions_found = true
  # ECR権限があるかチェック
  ecr_found := false
  some j
  statement2 := statements[j]
  statement2.Effect == "Allow"
  actions2 := to_set(statement2.Action)
  # statement2.Action が配列でない場合の処理
  actions2 = {statement2.Action} {
    is_string(statement2.Action)
  }
  some action2 in actions2
  startswith(action2, "ecr:")
  ecr_found = true
  ecs_permissions_found
  not ecr_found
  msg := sprintf("ECS deploy policy %v should include ECR permissions for image deployment", [name])
}
# iam:PassRole制限をチェック
deny[msg] {
  input.resource.aws_iam_policy[name]
  policy := input.resource.aws_iam_policy[name]
  # 名前にecsを含むポリシーに適用
  contains(lower(name), "ecs")
  # ポリシードキュメントをパース
  doc := json.unmarshal(policy.policy)
  statements := doc.Statement
  statement := statements[_]
  statement.Effect == "Allow"
  actions := to_set(statement.Action)
  # statement.Action が配列でない場合の処理
  actions = {statement.Action} {
    is_string(statement.Action)
  }
  "iam:PassRole" in actions
  # Condition制限がないかチェック
  not statement.Condition
  msg := sprintf("ECS policy %v with iam:PassRole should have Condition restrictions", [name])
}
# ECSサービスとタスクの特定のリソース制限をチェック
warn[msg] {
  input.resource.aws_iam_policy[name]
  policy := input.resource.aws_iam_policy[name]
  # 名前にecsを含むポリシーに適用
  contains(lower(name), "ecs")
  # ポリシードキュメントをパース
  doc := json.unmarshal(policy.policy)
  statements := doc.Statement

  statement := statements[_]
  statement.Effect == "Allow"
  statement.Resource == "*"

  actions := to_set(statement.Action)
  # statement.Action が配列でない場合の処理
  actions = {statement.Action} {
    is_string(statement.Action)
  }

  some action in actions
  action == "ecs:UpdateService" # UpdateServiceは特定のサービスに限定すべき

  msg := sprintf("ECS policy %v should restrict ecs:UpdateService to specific services, not '*'", [name])
}
