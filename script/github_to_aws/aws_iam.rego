package aws.iam
# OIDC設定のチェック
deny[msg] {
  input.resource.aws_iam_openid_connect_provider[name]
  provider := input.resource.aws_iam_openid_connect_provider[name]
  not provider.url = "https://token.actions.githubusercontent.com"
  msg := sprintf("OIDC provider %v is not configured for GitHub Actions", [name])
}
# クライアントIDリストのチェック
deny[msg] {
  input.resource.aws_iam_openid_connect_provider[name]
  provider := input.resource.aws_iam_openid_connect_provider[name]
  not contains(provider.client_id_list, "sts.amazonaws.com")
  msg := sprintf("OIDC provider %v must include sts.amazonaws.com in client_id_list", [name])
}
# ロール信頼ポリシーがOIDCフェデレーションを使用しているか
deny[msg] {
  input.resource.aws_iam_role[name]
  role := input.resource.aws_iam_role[name]
  policy := json.unmarshal(role.assume_role_policy)
  statements := policy.Statement
  count([s | s = statements[_]; s.Action = "sts:AssumeRoleWithWebIdentity"; s.Principal.Federated]) == 0
  # 名前に"github"が含まれるロールの場合だけチェック
  contains(lower(name), "github")
  msg := sprintf("IAM role %v should use AssumeRoleWithWebIdentity for GitHub Actions OIDC", [name])
}
# ワイルドカードの使用制限チェック
warn[msg] {
  input.resource.aws_iam_policy[name]
  policy := input.resource.aws_iam_policy[name]
  # ポリシードキュメントをパース
  doc := json.unmarshal(policy.policy)
  statements := doc.Statement
  statement := statements[_]
  statement.Effect == "Allow"
  statement.Action[_] == "*"
  statement.Resource == "*"
  msg := sprintf("IAM policy %v contains Allow with wildcard action and resource, which violates least privilege principle", [name])
}
# 特定のリスクの高い権限のチェック
warn[msg] {
  input.resource.aws_iam_policy[name]
  policy := input.resource.aws_iam_policy[name]
  # ポリシードキュメントをパース
  doc := json.unmarshal(policy.policy)
  statements := doc.Statement
  statement := statements[_]
  statement.Effect == "Allow"

  # リスクの高い権限のリスト
  high_risk_actions := {
    "iam:CreateUser",
    "iam:DeleteUser",
    "iam:CreateAccessKey",
    "iam:CreateLoginProfile",
    "iam:AttachUserPolicy",
    "iam:AttachRolePolicy",
    "lambda:AddPermission",
    "ec2:RunInstances",
    "ec2:CreateSecurityGroup",
    "cloudformation:CreateStack",
    "s3:PutBucketPolicy",
    "s3:PutAccountPublicAccessBlock",
    "kms:Decrypt",
    "kms:CreateGrant"
  }

  actions := to_set(statement.Action)
  intersection := actions & high_risk_actions
  count(intersection) > 0

  msg := sprintf("IAM policy %v contains high-risk permissions: %v", [name, intersection])
}

# パスロールのチェック（条件制限がされているか）
deny[msg] {
  input.resource.aws_iam_policy[name]
  policy := input.resource.aws_iam_policy[name]

  # ポリシードキュメントをパース
  doc := json.unmarshal(policy.policy)
  statements := doc.Statement

  statement := statements[_]
  statement.Effect == "Allow"
  statement.Action = "iam:PassRole"

  not statement.Condition

  msg := sprintf("IAM policy %v allows iam:PassRole without condition restrictions", [name])
}

# タグが設定されているかチェック
warn[msg] {
  input.resource.aws_iam_role[name]
  role := input.resource.aws_iam_role[name]
  not role.tags

  msg := sprintf("IAM role %v should have tags for better resource management", [name])
}