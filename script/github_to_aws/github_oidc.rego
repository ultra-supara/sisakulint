package github.oidc
# OIDCプロバイダーが設定されているか確認
deny[msg] {
  count([name | input.resource.aws_iam_openid_connect_provider[name]]) == 0
  msg := "No GitHub OIDC provider defined for secure GitHub Actions authentication"
}
# ロールが有効なAudience値を使用しているか確認
deny[msg] {
  input.resource.aws_iam_role[name]
  role := input.resource.aws_iam_role[name]
  # GitHub Actionsのロールのみにフォーカス
  contains(lower(name), "github")
  policy := json.unmarshal(role.assume_role_policy)
  statements := policy.Statement
  some i
  statement := statements[i]
  statement.Principal.Federated
  statement.Action == "sts:AssumeRoleWithWebIdentity"
  not statement.Condition.StringEquals["token.actions.githubusercontent.com:aud"]
  msg := sprintf("GitHub OIDC role %v must validate the 'aud' claim", [name])
}
# ロールがリポジトリとブランチを制限しているか確認
deny[msg] {
  input.resource.aws_iam_role[name]
  role := input.resource.aws_iam_role[name]
  # GitHub Actionsのロールのみにフォーカス
  contains(lower(name), "github")
  policy := json.unmarshal(role.assume_role_policy)
  statements := policy.Statement
  some i
  statement := statements[i]
  statement.Principal.Federated
  statement.Action == "sts:AssumeRoleWithWebIdentity"
  not statement.Condition.StringLike["token.actions.githubusercontent.com:sub"]
  msg := sprintf("GitHub OIDC role %v must restrict access to specific repositories and branches", [name])
}
# ワイルドカードだけのリポジトリ制限をチェック
warn[msg] {
  input.resource.aws_iam_role[name]
  role := input.resource.aws_iam_role[name]
  # GitHub Actionsのロールのみにフォーカス
  contains(lower(name), "github")
  policy := json.unmarshal(role.assume_role_policy)
  statements := policy.Statement
  some i
  statement := statements[i]
  statement.Principal.Federated
  statement.Action == "sts:AssumeRoleWithWebIdentity"
  subs := statement.Condition.StringLike["<http://token.actions.githubusercontent.com:sub%7Ctoken.actions.githubusercontent.com:sub>"]
  subs := statement.Condition.StringLike["token.actions.githubusercontent.com:sub"]

  some sub in subs
  sub == "repo:*"

  msg := sprintf("GitHub OIDC role %v uses wildcard for repository which is too permissive", [name])
}

# mainブランチ以外のブランチに対する警告
warn[msg] {
  input.resource.aws_iam_role[name]
  role := input.resource.aws_iam_role[name]

  # GitHub Actionsのロールのみにフォーカス
  contains(lower(name), "github")

  policy := json.unmarshal(role.assume_role_policy)
  statements := policy.Statement

  some i
  statement := statements[i]
  statement.Principal.Federated
  statement.Action == "sts:AssumeRoleWithWebIdentity"

  subs := statement.Condition.StringLike["token.actions.githubusercontent.com:sub"]

  some sub in subs
  not contains(sub, "refs/heads/main")
  not contains(sub, "refs/tags/")

  msg := sprintf("GitHub OIDC role %v allows branches other than main, verify this is intended: %v", [name, sub])
}
