package core

# クレデンシャルを含む環境変数が必要なステップのリスト
credential_required_steps := {"deploy", "build"}

# クレデンシャルを含む環境変数が不要なステップのリスト
credential_not_required_steps := {"test", "lint"}

# 外部アクションの安全性を確認する
external_action_is_safe {
    step := input.jobs[_].steps[_]
    action := step.uses
    startswith(action, "actions/")  # 公式アクションは安全と仮定
    not contains(action, "@latest") # 最新版ではなく、特定のバージョンまたはコミットハッシュを使用
}

# クレデンシャルを含む環境変数が必要なステップでのみ使用されていることを確認
credential_usage_is_valid {
    step := input.jobs[_].steps[_]
    step.env[credential]
    credential_required_steps[step.name]
}

# クレデンシャルを含む環境変数が不要なステップで使用されていないことを確認
credential_usage_is_invalid {
    step := input.jobs[_].steps[_]
    step.env[credential]
    credential_not_required_steps[step.name]
}

# エラーメッセージを生成
generate_error_messages[msg] {
    not external_action_is_safe
    msg := "Error: External actions must be secure. Use a specific version or commit hash."
}

generate_error_messages[msg] {
    credential_usage_is_invalid
    msg := "Error: Environment variables containing credentials should only be used in necessary steps."
}
