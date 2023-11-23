package core

# パスワードがハードコードされているかどうかをチェックするルール
check_credentials[violation] {
    container := input.jobs.test.container
    container.credentials.password
    not is_expression_assigned(container.credentials.password)
    violation := {
        "type": "credential_violation",
        "message": "Password found in container section, do not paste password direct hardcode",
        "position": "container.credentials.password"
    }
}

# サービスごとにチェックする
check_credentials[violation] {
    service := input.jobs.test.services[_]
    service.credentials.password
    not is_expression_assigned(service.credentials.password)
    violation := {
        "type": "credential_violation",
        "message": sprintf("Password found in service section %q, do not paste password direct hardcode", [service.name]),
        "position": "service.credentials.password"
    }
}

# 式が割り当てられているかどうかをチェックするヘルパー関数
is_expression_assigned(password) {
    regex.match(`^\$\{.+\}$`, password)
}
