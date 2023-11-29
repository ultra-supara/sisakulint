package core

default job_permissions_missing = false

# ルール: ジョブレベルでのpermissionsが設定されていない場合に警告
job_permissions_missing {
    job := input.jobs[_]
    not job.permissions
}

# 警告メッセージを生成
missing_permissions_warnings[result] {
    job_permissions_missing
    result := "Warning: 'permissions' is not set at the job level."
}
