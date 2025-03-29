package core

default job_secrets_set = false

# ワークフローに複数のジョブがあるかどうかを確認
multiple_jobs {
    count(input.jobs) > 1
}

# 各ジョブでシークレットが環境変数として設定されているかを確認
job_secrets_set {
    multiple_jobs
    job := input.jobs[_]
    job.env
}

# 各ステップでシークレットが環境変数として設定されているかを確認
step_secrets_set {
    multiple_jobs
    job := input.jobs[_]
    step := job.steps[_]
    step.env
}

# エラーメッセージを生成
missing_secrets_warnings[result] {
    not job_secrets_set
    result := "Warning: Secrets should be set at the job level in each job's env."
}

missing_secrets_warnings[result] {
    not step_secrets_set
    result := "Warning: Secrets should be set at the step level in each step's env."
}
