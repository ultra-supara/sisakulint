package core

# pull_request_target イベントと actions/checkout アクションを使用するワークフローを検出
deny[reason] {
    input.on.pull_request_target
    job := input.jobs[_]
    job.steps[_].uses == "actions/checkout@v2"
    reason := "Workflow uses pull_request_target event with actions/checkout, which may lead to security risks."
}
