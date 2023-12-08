package core

# プルリクエストのタイトルを使用するステップを検出
deny[reason] {
    input.jobs[_].steps[_].run
    regex.match(`\$\{\{\s*github\.event\.pull_request\.title\s*\}\}`, input.jobs[_].steps[_].run)
    reason := "Pull request title is used in the workflow without sanitization."
}
