package core

default job_timeout_missing = false

# Rule: Warn if timeout-minutes is not set at the job level
job_timeout_missing {
    job := input.jobs[_]
    not job["timeout-minutes"]
}

# Rule: Warn if timeout-minutes is not set at the step level
step_timeout_missing[step_name] {
    job := input.jobs[_]
    step := job.steps[_]
    not step["timeout-minutes"]
    step_name := step.name
}

# Generate warning messages
missing_timeout_warnings[result] {
    job_timeout_missing
    result := "Warning: timeout-minutes is not set at the job level."
}

missing_timeout_warnings[result] {
    step_name := step_timeout_missing[_]
    result := sprintf("Warning: timeout-minutes is not set for step '%v'.", [step_name])
}
