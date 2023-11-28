package core

#rule : jobs.<job_id>.secrets.inheritとなっている場合にdeny
# Rule: Warn if 'secrets' is set to 'inherit' at the job level
secrets_inherit_used[job_id] {
    job := input.jobs[job_id]
    job.secrets == "inherit"
}

# Generate warning messages
missing_secrets_warnings[result] {
    job_id := secrets_inherit_used[_]
    result := sprintf("Warning: 'secrets' should not be set to 'inherit' for job '%v'.", [job_id])
}
