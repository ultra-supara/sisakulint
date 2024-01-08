package core

default action_ref_not_sha = false

# Rule: Warn if the action ref is not a full length commit SHA and not an official GitHub Action
action_ref_not_sha {
    job := input.jobs[_]
    step := job.steps[_]
    uses := step.uses
    not is_official_action(uses)
    not is_full_length_sha(uses)
}

# Helper function to check if the action ref is a full length commit SHA
is_full_length_sha(ref) {
    is_commit := regex.match(`^.+@([0-9a-f]{40})$`, ref)
    is_commit
}

# Helper function to check if the action is an official GitHub Action
is_official_action(ref) {
    is_official := regex.match(`^actions\/.+`, ref)
    is_official
}

# Generate warning messages
missing_action_ref_sha_warnings[result] {
    action_ref_not_sha
    result := "Warning: The action ref in 'uses' should be a full length commit SHA for immutability and security, unless it's an official GitHub Action. see documents : https://docs.github.com/ja/actions/security-guides/security-hardening-for-github-actions#using-third-party-actions [security-hardening]"
}
