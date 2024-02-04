package core

# Detect direct usage of ${{ ... }} in run scripts and suggest using env
deny[reason] {
    some i, j
    step := input.jobs[i].steps[j]
    script := step.run

    # Check if ${{ ... }} is used directly in the script
    regex.match(`\$\{\{.*\}\}`, script)

    # Suggest using env for setting variables
    not step.env

    reason := sprintf("Direct usage of ${{ ... }} in run script detected at jobs.%v.steps.%v. Use env to set variables.", [i, j])
}
