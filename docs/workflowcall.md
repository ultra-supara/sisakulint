---
title: "Workflow Call Rule"
weight: 1
---

### Workflow Call Rule Overview

This rule validates the syntax and configuration of reusable workflow calls in GitHub Actions. It detects common misconfigurations that can cause workflow failures or unexpected behavior when using the `uses:` keyword to call reusable workflows.

**Invalid Example:**

```yaml
on: push
jobs:
  job1:
    uses: ultra-supara/sisakulint/workflow.yml@v1
    runs-on: ubuntu-latest  # Error: runs-on not allowed with uses
  job2:
    uses: ./.github/workflows/ci.yml@main  # Error: local path with ref
  job3:
    with:
      foo: bar  # Error: with without uses
    runs-on: ubuntu-latest
    steps:
      - run: echo hello
```

**Detection Output:**

```bash
a.yaml:6:5: when a reusable workflow is called with "uses", "runs-on" is not available. only following keys are allowed: "name", "uses", "with", "secrets", "needs", "if", and "permissions" in job "job1" [syntax]
      6 👈|    runs-on: ubuntu-latest

a.yaml:9:11: reusable workflow call "./.github/workflows/ci.yml@main" at uses is not following the format "owner/repo/path/to/workflow.yml@ref" nor "./path/to/workflow.yml". please visit to https://docs.github.com/en/actions/learn-github-actions/reusing-workflows for more details [workflow-call]
      9 👈|    uses: ./.github/workflows/ci.yml@main

a.yaml:12:5: "with" is only available for a reusable workflow call with "uses" but "uses" is not found in job "job3" [syntax]
       12 👈|    with:
```

### Rule Background

#### Why Workflow Call Validation Matters

Reusable workflows are a powerful feature for sharing workflow logic across repositories. However, incorrect syntax can cause:

1. **Workflow Parsing Failures**: GitHub Actions will reject invalid workflow configurations
2. **Confusing Error Messages**: GitHub's error messages for workflow call issues can be unclear
3. **Wasted CI Time**: Invalid workflows fail during execution rather than at parse time
4. **Maintenance Issues**: Incorrect patterns may work temporarily but break on updates

#### Reusable Workflow Basics

Reusable workflows allow you to call one workflow from another using the `uses:` keyword at the job level:

```yaml
jobs:
  call-workflow:
    uses: owner/repo/.github/workflows/workflow.yml@ref
```

### Technical Detection Mechanism

The rule validates several aspects of workflow calls:

```go
func (rule *WorkflowCallRule) VisitJobPre(node *ast.Job) error {
    if node.WorkflowCall != nil {
        // Validate uses format
        rule.validateUsesFormat(node.WorkflowCall.Uses)
        // Check for invalid keys
        rule.validateJobKeys(node)
    } else {
        // Check for orphaned with/secrets
        rule.checkOrphanedKeys(node)
    }
    return nil
}
```

### Detection Logic Explanation

#### What the Rule Checks

1. **runs-on with Reusable Workflows**
   - When `uses:` is specified, `runs-on:` is not allowed
   - The called workflow defines its own runner

2. **Local File Paths with Refs**
   - Local paths (starting with `./`) cannot have version refs
   - Valid: `./.github/workflows/ci.yml`
   - Invalid: `./.github/workflows/ci.yml@main`

3. **Orphaned with/secrets**
   - `with:` and `secrets:` are only valid when calling reusable workflows
   - They cannot be used with regular jobs that have `steps:`

4. **Uses Format Validation**
   - Remote: `owner/repo/path/to/workflow.yml@ref`
   - Local: `./path/to/workflow.yml`

### Valid Patterns

#### Pattern 1: Remote Reusable Workflow

```yaml
jobs:
  call-workflow:
    uses: organization/repo/.github/workflows/build.yml@v1
    with:
      environment: production
    secrets:
      API_KEY: ${{ secrets.API_KEY }}
```

#### Pattern 2: Local Reusable Workflow

```yaml
jobs:
  call-local:
    uses: ./.github/workflows/shared-build.yml
    with:
      config: default
```

#### Pattern 3: With Permissions

```yaml
jobs:
  call-workflow:
    uses: owner/repo/.github/workflows/deploy.yml@main
    permissions:
      contents: read
      deployments: write
    with:
      target: staging
```

#### Pattern 4: With Dependencies

```yaml
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: npm run build

  deploy:
    needs: build
    uses: ./.github/workflows/deploy.yml
    with:
      artifact: build-output
```

#### Pattern 5: Conditional Calls

```yaml
jobs:
  call-workflow:
    if: github.event_name == 'push'
    uses: owner/repo/.github/workflows/release.yml@v1
```

### Invalid Patterns

#### Invalid Pattern 1: runs-on with uses

```yaml
jobs:
  deploy:
    uses: ./.github/workflows/deploy.yml
    runs-on: ubuntu-latest  # Error: Not allowed with uses
```

**Fix:**
```yaml
jobs:
  deploy:
    uses: ./.github/workflows/deploy.yml
    # runs-on is defined in the reusable workflow
```

#### Invalid Pattern 2: Local Path with Ref

```yaml
jobs:
  build:
    uses: ./.github/workflows/build.yml@main  # Error: Local paths can't have refs
```

**Fix:**
```yaml
jobs:
  build:
    uses: ./.github/workflows/build.yml
```

#### Invalid Pattern 3: Orphaned with

```yaml
jobs:
  build:
    with:
      foo: bar  # Error: with without uses
    runs-on: ubuntu-latest
    steps:
      - run: echo ${{ inputs.foo }}
```

**Fix:** Either add `uses:` to call a reusable workflow, or use `env:` or step inputs instead.

### Allowed Keys for Reusable Workflow Calls

When calling a reusable workflow with `uses:`, only these keys are allowed:

| Key | Description |
|-----|-------------|
| `name` | Display name for the job |
| `uses` | Path to the reusable workflow |
| `with` | Input parameters for the workflow |
| `secrets` | Secrets to pass to the workflow |
| `needs` | Job dependencies |
| `if` | Conditional execution |
| `permissions` | GITHUB_TOKEN permissions |

**NOT allowed with reusable workflows:**
- `runs-on` (defined in the reusable workflow)
- `steps` (defined in the reusable workflow)
- `container` (defined in the reusable workflow)
- `services` (defined in the reusable workflow)
- `env` (use `with:` instead)

### Best Practices

#### 1. Use Semantic Versioning for Remote Workflows

```yaml
# Good: Pinned to specific version
uses: organization/workflows/.github/workflows/ci.yml@v1.2.0

# Better: Pinned to commit SHA
uses: organization/workflows/.github/workflows/ci.yml@abc123def456
```

#### 2. Define Clear Inputs

In your reusable workflow:

```yaml
# reusable-workflow.yml
on:
  workflow_call:
    inputs:
      environment:
        required: true
        type: string
      debug:
        required: false
        type: boolean
        default: false
```

#### 3. Use Explicit Secrets

```yaml
jobs:
  deploy:
    uses: ./.github/workflows/deploy.yml
    secrets:
      DEPLOY_TOKEN: ${{ secrets.DEPLOY_TOKEN }}
    # Or inherit all secrets:
    # secrets: inherit
```

#### 4. Document Workflow Requirements

Add comments explaining what inputs and secrets are needed:

```yaml
jobs:
  # Requires: environment (string), DEPLOY_KEY (secret)
  deploy:
    uses: org/repo/.github/workflows/deploy.yml@v1
    with:
      environment: production
    secrets:
      DEPLOY_KEY: ${{ secrets.PRODUCTION_DEPLOY_KEY }}
```

### Creating Reusable Workflows

When creating a reusable workflow, ensure it's properly defined:

```yaml
# .github/workflows/reusable-build.yml
name: Reusable Build

on:
  workflow_call:
    inputs:
      node-version:
        required: false
        type: string
        default: '18'
    secrets:
      NPM_TOKEN:
        required: true

jobs:
  build:
    runs-on: ubuntu-latest  # Runner defined HERE, not in caller
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: ${{ inputs.node-version }}
      - run: npm ci
        env:
          NPM_TOKEN: ${{ secrets.NPM_TOKEN }}
```

### False Positives

This rule has very few false positives because:

1. GitHub's workflow call syntax is well-defined
2. Invalid configurations will fail on GitHub Actions
3. The rule validates against GitHub's documented requirements

### Related Rules

- **[id]({{< ref "idrule.md" >}})**: Validates job and step IDs
- **[permissions]({{< ref "permissions.md" >}})**: Validates permission configurations

### References

#### GitHub Documentation
- [GitHub Docs: Reusing Workflows](https://docs.github.com/en/actions/using-workflows/reusing-workflows)
- [GitHub Docs: workflow_call Event](https://docs.github.com/en/actions/using-workflows/events-that-trigger-workflows#workflow_call)
- [GitHub Docs: Workflow Syntax for workflow_call](https://docs.github.com/en/actions/using-workflows/workflow-syntax-for-github-actions#onworkflow_call)

{{< popup_link2 href="https://docs.github.com/en/actions/using-workflows/reusing-workflows" >}}

{{< popup_link2 href="https://docs.github.com/en/actions/using-workflows/events-that-trigger-workflows#workflow_call" >}}

### Testing

To test this rule:

```bash
# Detect workflow call issues
sisakulint .github/workflows/*.yml
```

### Configuration

This rule is enabled by default. To disable it:

```bash
sisakulint -ignore workflow-call
```

However, disabling this rule is **not recommended** as invalid workflow calls will cause failures on GitHub Actions.
