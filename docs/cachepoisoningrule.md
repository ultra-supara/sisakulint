---
title: "Cache Poisoning Rule"
weight: 1
# bookFlatSection: false
# bookToc: true
# bookHidden: false
# bookCollapseSection: false
# bookComments: false
# bookSearchExclude: false
---

### Cache Poisoning Rule Overview

This rule detects potential cache poisoning vulnerabilities in GitHub Actions workflows. It identifies dangerous combinations of untrusted triggers with cache operations that could allow attackers to inject malicious payloads into the cache.

#### Key Features

- **Precise Detection**: Only triggers when all three risk conditions are present
- **Multiple Trigger Detection**: Identifies `issue_comment`, `pull_request_target`, and `workflow_run` triggers
- **Comprehensive Cache Detection**: Detects both `actions/cache` and setup-* actions with cache enabled
- **Job Isolation**: Correctly scopes detection to individual jobs
- **Smart Checkout Tracking**: Resets unsafe state when a safe checkout follows an unsafe one
- **Conservative Pattern Matching**: Detects direct, indirect, and unknown expression patterns
- **CodeQL Compatible**: Based on CodeQL's query with enhanced detection capabilities
- **Auto-fix Support**: Removes unsafe `ref` input from checkout steps

### Detection Conditions

The rule triggers when all three conditions are met

1. Untrusted Trigger is used:
   - `issue_comment`
   - `pull_request_target`
   - `workflow_run`

2. Unsafe Checkout with PR head reference
   - Direct patterns:
     - `ref: ${{ github.event.pull_request.head.sha }}`
     - `ref: ${{ github.event.pull_request.head.ref }}`
     - `ref: ${{ github.head_ref }}`
     - `ref: refs/pull/*/merge`
   - Indirect patterns (from step outputs):
     - `ref: ${{ steps.*.outputs.head_sha }}`
     - `ref: ${{ steps.*.outputs.head_ref }}`
     - `ref: ${{ steps.*.outputs.head-sha }}`
   - Conservative detection: Any unknown expression in `ref` with untrusted triggers is treated as potentially unsafe

3. Cache Action is used
   - `actions/cache`
   - `actions/setup-node` with `cache` input
   - `actions/setup-python` with `cache` input
   - `actions/setup-go` with `cache` input
   - `actions/setup-java` with `cache` input

### Example Vulnerable Workflows

#### Example 1: Direct PR Head Reference

```yaml
name: PR Build
on:
  pull_request_target:
    types: [opened, synchronize]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.head_ref }}  # Checks out untrusted PR code

      - uses: actions/setup-node@v4
        with:
          node-version: '18'
          cache: 'npm'  # Cache can be poisoned

      - uses: actions/cache@v3
        with:
          path: ~/.npm
          key: npm-${{ runner.os }}-${{ hashFiles('**/package-lock.json') }}
```

#### Example 2: Indirect Reference via Step Output (CodeQL Pattern)

```yaml
name: Comment Build
on:
  issue_comment:
    types: [created]

jobs:
  pr-comment:
    runs-on: ubuntu-latest
    steps:
      - uses: xt0rted/pull-request-comment-branch@v2
        id: comment-branch

      - uses: actions/checkout@v3
        with:
          ref: ${{ steps.comment-branch.outputs.head_sha }}  # Indirect untrusted reference

      - uses: actions/setup-python@v5
        with:
          python-version: '3.10'
          cache: 'pip'  # Cache can be poisoned
```

### Example Output

```bash
$ sisakulint ./vulnerable-workflow.yaml

./vulnerable-workflow.yaml:15:9: cache poisoning risk: 'actions/setup-node@v4' used after checking out untrusted PR code (triggers: pull_request_target). Validate cached content or scope cache to PR level [cache-poisoning]
      15 👈|      - uses: actions/setup-node@v4

./vulnerable-workflow.yaml:20:9: cache poisoning risk: 'actions/cache@v3' used after checking out untrusted PR code (triggers: pull_request_target). Validate cached content or scope cache to PR level [cache-poisoning]
      20 👈|      - uses: actions/cache@v3
```

### Safe Patterns

The following patterns do NOT trigger warnings

1. Safe Trigger (pull_request)
```yaml
on:
  pull_request:  # Safe: runs in PR context, not default branch

jobs:
  build:
    steps:
      - uses: actions/checkout@v4
      - uses: actions/cache@v3  # Safe: no cache poisoning risk
```

2. No Unsafe Checkout
```yaml
on:
  pull_request_target:

jobs:
  build:
    steps:
      - uses: actions/checkout@v4  # Safe: checks out base branch (default)
      - uses: actions/cache@v3     # Safe: base branch code is trusted
```

3. Cache in Separate Job
```yaml
on:
  pull_request_target:

jobs:
  checkout-pr:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.head_ref }}  # Unsafe checkout, but no cache

  build:
    steps:
      - uses: actions/cache@v3  # Safe: different job, no unsafe checkout here
```

4. Safe Checkout After Unsafe Checkout
```yaml
on:
  pull_request_target:

jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.head_ref }}  # Unsafe checkout (for testing PR code)

      - name: Test PR code
        run: npm test

      - uses: actions/checkout@v4  # Safe: checks out base branch (resets state)

      - uses: actions/cache@v3  # Safe: cache operates on base branch code
```

### Auto-fix Support

The cache-poisoning rule supports auto-fixing by removing the unsafe `ref` input from `actions/checkout`

```bash
# Preview changes without applying
sisakulint -fix dry-run

# Apply fixes
sisakulint -fix on
```

The auto-fix removes the `ref` input that checks out untrusted PR code, causing the workflow to checkout the base branch instead. This ensures the cached content is based on trusted code.

Before fix
```yaml
- uses: actions/checkout@v4
  with:
    ref: ${{ github.head_ref }}  # Unsafe: checks out PR code
```

After fix
```yaml
- uses: actions/checkout@v4
```

### Mitigation Strategies

1. **Validate Cached Content**: Verify integrity of restored cache before use
2. **Scope Cache to PR**: Use PR-specific cache keys to isolate caches
3. **Isolate Workflows**: Separate untrusted code execution from privileged operations
4. **Use Safe Checkout**: Avoid checking out PR code in workflows with untrusted triggers and caching

### Detection Strategy and CodeQL Compatibility

This rule is based on [CodeQL's `actions-cache-poisoning-direct-cache` query](https://codeql.github.com/codeql-query-help/actions/actions-cache-poisoning-direct-cache/) but implements additional detection capabilities:

#### Conservative Detection Approach

sisakulint uses a **conservative detection strategy** for maximum security:

- **Direct patterns**: Detects explicit PR head references like `github.head_ref` and `github.event.pull_request.head.sha`
- **Indirect patterns**: Detects step outputs that may contain PR head references (e.g., `steps.*.outputs.head_sha`)
- **Unknown expressions**: Any unknown expression in `ref` with untrusted triggers is treated as potentially unsafe

This conservative approach may result in some false positives but ensures that subtle attack vectors are not missed.

#### Differences from CodeQL

| Aspect | CodeQL | sisakulint |
|--------|--------|-----------|
| Detection scope | Explicit patterns only | Explicit + indirect + unknown expressions |
| Label guards | Considers `if: contains(labels)` as safe | Reports warning (conservative) |
| Multiple checkouts | May not handle correctly | Resets state on safe checkout |
| Step outputs | Limited detection | Comprehensive pattern matching |

**Example difference**: CodeQL may consider workflows with label guards safe, but sisakulint still reports warnings because label-based protection depends on operational procedures that may fail.

### OWASP CI/CD Security Risks

This rule addresses CICD-SEC-9: Improper Artifact Integrity Validation and helps mitigate risks related to cache manipulation in CI/CD pipelines.

### See Also

- [CodeQL: Cache Poisoning via Caching of Untrusted Files](https://codeql.github.com/codeql-query-help/actions/actions-cache-poisoning-direct-cache/)
- [GitHub Actions Security: Preventing Pwn Requests](https://securitylab.github.com/research/github-actions-preventing-pwn-requests/)
- [OWASP CI/CD Top 10: CICD-SEC-9](https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-09-Improper-Artifact-Integrity-Validation)

{{< popup_link2 href="https://codeql.github.com/codeql-query-help/actions/actions-cache-poisoning-direct-cache/" >}}

{{< popup_link2 href="https://securitylab.github.com/research/github-actions-preventing-pwn-requests/" >}}

{{< popup_link2 href="https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-09-Improper-Artifact-Integrity-Validation" >}}
