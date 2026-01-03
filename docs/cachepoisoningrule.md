---
title: "Cache Poisoning Rule"
weight: 1
---

### Cache Poisoning Rule Overview

This rule detects potential cache poisoning vulnerabilities in GitHub Actions workflows. It identifies dangerous combinations of untrusted triggers with cache operations that could allow attackers to inject malicious payloads into the cache.

#### Key Features:

- **Precise Detection**: Only triggers when all three risk conditions are present
- **Multiple Trigger Detection**: Identifies `issue_comment`, `pull_request_target`, and `workflow_run` triggers
- **Comprehensive Cache Detection**: Detects both `actions/cache` and setup-* actions with cache enabled
- **Job Isolation**: Correctly scopes detection to individual jobs

### Attack Mechanism

Cache poisoning in GitHub Actions exploits the trust model between workflow triggers and cache scope:

1. **Untrusted Triggers**: Events like `pull_request_target` and `issue_comment` run in the context of the default branch but can be triggered by external actors
2. **Unsafe Checkout**: When `actions/checkout` checks out untrusted PR code (using `ref: ${{ github.head_ref }}`), malicious code gains execution
3. **Cache Manipulation**: The malicious code can poison the cache, which is then restored in subsequent privileged workflows

Since caches are scoped based on branch hierarchy, a cache created on the default branch is accessible to all feature branches, enabling lateral movement from low-privilege to high-privilege contexts.

### Detection Conditions

The rule triggers when **all three conditions** are met:

1. **Untrusted Trigger** is used:
   - `issue_comment`
   - `pull_request_target`
   - `workflow_run`

2. **Unsafe Checkout** with PR head reference:
   - `ref: ${{ github.event.pull_request.head.sha }}`
   - `ref: ${{ github.event.pull_request.head.ref }}`
   - `ref: ${{ github.head_ref }}`
   - `ref: refs/pull/*/merge`

3. **Cache Action** is used:
   - `actions/cache`
   - `actions/setup-node` with `cache` input
   - `actions/setup-python` with `cache` input
   - `actions/setup-go` with `cache` input
   - `actions/setup-java` with `cache` input

### Example Vulnerable Workflow

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

### Example Output

```bash
$ sisakulint ./vulnerable-workflow.yaml

./vulnerable-workflow.yaml:15:9: cache poisoning risk: 'actions/setup-node@v4' used after checking out untrusted PR code (triggers: pull_request_target). Validate cached content or scope cache to PR level [cache-poisoning]
      15 👈|      - uses: actions/setup-node@v4

./vulnerable-workflow.yaml:20:9: cache poisoning risk: 'actions/cache@v3' used after checking out untrusted PR code (triggers: pull_request_target). Validate cached content or scope cache to PR level [cache-poisoning]
      20 👈|      - uses: actions/cache@v3
```

### Safe Patterns

The following patterns do NOT trigger warnings:

**1. Safe Trigger (pull_request)**
```yaml
on:
  pull_request:  # Safe: runs in PR context, not default branch

jobs:
  build:
    steps:
      - uses: actions/checkout@v4
      - uses: actions/cache@v3  # Safe: no cache poisoning risk
```

**2. No Unsafe Checkout**
```yaml
on:
  pull_request_target:

jobs:
  build:
    steps:
      - uses: actions/checkout@v4  # Safe: checks out base branch (default)
      - uses: actions/cache@v3     # Safe: base branch code is trusted
```

**3. Cache in Separate Job**
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

### Auto-fix Support

The cache-poisoning rule supports auto-fixing by removing the unsafe `ref` input from `actions/checkout`:

```bash
# Preview changes without applying
sisakulint -fix dry-run

# Apply fixes
sisakulint -fix on
```

The auto-fix removes the `ref` input that checks out untrusted PR code, causing the workflow to checkout the base branch instead. This ensures the cached content is based on trusted code.

**Before fix:**
```yaml
- uses: actions/checkout@v4
  with:
    ref: ${{ github.head_ref }}  # Unsafe: checks out PR code
```

**After fix:**
```yaml
- uses: actions/checkout@v4
# ref removed: now checks out base branch (safe)
```

### Mitigation Strategies

1. **Validate Cached Content**: Verify integrity of restored cache before use
2. **Scope Cache to PR**: Use PR-specific cache keys to isolate caches
3. **Use Short-lived Keys**: Include timestamps or unique identifiers in cache keys
4. **Sign Cache Values**: Cryptographically sign cache content and verify before use
5. **Isolate Workflows**: Separate untrusted code execution from privileged operations

### Example: PR-Scoped Cache Key

```yaml
- uses: actions/cache@v3
  with:
    path: ~/.npm
    key: npm-${{ github.event.pull_request.number }}-${{ hashFiles('**/package-lock.json') }}
    # PR-specific key prevents cross-PR cache poisoning
```

### OWASP CI/CD Security Risks

This rule addresses **CICD-SEC-9: Improper Artifact Integrity Validation** and helps mitigate risks related to cache manipulation in CI/CD pipelines.

### See Also

- [CodeQL: Cache Poisoning via Caching of Untrusted Files](https://codeql.github.com/codeql-query-help/actions/actions-cache-poisoning-direct-cache/)
- [GitHub Actions Security: Preventing Pwn Requests](https://securitylab.github.com/research/github-actions-preventing-pwn-requests/)
- [OWASP CI/CD Top 10: CICD-SEC-9](https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-09-Improper-Artifact-Integrity-Validation)

{{< popup_link2 href="https://codeql.github.com/codeql-query-help/actions/actions-cache-poisoning-direct-cache/" >}}

{{< popup_link2 href="https://securitylab.github.com/research/github-actions-preventing-pwn-requests/" >}}

{{< popup_link2 href="https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-09-Improper-Artifact-Integrity-Validation" >}}
