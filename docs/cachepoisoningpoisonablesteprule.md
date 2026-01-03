# cache-poisoning-poisonable-step

Detects potential cache poisoning vulnerabilities when untrusted code is executed after checking out PR head code.

## Overview

This rule detects workflows where untrusted code is executed in the context of the default branch, which can lead to cache poisoning attacks. Unlike the `cache-poisoning` rule which focuses on direct cache action usage, this rule focuses on **code execution** that could steal cache tokens or poison cache entries indirectly.

## Detection Conditions

The rule triggers when **all three conditions** are met:

1. **Unsafe trigger** is used:
   - `issue_comment`
   - `pull_request_target`
   - `workflow_run`

2. **Unsafe checkout** is performed:
   - `ref: ${{ github.event.pull_request.head.sha }}`
   - `ref: ${{ github.event.pull_request.head.ref }}`
   - `ref: ${{ github.head_ref }}`
   - `ref: refs/pull/${{ ... }}/merge`

3. **Poisonable step** is executed after unsafe checkout:
   - Local script execution (`./build.sh`, `bash ./script.sh`)
   - Build commands (`npm install`, `make`, `pip install`, etc.)
   - Local actions (`uses: ./.github/actions/my-action`)
   - `actions/github-script` with local file import

## Poisonable Steps

### Local Script Execution
```yaml
# Vulnerable patterns
- run: ./build.sh
- run: bash ./test.sh
- run: python ./setup.py
- run: node ./index.js
```

### Build Commands
```yaml
# Vulnerable patterns
- run: npm install
- run: yarn
- run: pip install -r requirements.txt
- run: make
- run: go build ./...
- run: cargo build
- run: mvn package
- run: gradle build
```

### Local Actions
```yaml
# Vulnerable pattern
- uses: ./.github/actions/build
```

### GitHub Script with Local Import
```yaml
# Vulnerable pattern
- uses: actions/github-script@v7
  with:
    script: |
      const script = require('./scripts/test.js')
      await script()
```

## Vulnerable Example

This workflow is vulnerable because it runs in the `pull_request_target` context (default branch permissions) while checking out and executing untrusted PR code.

```yaml
name: Vulnerable Workflow
on:
  pull_request_target:
    branches: [main]

permissions: {}

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}

      - name: Run tests
        run: ./run_tests.sh
```

**Why this is vulnerable:**
- `pull_request_target` event runs the workflow with default branch credentials
- `actions/checkout` with PR head reference checks out attacker-controlled code
- `./run_tests.sh` from the untrusted PR is executed with elevated permissions
- Attacker can steal `ACTIONS_RUNTIME_TOKEN` and poison cache for the default branch

## Safe Examples

### Correct: Using Safe Trigger

The key difference is using `pull_request` instead of `pull_request_target`. This scopes the cache to the PR branch, preventing attackers from poisoning the main branch cache.

```yaml
name: Secure Workflow
on:
  pull_request:
    branches: [main]

permissions: {}

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}

      - name: Run tests
        run: ./run_tests.sh
```

**Why this is safe:**
- `pull_request` event restricts cache scope to the PR branch
- Cache is not shared with the default branch
- Attacker cannot poison the default branch cache even if they steal tokens

### Safe Checkout (Base Branch)

If you must use `pull_request_target`, ensure `actions/checkout` does NOT specify a PR head reference. By default, it checks out the base branch, preventing code execution on attacker-controlled files.

```yaml
name: Safe - Base Branch Checkout
on:
  pull_request_target:
    branches: [main]

permissions: {}

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        # No 'ref' input: defaults to base branch (main)

      - run: ./build.sh
        # Safe: checked out base branch code, not PR code
```

**Why this is safe:**
- `actions/checkout` without `ref` defaults to base branch
- Execution happens on repository code, not untrusted PR code
- Attacker cannot influence which code gets executed

### Safe: External Commands Only

Even with unsafe checkout, limiting steps to safe external commands prevents code execution vulnerabilities.

```yaml
name: Safe - External Commands Only
on:
  pull_request_target:
    branches: [main]

permissions: {}

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}

      - run: echo "Hello World"
        # Safe: doesn't execute local code
      - run: node --version
        # Safe: external command only
```

**Why this is safe:**
- No local scripts are executed (`./build.sh`, etc.)
- No build tools that read local files (`npm install`, `pip install`, etc.)
- No local actions
- No github-script with local imports

## Auto-fix

The rule can automatically fix the vulnerability by removing the `ref` input from the checkout step, causing it to checkout the base branch instead:

```bash
# Preview fix
sisakulint -fix dry-run ./workflow.yaml

# Apply fix
sisakulint -fix on ./workflow.yaml
```

**Before:**
```yaml
- uses: actions/checkout@v4
  with:
    ref: ${{ github.head_ref }}
```

**After:**
```yaml
- uses: actions/checkout@v4
```

## Attack Scenario

1. Attacker submits a malicious PR with modified `build.sh` or `package.json`
2. `pull_request_target` workflow checks out attacker's code
3. Malicious code executes and can:
   - Steal `ACTIONS_RUNTIME_TOKEN` for cache access
   - Poison cache entries with malicious content
   - Exfiltrate secrets available to the workflow
4. Future workflow runs restore poisoned cache, achieving code execution

## OWASP CICD-SEC Reference

This rule addresses [CICD-SEC-9: Improper Artifact Integrity Validation](https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-09-Improper-Artifact-Integrity-Validation).

## References

- [CodeQL: actions-cache-poisoning-poisonable-step](https://codeql.github.com/codeql-query-help/actions/actions-cache-poisoning-poisonable-step/)
- [GitHub Actions Cache Poisoning](https://adnanthekhan.com/2024/05/06/the-monsters-in-your-build-cache-github-actions-cache-poisoning/)
- [GitHub Security Lab: Preventing Pwn Requests](https://securitylab.github.com/research/github-actions-preventing-pwn-requests/)
