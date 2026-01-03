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

```yaml
name: Vulnerable Workflow
on:
  pull_request_target:
    branches: [main]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.head_ref }}  # Unsafe checkout

      - run: ./build.sh  # VULNERABLE: executes untrusted code

      - run: npm install  # VULNERABLE: executes untrusted package.json scripts
```

## Safe Examples

### Using Safe Trigger
```yaml
name: Safe - Pull Request Trigger
on:
  pull_request:  # Safe trigger (not pull_request_target)
    branches: [main]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.head_ref }}
      - run: ./build.sh  # Safe because trigger is pull_request
```

### Safe Checkout
```yaml
name: Safe - Base Branch Checkout
on:
  pull_request_target:
    branches: [main]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4  # Safe: checks out base branch

      - run: ./build.sh  # Safe because checked out base branch code
```

### External Commands Only
```yaml
name: Safe - No Local Code Execution
on:
  pull_request_target:
    branches: [main]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.head_ref }}

      - run: echo "Hello"  # Safe: doesn't execute local code
      - run: node --version  # Safe: external command only
```

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
