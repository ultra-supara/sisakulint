---
title: "Cache Poisoning Poisonable Step Rule"
weight: 10
---

### Cache Poisoning Poisonable Step Rule Overview

This rule detects potential cache poisoning vulnerabilities when untrusted code is executed after checking out PR head code in privileged workflow contexts. Unlike the `cache-poisoning` rule which focuses on direct cache action usage, this rule focuses on **code execution** that could steal cache tokens or poison cache entries indirectly.

**Vulnerable Example:**

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
        run: ./run_tests.sh  # Executes attacker-controlled code!
```

**Detection Output:**

```bash
workflow.yaml:15:9: cache poisoning risk: executing local script './run_tests.sh' after unsafe checkout in privileged context. Attacker can steal ACTIONS_RUNTIME_TOKEN and poison cache. [cache-poisoning-poisonable-step]
      15 👈|      - name: Run tests
```

### Security Background

#### Why This is Dangerous

This vulnerability combines three dangerous patterns:

1. **Privileged Trigger**: `pull_request_target`, `issue_comment`, or `workflow_run` runs with elevated permissions
2. **Unsafe Checkout**: Checking out untrusted PR code with `ref: ${{ github.event.pull_request.head.sha }}`
3. **Code Execution**: Running local scripts or build commands that execute the checked-out code

#### Attack Scenario

```
1. Attacker submits malicious PR
   └── Modified build.sh or package.json with malicious code

2. pull_request_target workflow triggers
   └── Runs with default branch permissions and cache access

3. Workflow checks out attacker's code
   └── ref: ${{ github.event.pull_request.head.sha }}

4. Malicious code executes (./build.sh, npm install, etc.)
   └── Steals ACTIONS_RUNTIME_TOKEN
   └── Poisons cache entries with backdoor

5. Future workflow runs restore poisoned cache
   └── Backdoor executes in legitimate builds
   └── Supply chain compromise achieved
```

#### OWASP and CWE Mapping

- **CWE-829**: Inclusion of Functionality from Untrusted Control Sphere
- **CWE-349**: Acceptance of Extraneous Untrusted Data With Trusted Data
- **OWASP CI/CD Security Risks**:
  - **CICD-SEC-4**: Poisoned Pipeline Execution (PPE)
  - **CICD-SEC-9**: Improper Artifact Integrity Validation

### Technical Detection Mechanism

The rule triggers when **all three conditions** are met:

**1. Unsafe Trigger is Used:**
- `issue_comment`
- `pull_request_target`
- `workflow_run`

**2. Unsafe Checkout is Performed:**
- `ref: ${{ github.event.pull_request.head.sha }}`
- `ref: ${{ github.event.pull_request.head.ref }}`
- `ref: ${{ github.head_ref }}`
- `ref: refs/pull/${{ ... }}/merge`

**3. Poisonable Step is Executed After Unsafe Checkout:**
- Local script execution (`./build.sh`, `bash ./script.sh`)
- Build commands (`npm install`, `make`, `pip install`, etc.)
- Local actions (`uses: ./.github/actions/my-action`)
- `actions/github-script` with local file import

### Detection Logic Explanation

#### Poisonable Step Patterns

**Local Script Execution:**
```yaml
# Vulnerable patterns
- run: ./build.sh
- run: bash ./test.sh
- run: python ./setup.py
- run: node ./index.js
```

**Build Commands:**
```yaml
# Vulnerable patterns - these read local config files
- run: npm install
- run: yarn
- run: pip install -r requirements.txt
- run: make
- run: go build ./...
- run: cargo build
- run: mvn package
- run: gradle build
```

**Local Actions:**
```yaml
# Vulnerable pattern
- uses: ./.github/actions/build
```

**GitHub Script with Local Import:**
```yaml
# Vulnerable pattern
- uses: actions/github-script@v7
  with:
    script: |
      const script = require('./scripts/test.js')
      await script()
```

### Safe Patterns

#### Pattern 1: Using Safe Trigger (`pull_request`)

The key difference is using `pull_request` instead of `pull_request_target`. This scopes the cache to the PR branch, preventing attackers from poisoning the main branch cache.

```yaml
name: Secure Workflow
on:
  pull_request:  # Safe: Cache scoped to PR branch
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
        run: ./run_tests.sh  # Safe: Cache cannot affect main branch
```

**Why this is safe:**
- `pull_request` event restricts cache scope to the PR branch
- Cache is not shared with the default branch
- Attacker cannot poison the default branch cache even if they steal tokens

#### Pattern 2: Safe Checkout (Base Branch)

If you must use `pull_request_target`, ensure `actions/checkout` does NOT specify a PR head reference:

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

#### Pattern 3: External Commands Only

Even with unsafe checkout, limiting steps to safe external commands prevents code execution vulnerabilities:

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

### Auto-Fix Support

The rule can automatically fix the vulnerability by removing the `ref` input from the checkout step:

```bash
# Preview fix
sisakulint -fix dry-run ./workflow.yaml

# Apply fix
sisakulint -fix on ./workflow.yaml
```

**Before (Vulnerable):**
```yaml
- uses: actions/checkout@v4
  with:
    ref: ${{ github.head_ref }}
```

**After Auto-Fix (Safe):**
```yaml
- uses: actions/checkout@v4
```

**Note:** After auto-fix, the checkout defaults to base branch. Review your workflow to ensure this is the desired behavior.

### Best Practices

#### 1. Prefer `pull_request` Over `pull_request_target`

```yaml
# Good: Safe trigger
on: pull_request

# Dangerous: Privileged trigger
on: pull_request_target
```

#### 2. Separate Untrusted and Privileged Operations

```yaml
# Workflow 1: Build (untrusted, no secrets)
name: Build PR
on: pull_request
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm ci && npm run build
      - uses: actions/upload-artifact@v4
        with:
          name: build
          path: dist/

# Workflow 2: Deploy (trusted, uses secrets)
name: Deploy
on:
  workflow_run:
    workflows: ["Build PR"]
    types: [completed]
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/download-artifact@v4
      # No checkout of PR code!
      - run: ./deploy.sh
        env:
          TOKEN: ${{ secrets.DEPLOY_TOKEN }}
```

#### 3. Avoid Executing Local Code After Unsafe Checkout

If you must checkout PR code in a privileged context:

```yaml
# Only run safe external commands
- run: echo "PR: ${{ github.event.pull_request.number }}"
- run: git diff --stat HEAD~1

# DO NOT run:
# - run: ./script.sh
# - run: npm install
# - uses: ./.github/actions/local
```

### Comparison with Related Rules

| Rule | Focus | Detection |
|------|-------|-----------|
| **cache-poisoning** | Cache keys with untrusted input | Flags dangerous cache key patterns |
| **cache-poisoning-poisonable-step** | Code execution after unsafe checkout | Flags steps that could poison cache |
| **untrusted-checkout** | Checkout in privileged contexts | Flags unsafe ref usage |

### False Positives

The rule may flag steps that:

1. Execute external commands that don't read local files
2. Use build commands with `--ignore-scripts` or similar flags
3. Have other mitigations in place

Review flagged steps carefully and consider if the code execution path is actually exploitable.

### Related Rules

- **[cache-poisoning]({{< ref "cachepoisoningrule.md" >}})**: Detects cache keys with untrusted input
- **[untrusted-checkout]({{< ref "untrustedcheckout.md" >}})**: Detects checkout of untrusted PR code
- **[code-injection-critical]({{< ref "codeinjectioncritical.md" >}})**: Detects code injection in privileged contexts

### References

#### GitHub Documentation
- [GitHub Docs: Security Hardening](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions)

#### Security Research
- [CodeQL: actions-cache-poisoning-poisonable-step](https://codeql.github.com/codeql-query-help/actions/actions-cache-poisoning-poisonable-step/)
- [GitHub Actions Cache Poisoning](https://adnanthekhan.com/2024/05/06/the-monsters-in-your-build-cache-github-actions-cache-poisoning/)
- [GitHub Security Lab: Preventing Pwn Requests](https://securitylab.github.com/research/github-actions-preventing-pwn-requests/)
- [OWASP CICD-SEC-9: Improper Artifact Integrity Validation](https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-09-Improper-Artifact-Integrity-Validation)

{{< popup_link2 href="https://codeql.github.com/codeql-query-help/actions/actions-cache-poisoning-poisonable-step/" >}}

{{< popup_link2 href="https://adnanthekhan.com/2024/05/06/the-monsters-in-your-build-cache-github-actions-cache-poisoning/" >}}

{{< popup_link2 href="https://securitylab.github.com/research/github-actions-preventing-pwn-requests/" >}}

### Testing

To test this rule:

```bash
# Detect poisonable steps
sisakulint .github/workflows/*.yml

# Apply auto-fix
sisakulint -fix on .github/workflows/*.yml
```

### Configuration

This rule is enabled by default. To disable it:

```bash
sisakulint -ignore cache-poisoning-poisonable-step
```

However, disabling this rule is **not recommended** as cache poisoning can lead to supply chain compromise.
