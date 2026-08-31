---
title: "Environment Variable Injection Rule (Medium)"
weight: 11
# bookFlatSection: false
# bookToc: true
# bookHidden: false
# bookCollapseSection: false
# bookComments: false
# bookSearchExclude: false
---

### Environment Variable Injection Rule (Medium) Overview

This rule detects environment variable injection vulnerabilities when untrusted input is written to `$GITHUB_ENV` within **normal workflow contexts**. While these workflows have limited permissions compared to privileged contexts, environment variable injection can still lead to security issues and unexpected behavior.

#### Key Features:

- **Normal Trigger Detection**: Identifies patterns in `pull_request`, `push`, `schedule`, and other standard triggers
- **GITHUB_ENV Write Detection**: Analyzes scripts that write to `$GITHUB_ENV` file
- **Auto-fix Support**: Automatically sanitizes inputs using `tr -d '\n'` to prevent newline injection
- **Developer-Friendly**: Helps maintain secure coding practices even in lower-risk contexts

### Security Impact

**Severity: Medium (5/10)**

Environment variable injection in normal workflows represents a medium-severity vulnerability:

1. **Workflow Logic Manipulation**: Attackers can alter workflow behavior through environment pollution
2. **Data Integrity Issues**: Injected variables can corrupt build outputs or test results
3. **Defense-in-Depth**: Preventing medium-risk patterns stops privilege escalation paths
4. **Best Practice Enforcement**: Maintains security hygiene across all workflows

While normal workflows lack write permissions and secret access, environment variable injection can still:

- **Interfere with CI/CD logic**: Modified environment variables can skip tests or alter build configurations
- **Create false positives/negatives**: Test results can be manipulated
- **Enable chaining attacks**: If workflows later gain privileges, existing vulnerabilities become exploitable

This vulnerability is classified as **CWE-77: Improper Neutralization of Special Elements used in a Command ('Command Injection')** and **CWE-20: Improper Input Validation**.

### Normal Workflow Triggers

The following triggers are considered normal (non-privileged) workflows:

- **`pull_request`**: Runs with read-only permissions for external PRs
- **`push`**: Triggered by repository pushes
- **`schedule`**: Runs on a cron schedule
- **`workflow_dispatch`**: Manually triggered workflows
- **`merge_group`**: Triggered by merge queue events

### Example Vulnerable Workflow

Consider this workflow that writes PR data to `$GITHUB_ENV`:

```yaml
name: CI Build

on:
  pull_request:  # Normal trigger with limited permissions
    types: [opened, synchronize]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      # MEDIUM VULNERABILITY: Untrusted input written to GITHUB_ENV
      - name: Set build variables
        run: |
          echo "PR_TITLE=${{ github.event.pull_request.title }}" >> "$GITHUB_ENV"
          echo "PR_BRANCH=${{ github.event.pull_request.head.ref }}" >> "$GITHUB_ENV"

      - name: Build project
        run: |
          echo "Building: $PR_TITLE from $PR_BRANCH"
          npm run build
          # Environment variables affect build process
```

### Attack Scenario

**How Environment Variable Injection Works in Normal Workflows:**

1. **Attacker Creates Malicious PR**: Opens a PR with a crafted title:
   ```
   Title: Fix typo
   NODE_OPTIONS=--require=/tmp/malicious.js
   CI=false
   ```

2. **Workflow Triggers**: `pull_request` runs with limited permissions

3. **Variables Injected**: The malicious input writes multiple environment variables:
   ```bash
   # Attacker's input creates:
   PR_TITLE=Fix typo
   NODE_OPTIONS=--require=/tmp/malicious.js
   CI=false
   ```

4. **Build Process Affected**: Subsequent steps run with altered environment:
   ```yaml
   - name: Run tests  # Now running with CI=false
     run: |
       npm test  # NODE_OPTIONS affects Node.js execution
   ```

5. **Impact**: While limited in scope, this can:
   - Skip test suites (via `CI=false`)
   - Alter build configurations
   - Create misleading CI results
   - Interfere with quality gates

### What Makes This Medium Risk

**Normal workflows with environment variable injection are medium risk because:**

1. **Limited Permissions**: No write access to repository or access to secrets
2. **Read-Only Context**: Cannot directly modify code or configuration
3. **Isolated Impact**: Effects are contained within the workflow run
4. **Defense-in-Depth**: Prevents escalation if workflow gains privileges later

However, it's still a security issue because:

- Workflow logic can be manipulated
- CI/CD decisions may be based on compromised data
- Creates technical debt that could become critical if workflow permissions change

### Safe Pattern (Using Environment Variables with Sanitization)

The recommended approach is to sanitize input by removing newlines:

```yaml
name: CI Build (Safe)

on:
  pull_request:

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      # SAFE: Sanitize input before writing to GITHUB_ENV
      - name: Set build variables safely
        env:
          PR_TITLE: ${{ github.event.pull_request.title }}
          PR_BRANCH: ${{ github.event.pull_request.head.ref }}
        run: |
          # Remove newlines to prevent injection
          echo "PR_TITLE=$(echo "$PR_TITLE" | tr -d '\n')" >> "$GITHUB_ENV"
          echo "PR_BRANCH=$(echo "$PR_BRANCH" | tr -d '\n')" >> "$GITHUB_ENV"

      - name: Build project
        run: |
          echo "Building: $PR_TITLE from $PR_BRANCH"
          npm run build
```

### Alternative: Avoid GITHUB_ENV Entirely

For read-only workflows, consider using environment variables directly:

```yaml
- name: Build project
  env:
    PR_TITLE: ${{ github.event.pull_request.title }}
    PR_BRANCH: ${{ github.event.pull_request.head.ref }}
  run: |
    echo "Building: $PR_TITLE from $PR_BRANCH"
    npm run build
```

### Auto-Fix Example

sisakulint can automatically fix this vulnerability:

**Before (Vulnerable):**
```yaml
- name: Set variables
  run: |
    echo "TITLE=${{ github.event.pull_request.title }}" >> "$GITHUB_ENV"
```

**After Auto-Fix (Safe):**
```yaml
- name: Set variables
  env:
    PR_TITLE: ${{ github.event.pull_request.title }}
  run: |
    echo "TITLE=$(echo "$PR_TITLE" | tr -d '\n')" >> "$GITHUB_ENV"
```

### Detection Details

The rule detects:

1. **Direct writes to $GITHUB_ENV** using various formats:
   - `>> $GITHUB_ENV`
   - `>> "$GITHUB_ENV"`
   - `>> ${GITHUB_ENV}`
   - `>>$GITHUB_ENV`

2. **Untrusted input sources** including:
   - `github.event.pull_request.title`
   - `github.event.pull_request.body`
   - `github.event.pull_request.head.ref`
   - `github.event.pull_request.head.label`
   - `github.event.pull_request.head.repo.full_name`
   - And other user-controlled fields

3. **Normal workflow triggers** where permissions are limited

### Why This Pattern Should Be Fixed

Even in normal workflows, writing untrusted input to `$GITHUB_ENV` is problematic:

1. **Unpredictable Behavior**: Environment pollution can cause hard-to-debug issues
2. **CI/CD Reliability**: Test and build results may become unreliable
3. **Future-Proofing**: If workflow gains privileges later, the vulnerability becomes critical
4. **Code Quality**: Encourages secure coding practices

### Difference from Critical Severity

| Aspect | Critical (Privileged) | Medium (Normal) |
|--------|----------------------|-----------------|
| **Permissions** | Write access, secrets | Read-only |
| **Impact** | Repository compromise | Workflow behavior manipulation |
| **Secret Access** | Yes | No |
| **Attack Surface** | High | Medium |
| **Urgency** | Immediate fix required | Should be fixed |

### Real-World Impact

Environment variable injection in normal workflows can lead to:

- **CI/CD Confusion**: Misleading build or test results
- **Quality Gate Bypass**: Altered environment skips critical checks
- **Developer Friction**: Hard-to-reproduce bugs in CI
- **Escalation Path**: Becomes critical if workflow permissions change

### Best Practices

1. **Prefer Direct Usage**: Use `env:` blocks instead of writing to `$GITHUB_ENV` when possible
2. **Sanitize Inputs**: Always use `tr -d '\n'` when writing to `$GITHUB_ENV`
3. **Use Heredoc for Multi-line**: Use unique delimiters for multi-line values
4. **Validate Permissions**: Ensure workflows have minimal necessary permissions
5. **Regular Audits**: Review workflows for privilege escalation paths

### Related Rules

- **[envvar-injection-critical]({{< ref "envvarinjectioncritical.md" >}})**: Detects the same pattern in privileged workflows (higher severity)
- **[code-injection-medium]({{< ref "codeinjectionmedium.md" >}})**: Detects direct code injection in normal contexts
- **[permissions]({{< ref "permissions.md" >}})**: Ensures workflows follow least-privilege principle

### Rule Interactions

You may see both `envvar-injection-medium` and `code-injection-medium` errors on the same line. This is intentional and provides defense in depth:

- **code-injection-medium**: Detects untrusted input anywhere in run scripts and isolates it to environment variables
- **envvar-injection-medium**: Specifically detects $GITHUB_ENV writes and adds newline sanitization

Both auto-fixes work together. Apply both for complete protection:
1. `code-injection` moves expressions to `env:` section
2. `envvar-injection` adds `tr -d '\n'` to $GITHUB_ENV writes

For detailed explanation of how these rules interact, see [envvar-injection-critical Rule Interactions]({{< ref "envvarinjectioncritical.md#rule-interactions" >}}).

### References

- [CodeQL: Environment Variable Injection (Medium)](https://codeql.github.com/codeql-query-help/actions/actions-envvar-injection-medium/)
- [GitHub Security: Script Injection](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#understanding-the-risk-of-script-injections)
- [GitHub Actions: Environment Variables](https://docs.github.com/en/actions/learn-github-actions/variables#default-environment-variables)

### Testing

To test this rule with example workflows:

```bash
# Detect vulnerable patterns
sisakulint script/actions/envvar-injection-medium.yaml

# Apply auto-fix
sisakulint -fix on script/actions/envvar-injection-medium.yaml
```

### Configuration

This rule is enabled by default. To disable it, use:

```bash
sisakulint -ignore envvar-injection-medium
```

### When to Use Critical vs Medium

Choose the appropriate severity based on workflow trigger:

- **Use Critical Rule**: For `pull_request_target`, `workflow_run`, `issue_comment`, `issues`, `discussion_comment`
- **Use Medium Rule**: For `pull_request`, `push`, `schedule`, `workflow_dispatch`

Both rules use the same detection and fix logic, but differ in severity classification based on the attack surface and potential impact.
