---
title: "Environment Variable Injection Rule (Critical)"
weight: 10
# bookFlatSection: false
# bookToc: true
# bookHidden: false
# bookCollapseSection: false
# bookComments: false
# bookSearchExclude: false
---

### Environment Variable Injection Rule (Critical) Overview

This rule detects environment variable injection vulnerabilities when untrusted input is written to `$GITHUB_ENV` within **privileged workflow contexts**. Privileged workflows have write permissions or access to secrets, making environment variable injection particularly dangerous as it can persist malicious values across workflow steps.

#### Key Features:

- **Privileged Context Detection**: Identifies dangerous patterns in `pull_request_target`, `workflow_run`, `issue_comment`, and other privileged triggers
- **GITHUB_ENV Write Detection**: Analyzes scripts that write to `$GITHUB_ENV` file
- **Auto-fix Support**: Automatically sanitizes inputs using `tr -d '\n'` to prevent newline injection
- **Zero False Positives**: Does not flag already-safe patterns with proper sanitization

### Security Impact

**Severity: Critical (9/10)**

Environment variable injection in privileged workflows represents a critical vulnerability in GitHub Actions:

1. **Environment Pollution**: Attackers can inject arbitrary environment variables that affect subsequent steps
2. **LD_PRELOAD Attacks**: Injection of `LD_PRELOAD` can hijack library loading for code execution
3. **BASH_ENV Attacks**: Malicious `BASH_ENV` can execute code in every shell invocation
4. **Secret Exfiltration**: Injected variables can capture or override security-critical values
5. **Persistence Across Steps**: Unlike in-memory code injection, environment variables persist throughout the job

This vulnerability is classified as **CWE-77: Improper Neutralization of Special Elements used in a Command ('Command Injection')** and **CWE-20: Improper Input Validation**, and aligns with OWASP CI/CD Security Risk **CICD-SEC-04: Poisoned Pipeline Execution (PPE)**.

### Privileged Workflow Triggers

The following triggers are considered privileged because they run with write access or secrets:

- **`pull_request_target`**: Runs with write permissions and secrets, but triggered by untrusted PRs
- **`workflow_run`**: Executes with elevated privileges after another workflow completes
- **`issue_comment`**: Triggered by comments from any user, including external contributors
- **`issues`**: Triggered by issue events, potentially from untrusted sources
- **`discussion_comment`**: Triggered by discussion comments from any user

### Example Vulnerable Workflow

Consider this dangerous workflow that writes PR data to `$GITHUB_ENV` in a privileged context:

```yaml
name: Process PR Metadata

on:
  pull_request_target:  # PRIVILEGED: Has write access and secrets
    types: [opened, edited]

jobs:
  process:
    runs-on: ubuntu-latest
    steps:
      # CRITICAL VULNERABILITY: Untrusted input written to GITHUB_ENV
      - name: Set PR variables
        run: |
          echo "PR_TITLE=${{ github.event.pull_request.title }}" >> "$GITHUB_ENV"
          echo "PR_BODY=${{ github.event.pull_request.body }}" >> "$GITHUB_ENV"

      - name: Use variables
        run: |
          echo "Processing: $PR_TITLE"
          # LD_PRELOAD or other injected variables now active!
```

### Attack Scenario

**How Environment Variable Injection Exploits Privileged Workflows:**

1. **Attacker Creates Malicious PR**: Opens a PR with a crafted title containing newlines:
   ```
   Title: Legit Feature
   LD_PRELOAD=/tmp/evil.so
   BASH_ENV=/tmp/backdoor.sh
   ```

2. **Workflow Triggers**: `pull_request_target` runs with write permissions and secrets

3. **Variables Injected**: The malicious input writes multiple environment variables:
   ```bash
   # Attacker's input creates:
   PR_TITLE=Legit Feature
   LD_PRELOAD=/tmp/evil.so
   BASH_ENV=/tmp/backdoor.sh
   ```

4. **Subsequent Steps Compromised**: All following steps run with the malicious environment:
   ```yaml
   - name: Build and deploy  # Now running with LD_PRELOAD=/tmp/evil.so
     run: |
       npm install  # Libraries hijacked via LD_PRELOAD
       npm run build
       aws s3 sync ./dist s3://production/
   ```

5. **Code Execution Achieved**: The attacker's shared library is loaded into every process, enabling:
   - Secret exfiltration via network calls
   - Modification of build artifacts
   - Backdoor installation in deployments

### What Makes This Critical

**Privileged workflows with environment variable injection are particularly dangerous because:**

1. **Write Access**: Workflows can modify repository content, create releases, and manage secrets
2. **Persistence**: Environment variables affect ALL subsequent steps in the job
3. **Stealth**: Unlike direct code injection, environment pollution is harder to detect
4. **Supply Chain Impact**: Compromised build environments can poison production deployments

### Safe Pattern (Using Environment Variables with Sanitization)

The recommended approach is to sanitize input by removing newlines:

```yaml
name: Process PR Metadata (Safe)

on:
  pull_request_target:

jobs:
  process:
    runs-on: ubuntu-latest
    steps:
      # SAFE: Sanitize input before writing to GITHUB_ENV
      - name: Set PR variables safely
        env:
          PR_TITLE: ${{ github.event.pull_request.title }}
          PR_BODY: ${{ github.event.pull_request.body }}
        run: |
          # Remove newlines to prevent injection
          echo "PR_TITLE=$(echo "$PR_TITLE" | tr -d '\n')" >> "$GITHUB_ENV"
          echo "PR_BODY=$(echo "$PR_BODY" | tr -d '\n')" >> "$GITHUB_ENV"

      - name: Use variables safely
        run: |
          echo "Processing: $PR_TITLE"
```

### Alternative: Heredoc Syntax

For multi-line values, use heredoc with unique delimiters:

```yaml
- name: Set multiline variable safely
  env:
    PR_BODY: ${{ github.event.pull_request.body }}
  run: |
    EOF_MARKER="EOF_$(uuidgen)"
    {
      echo "PR_BODY<<$EOF_MARKER"
      echo "$PR_BODY"
      echo "$EOF_MARKER"
    } >> "$GITHUB_ENV"
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
   - `github.event.issue.title`
   - `github.event.comment.body`
   - And other user-controlled fields

3. **Privileged workflow triggers** where the impact is critical

### Why This Pattern is Dangerous

Writing untrusted input to `$GITHUB_ENV` without sanitization allows attackers to:

1. **Inject Multiple Variables**: A single newline creates a new environment variable
2. **Override Existing Variables**: Can shadow legitimate environment variables
3. **Inject Special Variables**: `LD_PRELOAD`, `BASH_ENV`, `PATH`, etc.
4. **Persist Across Steps**: Unlike inline injection, this affects the entire job

### Real-World Impact

Environment variable injection in privileged workflows can lead to:

- **Supply Chain Compromise**: Poisoned artifacts deployed to production
- **Secret Theft**: GITHUB_TOKEN and other secrets can be exfiltrated
- **Repository Takeover**: With write permissions, attackers can modify code
- **Build System Compromise**: Injection of LD_PRELOAD hijacks all subsequent processes

### Related Rules

- **[envvar-injection-medium]({{< ref "envvarinjectionmedium.md" >}})**: Detects the same pattern in normal (non-privileged) workflows
- **[code-injection-critical]({{< ref "codeinjectioncritical.md" >}})**: Detects direct code injection in privileged contexts
- **[untrustedcheckout]({{< ref "untrustedcheckout.md" >}})**: Detects unsafe checkout of PR code

### Rule Interactions

You may see both `envvar-injection-critical` and `code-injection-critical` errors on the same line. This is intentional and provides defense in depth:

- **code-injection-critical**: Detects untrusted input anywhere in run scripts and isolates it to environment variables
- **envvar-injection-critical**: Specifically detects $GITHUB_ENV writes and adds newline sanitization

Both auto-fixes work together. Apply both for complete protection:
1. `code-injection` moves expressions to `env:` section
2. `envvar-injection` adds `tr -d '\n'` to $GITHUB_ENV writes

**Known Limitation**: The rule may not detect indirect injection through intermediate variables:
```yaml
run: |
  TEMP=${{ github.event.pull_request.title }}  # code-injection detects
  echo "X=$TEMP" >> "$GITHUB_ENV"              # envvar-injection may miss
```
Enable both rules (default) to catch these patterns.

### References

- [CodeQL: Environment Variable Injection (Critical)](https://codeql.github.com/codeql-query-help/actions/actions-envvar-injection-critical/)
- [GitHub Security: Script Injection](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#understanding-the-risk-of-script-injections)
- [OWASP: Command Injection](https://owasp.org/www-community/attacks/Command_Injection)
- [OWASP Top 10 CI/CD Security Risks](https://owasp.org/www-project-top-10-ci-cd-security-risks/)

### Testing

To test this rule with example workflows:

```bash
# Detect vulnerable patterns
sisakulint script/actions/envvar-injection-critical.yaml

# Apply auto-fix
sisakulint -fix on script/actions/envvar-injection-critical.yaml
```

### Configuration

This rule is enabled by default. To disable it, use:

```bash
sisakulint -ignore envvar-injection-critical
```
