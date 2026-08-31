---
title: "Improper Access Control Rule"
weight: 1
---

### Improper Access Control Rule Overview

This rule detects improper access control vulnerabilities in GitHub Actions workflows that use label-based approval mechanisms. This is a **critical security vulnerability** (CVSS 9.3, CWE-285) that allows attackers to bypass label-based approval and execute malicious code.

**Vulnerable Example:**

```yaml
name: PR Build
on:
  pull_request_target:
    types: [opened, synchronize]  # Dangerous: synchronize allows code changes after approval

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        if: contains(github.event.pull_request.labels.*.name, 'safe to test')
        with:
          ref: ${{ github.event.pull_request.head.ref }}  # Mutable reference!
      - run: npm test
```

**Detection Output:**

```bash
vulnerable.yaml:12:9: improper access control: checkout uses label-based approval with 'synchronize' event type and mutable ref. An attacker can modify code after label approval. Fix: 1) Change trigger types from 'synchronize' to 'labeled', 2) Use immutable 'github.event.pull_request.head.sha' instead of mutable 'head.ref'. See https://codeql.github.com/codeql-query-help/actions/actions-improper-access-control/ [improper-access-control]
      12 👈|      - uses: actions/checkout@v4
```

### Security Background

#### Why is this dangerous?

The vulnerability occurs when three conditions are met:

1. **`pull_request_target` trigger with `synchronize` event type** - Allows the workflow to trigger when new commits are pushed to the PR
2. **Label-based approval check** - Uses labels like "safe to test" to gate execution
3. **Mutable branch reference** - Uses `head.ref` instead of `head.sha`

#### Attack Scenario

```
1. Attacker opens PR with benign code
   └── Workflow does NOT run (no "safe to test" label)

2. Maintainer reviews code and adds "safe to test" label
   └── Workflow runs with benign code ✓

3. Attacker pushes malicious commit to same PR
   └── "synchronize" event triggers workflow
   └── "safe to test" label is still present
   └── Workflow runs with MALICIOUS code! 🚨

4. Mutable ref (head.ref) points to the NEW malicious code
   └── Attacker's code executes with access to secrets
```

**Visual Timeline:**

```
Time ──────────────────────────────────────────────────────────►

PR opened          Label added       Malicious commit pushed
    │                  │                      │
    ▼                  ▼                      ▼
[Benign code]    [Approved! ✓]    [Still has label! 🚨]
                                  [head.ref → malicious code]
```

#### Why `head.ref` vs `head.sha` matters

| Reference | Type | After new push | Security |
|-----------|------|----------------|----------|
| `head.ref` | Branch name | Points to NEW commit | ❌ Mutable |
| `head.sha` | Commit SHA | Points to SAME commit | ✅ Immutable |

Using `head.ref` (branch name) means the checkout will always get the latest code, even after approval. Using `head.sha` (commit SHA) locks the checkout to the specific commit that was approved.

#### OWASP and CWE Mapping

- **CWE-285:** Improper Authorization
- **OWASP Top 10 CI/CD Security Risks:**
  - **CICD-SEC-4:** Poisoned Pipeline Execution (PPE)

### Technical Detection Mechanism

The rule performs three-step detection:

**Step 1: Identify `pull_request_target` with `synchronize`**

```go
// In VisitWorkflowPre
for _, event := range workflow.On {
    if webhookEvent, ok := event.(*ast.WebhookEvent); ok {
        if webhookEvent.EventName() == "pull_request_target" {
            for _, eventType := range webhookEvent.Types {
                if eventType.Value == "synchronize" {
                    rule.hasSynchronizeType = true
                }
            }
        }
    }
}
```

**Step 2: Find Checkout Actions with Mutable Refs**

```go
// In VisitStep
if action, ok := step.Exec.(*ast.ExecAction); ok {
    if strings.HasPrefix(action.Uses.Value, "actions/checkout@") {
        refInput := action.Inputs["ref"]
        if strings.Contains(refInput.Value.Value, "head.ref") ||
           strings.Contains(refInput.Value.Value, "github.head_ref") {
            // Mutable reference detected!
        }
    }
}
```

**Step 3: Check for Label-Based Conditions**

```go
// Check step's if condition
if step.If != nil {
    if strings.Contains(step.If.Value, "github.event.pull_request.labels") {
        // Label-based gating detected
    }
}
```

### Detection Logic Explanation

#### Mutable Ref Patterns Detected

The rule detects these dangerous mutable reference patterns:

- `${{ github.event.pull_request.head.ref }}` - PR branch name (mutable)
- `${{ github.head_ref }}` - Shorthand for PR branch name (mutable)

#### Label-Based Condition Patterns Detected

- `contains(github.event.pull_request.labels.*.name, 'safe to test')`
- `github.event.pull_request.labels`
- `github.event.label`

#### Safe Patterns

The rule does NOT flag these patterns:

**Safe Pattern 1: Use `labeled` event type only**

```yaml
on:
  pull_request_target:
    types: [labeled]  # Only triggers when label is added - no subsequent pushes

jobs:
  test:
    steps:
      - uses: actions/checkout@v4
        if: contains(github.event.pull_request.labels.*.name, 'safe to test')
        with:
          ref: ${{ github.event.pull_request.head.sha }}  # Immutable!
```

**Safe Pattern 2: Use immutable SHA reference**

```yaml
on:
  pull_request_target:
    types: [opened, synchronize]

jobs:
  test:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}  # Immutable!
```

**Safe Pattern 3: Use `pull_request` trigger instead**

```yaml
on: pull_request  # No secrets access, safe to run PR code

jobs:
  test:
    steps:
      - uses: actions/checkout@v4  # Safe: no privileged context
```

### Comparison with Untrusted Checkout Rule

| Rule | Focus | Trigger |
|------|-------|---------|
| **Untrusted Checkout** | Any checkout of PR code in privileged context | All privileged triggers |
| **Improper Access Control** | Label approval bypass via `synchronize` + mutable ref | `pull_request_target` with `synchronize` |

The Improper Access Control rule is more specific - it focuses on the combination of label-based approval, `synchronize` events, and mutable references that creates a bypass vulnerability.

### False Positives

The rule has very few false positives because it requires ALL of:

1. `pull_request_target` trigger
2. `synchronize` in the event types
3. Checkout with mutable ref (`head.ref` or `github.head_ref`)

If any condition is not met, the rule will not flag the workflow.

### References

#### GitHub Documentation
- {{< popup_link2 href="https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions" >}}
- {{< popup_link2 href="https://docs.github.com/en/actions/using-workflows/events-that-trigger-workflows#pull_request_target" >}}

#### Security Research
- {{< popup_link2 href="https://codeql.github.com/codeql-query-help/actions/actions-improper-access-control/" >}}
- {{< popup_link2 href="https://securitylab.github.com/research/github-actions-preventing-pwn-requests/" >}}

#### OWASP Resources
- {{< popup_link2 href="https://owasp.org/www-project-top-10-ci-cd-security-risks/" >}}

### Auto-Fix

This rule supports automatic fixing. When you run sisakulint with the `-fix on` flag, it will automatically apply two fixes:

**Fix 1: Replace mutable refs with immutable SHAs**

- `ref: ${{ github.event.pull_request.head.ref }}` becomes `ref: ${{ github.event.pull_request.head.sha }}`
- `ref: ${{ github.head_ref }}` becomes `ref: ${{ github.event.pull_request.head.sha }}`

**Fix 2: Replace `synchronize` with `labeled` in event types**

- `types: [opened, synchronize]` becomes `types: [opened, labeled]`

**Example:**

Before auto-fix:
```yaml
on:
  pull_request_target:
    types: [opened, synchronize]

jobs:
  test:
    steps:
      - uses: actions/checkout@v4
        if: contains(github.event.pull_request.labels.*.name, 'safe to test')
        with:
          ref: ${{ github.event.pull_request.head.ref }}
```

After running `sisakulint -fix on`:
```yaml
on:
  pull_request_target:
    types: [opened, labeled]

jobs:
  test:
    steps:
      - uses: actions/checkout@v4
        if: contains(github.event.pull_request.labels.*.name, 'safe to test')
        with:
          ref: ${{ github.event.pull_request.head.sha }}
```

**Note:** After auto-fix, the workflow will only trigger when a label is added (not on subsequent pushes). This is the correct security behavior for label-gated workflows.

### Remediation Steps

When this rule triggers:

1. **Use auto-fix for quick remediation**
   - Run `sisakulint -fix on` to automatically fix the vulnerability
   - Review the changes to ensure they meet your workflow requirements

2. **Change event types to `labeled` only**
   - Remove `synchronize` from the types array
   - Add `labeled` if not already present
   - This ensures the workflow only runs when approval is explicitly granted

3. **Use immutable SHA references**
   - Replace `head.ref` with `head.sha`
   - This locks the checkout to the specific approved commit

4. **Consider using `pull_request` trigger**
   - If you don't need secrets access, use `pull_request` instead
   - This is the safest option for running untrusted PR code

5. **Implement robust approval workflows**
   - Require label removal on new commits
   - Use GitHub's required reviews feature
   - Consider using GitHub Apps for automated approval management

### Additional Resources

For more information on securing GitHub Actions workflows, see:
- [GitHub Actions Security Best Practices](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions)
- [Preventing pwn requests](https://securitylab.github.com/research/github-actions-preventing-pwn-requests/)
- [CodeQL: Improper Access Control](https://codeql.github.com/codeql-query-help/actions/actions-improper-access-control/)
- [OWASP CI/CD Security Top 10](https://owasp.org/www-project-top-10-ci-cd-security-risks/)
