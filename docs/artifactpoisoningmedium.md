---
title: "Artifact Poisoning Rule(Medium) "
weight: 9
# bookFlatSection: false
# bookToc: true
# bookHidden: false
# bookCollapseSection: false
# bookComments: false
# bookSearchExclude: false
---

### Artifact Poisoning Rule (Medium) Overview

This rule detects potential artifact poisoning vulnerabilities when third-party artifact download actions are used in workflows triggered by untrusted events. Unlike the critical severity rule which focuses on unsafe extraction paths with the official `actions/download-artifact`, this medium severity rule targets third-party actions that may have unsafe default behaviors.

#### Key Features:

- **Third-Party Action Detection**: Identifies uses of non-official artifact download actions (e.g., `dawidd6/action-download-artifact`)
- **Untrusted Trigger Context**: Checks for workflows triggered by `workflow_run`, `pull_request_target`, or `issue_comment`
- **Heuristic Detection**: Uses naming patterns to catch new or unknown third-party artifact actions
- **Auto-fix Support**: Automatically adds safe extraction paths using `${{ runner.temp }}/artifacts`
- **Complementary to Critical Rule**: Works alongside artifact-poisoning-critical for comprehensive protection

### Difference from artifact-poisoning-critical

| Aspect | Critical | Medium |
|--------|----------|--------|
| **Target Actions** | `actions/download-artifact` only | Third-party artifact download actions |
| **Detection Focus** | Unsafe extraction path (workspace) | Untrusted trigger context + third-party actions |
| **Risk** | Direct file overwriting | Potentially unsafe default behavior of third-party actions |
| **Severity** | Critical (9/10) | Medium (6/10) |

### Security Impact

**Severity: Medium (6/10)**

Third-party artifact download actions in untrusted contexts represent a medium security risk:

1. **Default Behavior Risk**: Third-party actions may extract artifacts directly to the workspace by default
2. **Untrusted Source**: Artifacts from `workflow_run` or `pull_request_target` may originate from untrusted PRs
3. **File Overwriting**: Without explicit safe paths, malicious artifacts can overwrite existing files
4. **Supply Chain Vector**: Compromised workflows can inject malicious content into privileged contexts

This vulnerability aligns with OWASP CI/CD Security Risk **CICD-SEC-4: Poisoned Pipeline Execution (PPE)**.

### Example Vulnerable Workflow

Consider the following vulnerable workflow using a third-party artifact download action:

```yaml
name: Process PR Results

on:
  workflow_run:
    workflows: ["PR Build"]
    types: [completed]

jobs:
  process:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      # VULNERABLE: Third-party action with workflow_run trigger
      - name: Download PR artifacts
        uses: dawidd6/action-download-artifact@v2
        with:
          name: pr_number
          # No path specified - may extract to workspace root!

      # DANGEROUS: Executes script that may be overwritten
      - name: Process results
        run: |
          sh ./process.sh
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

### Attack Scenario

**How Third-Party Artifact Poisoning Works:**

1. **Attacker Opens Malicious PR**: Creates a pull request with malicious code
2. **PR Build Workflow Runs**: The "PR Build" workflow runs and uploads artifacts
3. **Malicious Artifact Created**: Attacker includes malicious `process.sh` in the artifact
4. **Workflow Run Triggered**: The `workflow_run` trigger fires for the "Process PR Results" workflow
5. **Third-Party Action Downloads**: `dawidd6/action-download-artifact` extracts the artifact
6. **Files Overwritten**: By default, the action may extract to the workspace root, overwriting `process.sh`
7. **Code Execution**: The malicious script executes with `GITHUB_TOKEN` access
8. **Compromise**: Attacker gains repository access and can steal secrets

This attack is particularly dangerous because:
- Third-party actions may have different security defaults than official actions
- The `workflow_run` trigger provides a privileged execution context
- Artifacts appear to come from the same repository
- The attack chain is not obvious to reviewers

### Example Output

Running sisakulint will detect unsafe third-party artifact downloads:

```bash
$ sisakulint

.github/workflows/process.yaml:12:9: artifact poisoning risk: third-party action "dawidd6/action-download-artifact@v2" downloads artifacts in workflow with untrusted triggers (workflow_run) without safe extraction path. This may allow malicious artifacts to overwrite existing files. Extract to '${{ runner.temp }}/artifacts' and validate content before use. See https://codeql.github.com/codeql-query-help/actions/actions-artifact-poisoning-medium/ [artifact-poisoning-medium]
     12 👈|      - name: Download PR artifacts
```

### Auto-fix Support

The artifact-poisoning-medium rule supports auto-fixing by adding safe extraction paths:

```bash
# Preview changes without applying
sisakulint -fix dry-run

# Apply fixes
sisakulint -fix on
```

After auto-fix, the workflow uses a safe extraction path:

```yaml
name: Process PR Results

on:
  workflow_run:
    workflows: ["PR Build"]
    types: [completed]

jobs:
  process:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      # FIXED: Safe extraction path specified
      - name: Download PR artifacts
        uses: dawidd6/action-download-artifact@v2
        with:
          name: pr_number
          path: ${{ runner.temp }}/artifacts  # Isolated directory

      # SECURE: Process from isolated location
      - name: Validate artifact
        run: |
          # Validate artifact integrity
          sha256sum -c ${{ runner.temp }}/artifacts/checksums.txt

      - name: Process results
        run: |
          # Copy validated files only
          cp ${{ runner.temp }}/artifacts/data.txt .
          sh ./process.sh
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

### Detected Third-Party Actions

The rule detects the following types of third-party artifact download actions:

#### Known Actions:
- `dawidd6/action-download-artifact` (explicitly listed in CodeQL documentation)

#### Heuristic Detection:
Any action (excluding `actions/download-artifact`) with a name containing both:
- "download" AND "artifact" (case-insensitive)

Examples caught by heuristic:
- `myorg/download-artifact@v1`
- `company/artifact-download-tool@v2`
- `user/download-artifacts-action@v1`

**Note**: The official `actions/download-artifact` is excluded because it's handled by the `artifact-poisoning-critical` rule.

### Best Practices

#### 1. Always Specify Safe Extraction Paths

Use `runner.temp` for third-party artifact actions:

```yaml
- uses: dawidd6/action-download-artifact@v2
  with:
    name: my-artifact
    path: ${{ runner.temp }}/artifacts  # Isolated directory
```

#### 2. Validate Artifact Content Before Use

Never trust downloaded artifacts from untrusted sources:

```yaml
- name: Validate artifact
  run: |
    # Verify checksums
    sha256sum -c ${{ runner.temp }}/artifacts/checksums.txt

    # Check file signatures (if available)
    gpg --verify ${{ runner.temp }}/artifacts/data.sig ${{ runner.temp }}/artifacts/data.txt

    # Scan for malicious content
    echo "Validating artifact contents..."
    if grep -r "eval\|exec" ${{ runner.temp }}/artifacts/; then
      echo "Suspicious content detected!"
      exit 1
    fi
```

#### 3. Prefer Official Actions When Possible

Use `actions/download-artifact` instead of third-party alternatives:

```yaml
# Good: Official action with explicit safe path
- uses: actions/download-artifact@v4
  with:
    name: my-artifact
    path: ${{ runner.temp }}/artifacts

# Less secure: Third-party action (may have different defaults)
- uses: dawidd6/action-download-artifact@v2
  with:
    name: my-artifact
    path: ${{ runner.temp }}/artifacts
```

#### 4. Separate Untrusted and Privileged Workflows

Avoid mixing artifact downloads from untrusted sources with privileged operations:

```yaml
# Build workflow (untrusted - runs on PRs)
name: PR Build
on: [pull_request]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm run build
      - uses: actions/upload-artifact@v4
        with:
          name: build-output
          path: dist/

---

# Deploy workflow (trusted - runs on main only)
name: Deploy
on:
  push:
    branches: [main]
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm run build  # Build from trusted source
      - run: ./deploy.sh
    # Don't download artifacts from untrusted PRs!
```

#### 5. Use workflow_run Safely

When using `workflow_run` triggers, verify the workflow source:

```yaml
on:
  workflow_run:
    workflows: ["PR Build"]
    types: [completed]

jobs:
  process:
    runs-on: ubuntu-latest
    # Only process artifacts from main branch
    if: github.event.workflow_run.head_branch == 'main'
    steps:
      - uses: dawidd6/action-download-artifact@v2
        with:
          workflow: ${{ github.event.workflow_run.workflow_id }}
          path: ${{ runner.temp }}/artifacts
```

### Detection Patterns

The artifact-poisoning-medium rule detects:

1. **Untrusted Triggers**:
   - `workflow_run`: Triggered by completion of another workflow
   - `pull_request_target`: Runs in base branch context with PR info
   - `issue_comment`: Triggered by comments from external contributors

2. **Third-Party Artifact Actions**:
   - Known third-party actions (e.g., `dawidd6/action-download-artifact`)
   - Actions matching naming heuristics (contains "download" + "artifact")
   - Excludes official `actions/download-artifact` (handled by critical rule)

3. **Risk Conditions**:
   - Missing `path` parameter
   - Unsafe `path` parameter (not using `runner.temp`)

### Safe Patterns

The rule does NOT trigger warnings for:

1. **Safe Triggers**:
   ```yaml
   on:
     pull_request:  # Safe: limited permissions
     push:          # Safe: only trusted branches
   ```

2. **Official Actions**:
   ```yaml
   - uses: actions/download-artifact@v4  # Handled by critical rule
   ```

3. **Safe Extraction Paths**:
   ```yaml
   - uses: dawidd6/action-download-artifact@v2
     with:
       path: ${{ runner.temp }}/artifacts  # Safe path specified
   ```

### Real-World Attack Vectors

#### Attack Vector 1: Cross-Workflow Artifact Poisoning

**Scenario**: Attacker poisons artifacts in a PR build that are consumed by a privileged workflow

```yaml
# Vulnerable Pattern
on:
  workflow_run:
    workflows: ["PR Tests"]
    types: [completed]

steps:
  - uses: dawidd6/action-download-artifact@v2
    with:
      name: test-results
      # No path - extracts to workspace!
```

**Mitigation**: Use safe paths and validate artifact source

#### Attack Vector 2: Comment-Triggered Artifact Processing

**Scenario**: Attacker triggers artifact download via issue comments

```yaml
# Vulnerable Pattern
on:
  issue_comment:
    types: [created]

steps:
  - uses: third-party/download-artifact-action@v1
    # May download malicious artifact from attacker's fork
```

**Mitigation**: Validate comment author and artifact source before processing

### Integration with GitHub Security Features

This rule complements GitHub's native security features:

- **Branch Protection**: Prevent direct pushes to protected branches
- **Required Reviews**: Require code review for workflow changes
- **CODEOWNERS**: Require security team review for `.github/workflows/` changes
- **Workflow Approval**: Require approval for first-time contributors' workflows

### CodeQL Integration

This rule is based on CodeQL's artifact-poisoning-medium query:
- [CodeQL Query: Artifact Poisoning (Medium)](https://codeql.github.com/codeql-query-help/actions/actions-artifact-poisoning-medium/)

sisakulint provides:
- Faster feedback during development (no CI run needed)
- Auto-fix capabilities
- Heuristic detection for new third-party actions
- No GitHub Advanced Security license required

### OWASP CI/CD Security Alignment

This rule addresses multiple OWASP CI/CD Security Risks:

**CICD-SEC-4: Poisoned Pipeline Execution (PPE)**
- Prevents malicious artifacts from executing in privileged contexts
- Isolates untrusted content from execution environment

**CICD-SEC-9: Improper Artifact Integrity Validation**
- Encourages artifact validation before use
- Promotes secure artifact handling practices

### Complementary Rules

Use these rules together for comprehensive protection:

1. **artifact-poisoning-critical**: Detects unsafe paths with official `actions/download-artifact`
2. **cache-poisoning**: Detects cache poisoning with untrusted triggers
3. **permissions**: Limits workflow permissions to reduce attack surface
4. **commit-sha**: Pins actions to prevent supply chain attacks

### Configuration

The artifact-poisoning-medium rule is enabled by default. To customize behavior, configure `.github/action.yaml`:

```yaml
# Currently no configuration options available
# Rule always enforces safe third-party artifact download practices
```

### Performance Considerations

This rule has minimal performance impact:
- **Detection**: O(n) where n is the number of steps
- **Auto-fix**: Modifies YAML structure in-place
- **No Network Calls**: Purely static analysis
- **Heuristic Matching**: Fast string operations

### See Also

**Industry References:**
- [CodeQL: Artifact Poisoning (Medium)](https://codeql.github.com/codeql-query-help/actions/actions-artifact-poisoning-medium/) - CodeQL's medium severity artifact poisoning detection
- [CodeQL: Artifact Poisoning (Critical)](https://codeql.github.com/codeql-query-help/actions/actions-artifact-poisoning-critical/) - Critical severity variant
- [GitHub: Preventing Pwn Requests](https://securitylab.github.com/research/github-actions-preventing-pwn-requests/) - GitHub Security Lab research
- [GitHub: Security Hardening for GitHub Actions](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions) - Official security guidance
- [OWASP: CICD-SEC-04 - Poisoned Pipeline Execution](https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-04-Poisoned-Pipeline-Execution) - PPE attack patterns

**Related sisakulint Rules:**
- [artifact-poisoning-critical](../artifactpoisoningcritical/) - Critical severity artifact poisoning detection
- [cache-poisoning](../cachepoisoningrule/) - Cache poisoning detection

{{< popup_link2 href="https://codeql.github.com/codeql-query-help/actions/actions-artifact-poisoning-medium/" >}}

{{< popup_link2 href="https://securitylab.github.com/research/github-actions-preventing-pwn-requests/" >}}

{{< popup_link2 href="https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions" >}}

{{< popup_link2 href="https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-04-Poisoned-Pipeline-Execution" >}}
