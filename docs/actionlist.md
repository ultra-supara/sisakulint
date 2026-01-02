---
title: "Action List Rule"
weight: 1
# bookFlatSection: false
# bookToc: true
# bookHidden: false
# bookCollapseSection: false
# bookComments: false
# bookSearchExclude: false
---

### Action List Rule Overview

This rule enforces a whitelist of allowed GitHub Actions in your workflows. It helps prevent the use of unauthorized or potentially malicious third-party actions, which is a critical security practice for CI/CD pipelines.

**IMPORTANT**: This rule **only activates when `action-list:` is defined in `.github/sisakulint.yaml`**. Without this configuration, all actions are permitted by default. To begin using this rule, you must either:
1. Generate a configuration using `-generate-action-list` command (recommended for first-time setup)
2. Manually define `action-list:` patterns in your configuration file

When `action-list:` is not configured, sisakulint will not check action references, allowing you to use any third-party actions without restrictions.

#### Key Features:

- **Opt-in Activation**: Rule only runs when `action-list:` is configured in `.github/sisakulint.yaml`
- **Whitelist Enforcement**: Only actions matching configured patterns are allowed
- **Wildcard Support**: Use `*` wildcards to match multiple versions (e.g., `actions/checkout@*`)
- **Auto-generation**: Automatically generate whitelist from existing workflows
- **Auto-fix**: Automatically remove non-compliant action steps from workflows

### Generating Action List Configuration (First-Time Setup)

**Use this command when you don't have `action-list:` defined in `.github/sisakulint.yaml` yet.** This is the recommended way to create your initial whitelist configuration.

sisakulint provides a convenient command to automatically generate an action list configuration from your existing workflow files:

```bash
sisakulint -generate-action-list
```

This command will:
1. Scan all workflow files in `.github/workflows/`
2. Extract all action references (e.g., `actions/checkout@v4`)
3. Normalize them to patterns with wildcards (e.g., `actions/checkout@*`)
4. Generate or update `.github/sisakulint.yaml` with the action list

**Once generated, the action-list rule will activate on your next `sisakulint` run.**

#### Example Output:

```bash
Generated action list configuration at .github/sisakulint.yaml
Found 5 unique action patterns
```

#### Generated Configuration Example:

```yaml
# Configuration file for sisakulint
# Auto-generated action list from existing workflow files

# Allowed GitHub Actions (auto-generated from existing workflows)
action-list:
  - actions/checkout@*
  - actions/setup-go@*
  - docker/build-push-action@*
  - golangci/golangci-lint-action@*
```

### Pattern Matching

The action list supports flexible pattern matching with wildcards:

- **Version wildcards**: `actions/checkout@*` matches any version
- **Exact matches**: `actions/checkout@v4` matches only v4
- **Local paths**: `./local-action@v1` (preserved as-is)
- **Docker images**: `docker://alpine:latest` (preserved as-is)

### Example Workflow

Consider the following workflow file:

```yaml
name: CI
on: [push, pull_request]

jobs:
  lint:
    name: Lint
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: "1.21.4"
      - uses: unauthorized/suspicious-action@v1
        name: Run Suspicious Action
```

With the following `.github/sisakulint.yaml` configuration:

```yaml
action-list:
  - actions/checkout@*
  - actions/setup-go@*
  - golangci/golangci-lint-action@*
```

### Example Output

Running sisakulint will detect the unauthorized action:

```bash
$ sisakulint

.github/workflows/ci.yaml:12:9: action 'unauthorized/suspicious-action@v1' is not in the whitelist in step 'Run Suspicious Action' [action-list]
       12 👈|      - uses: unauthorized/suspicious-action@v1
```

### Auto-fix Support

The action-list rule supports auto-fixing by removing non-compliant action steps:

```bash
# Preview changes without applying
sisakulint -fix dry-run

# Apply fixes
sisakulint -fix on
```

After auto-fix, the unauthorized action step will be completely removed from the workflow file.

### Feature Background

#### Real-World Supply Chain Attack: tj-actions Breach

This rule was created in response to recommendations from the **Black Hat USA 2025 presentation** on the tj-actions supply chain breach, which demonstrated the critical need for action governance:

**The Incident:**
- **tj-actions/changed-files**, a popular GitHub Action used in over 23,000 public repositories, was compromised
- Attackers used "imposter commits" living in a fork to inject malicious code
- The malicious payload downloaded a Python script to dump and exfiltrate CI/CD secrets
- Traditional security tools failed to detect this sophisticated attack

**Recommendations**
The presentation outlined four key security controls, with **"Enforce an Action Allowlist"** as a critical recommendation:
1. Implement Security Monitoring for CI/CD Runners
2. **Enforce an Action Allowlist** - Due to over 25,000 actions in GitHub Marketplace, organizations must curate and control which actions can be used
3. Pin Actions to Specific Commit SHAs
4. Develop an Incident Response Plan

**Why Action Allowlist Matters**
With over 25,000 actions available in the GitHub Marketplace, it's impossible to manually vet every action. An allowlist approach ensures:
- Only pre-approved, vetted actions can be used in your workflows
- New or compromised actions are blocked by default
- Organizations maintain control over their CI/CD supply chain

#### Common Security Risks

As the complexity of CI/CD pipelines grows, the number of third-party actions used in workflows increases significantly. This introduces several security risks:

1. **Supply Chain Attacks**: Malicious actors can compromise popular actions or create imposter actions with similar names (as seen in the tj-actions breach)
2. **Credential Theft**: Unauthorized actions may exfiltrate secrets or credentials
3. **Code Injection**: Actions can inject malicious code into your build process
4. **Compliance Violations**: Using unvetted actions may violate organizational security policies

The action-list rule addresses these risks by implementing a whitelist approach:

- **Explicit Allow**: Only pre-approved actions can be used
- **Version Control**: Track approved actions in version control
- **Team Collaboration**: Share and review approved actions across teams
- **Automated Enforcement**: Catch unauthorized actions in CI/CD

This aligns with OWASP CI/CD Security Risk **CICD-SEC-8: Ungoverned Usage of 3rd Party Services**, specifically addressing the governance of third-party GitHub Actions. While CICD-SEC-8 covers a broader range of third-party integrations (GitHub Apps, OAuth, webhooks, etc.), this rule focuses on controlling and monitoring third-party action usage in workflows, which is a critical subset of the overall risk.

### Configuration Best Practices

1. **Start with generation**: Use `-generate-action-list` to create an initial whitelist when `.github/sisakulint.yaml` doesn't have `action-list:` configured yet
2. **Review and refine**: Manually review the generated list and remove any suspicious actions
3. **Understand opt-in behavior**: Remember that without `action-list:` in your config, this rule will not run—all actions are allowed
4. **Use wildcards wisely**: Balance security with maintenance overhead
   - `actions/checkout@*` - Flexible, allows version updates
   - `actions/checkout@v4` - Strict, requires config updates for new versions
5. **Regular updates**: Periodically regenerate and review your action list

### See Also

**Industry References:**
- [Black Hat USA 2025: tj-actions Supply Chain Breach Analysis](https://www.stepsecurity.io/blog/when-changed-files-changed-everything-our-black-hat-2025-presentation-on-the-tj-actions-supply-chain-breach) - Real-world case study demonstrating the need for action allowlists
- [OWASP Top 10 CI/CD Security Risks: CICD-SEC-08](https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-08-Ungoverned-Usage-of-3rd-Party-Services) - Ungoverned Usage of 3rd Party Services

{{< popup_link2 href="https://www.stepsecurity.io/blog/when-changed-files-changed-everything-our-black-hat-2025-presentation-on-the-tj-actions-supply-chain-breach" >}}

{{< popup_link2 href="https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-08-Ungoverned-Usage-of-3rd-Party-Services" >}}
