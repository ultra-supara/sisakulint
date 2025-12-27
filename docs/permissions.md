---
title: "Permissions Rule"
weight: 1
# bookFlatSection: false
# bookToc: true
# bookHidden: false
# bookCollapseSection: false
# bookComments: false
# bookSearchExclude: false
---

---

**Rule Overview:**

This rule is designed to analyze and enforce permission settings for GitHub Actions, ensuring proper scopes and values are used when configuring permissions. The rule checks the following:

1. **Whole Permissions Validation**:
   - Validates that the overall permissions setting only uses the accepted values: `"write-all"`, `"read-all"`, or `"none"`.
   - Ensures that any deviation from these values triggers an alert or warning, guiding users to set the appropriate permission level.

2. **Scope-Specific Permissions**:
   - Focuses on specific scopes like `"checks"`, verifying that only the accepted permission values `"read"`, `"write"`, or `"none"` are applied.
   - Ensures that any misconfiguration in these scoped permissions is flagged for correction, such as using incorrect or unsupported values.

This rule helps maintain security best practices by ensuring that permissions are explicitly and correctly defined, reducing the risk of overly broad access in GitHub Actions workflows.

The test sample `permissions.yaml` file is below

```yaml
on: push

# ERROR
permissions: write
permissions: write-all
permissions: read-all

jobs:
  test:
    runs-on: ubuntu-latest
    permissions:
      # ERROR
      check: write
      # ERROR
      issues: readable
      contents: write-all
    steps:
      - run: echo hello
```

results

```bash
$ sisakulint -ignore expressions -debug

.github/workflows/permissions.yaml:4:14: "write" is invalid for permission for all the scopes. [permissions]
      4 👈|permissions: write

.github/workflows/permissions.yaml:6:14: "read-all" is invalid for permission for all the scopes. [permissions]
      6 👈|permissions: read-all
                   
.github/workflows/permissions.yaml:11:7: unknown permission scope "check". all available permission scopes are "actions", "checks", "contents", "deployments", "discussions", "id-token", "issues", "packages", "pages", "pull-requests", "repository-projects", "security-events", "statuses" [permissions]
       11 👈|      check: write
             
.github/workflows/permissions.yaml:13:15: The value "readable" is not a valid permission for the scope "issues". Only 'read', 'write', or 'none' are acceptable values. [permissions]
       13 👈|      issues: readable
                     
.github/workflows/permissions.yaml:14:17: The value "write-all" is not a valid permission for the scope "contents". Only 'read', 'write', or 'none' are acceptable values. [permissions]
       14 👈|      contents: write-all
```

I was able to get the following error.Available values for whole permissions are "write-all", "read-all" or "none".

{{< popup_link2 href=https://docs.github.com/en/actions/security-guides/automatic-token-authentication#permissions-for-the-github_token >}}
