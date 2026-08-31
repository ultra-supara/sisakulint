---
title: "Credentials Rule"
weight: 1
---

### Credentials Rule Overview

This rule detects hardcoded credentials in GitHub Actions workflows, specifically focusing on passwords within container and service definitions. Hardcoding sensitive information like passwords directly in workflow files is a critical security risk that can lead to credential exposure.

**Vulnerable Example:**

```yaml
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    container:
      image: "example.com/owner/image"
      credentials:
        username: user
        password: "hardcodedPassword123"  # Hardcoded credential detected
    services:
      redis:
        image: redis
        credentials:
          username: user
          password: "anotherHardcodedPassword456"  # Hardcoded credential detected
    steps:
      - run: echo 'hello'
```

**Detection Output:**

```bash
credentials.yaml:9:19: "Container" section: Password found in container section, do not paste password direct hardcode [credentials]
      9 👈|        password: "hardcodedPassword123"

credentials.yaml:15:21: "Service" section for service redis: Password found in container section, do not paste password direct hardcode [credentials]
      15 👈|          password: "anotherHardcodedPassword456"
```

### Security Background

#### Why is this dangerous?

Hardcoded credentials in workflow files pose significant security risks:

1. **Version Control Exposure**: Credentials committed to version control are visible to anyone with repository access
2. **Fork Exposure**: Forked repositories inherit hardcoded credentials
3. **Log Exposure**: Hardcoded passwords may appear in CI/CD logs
4. **Rotation Difficulty**: Changing hardcoded credentials requires code changes and redeployment

#### Attack Scenario

```
1. Developer hardcodes password in workflow file
   └── Password committed to repository

2. Repository is forked or accessed by unauthorized user
   └── Credentials are visible in workflow file

3. Attacker uses credentials to access container registry
   └── Pulls or pushes malicious container images

4. Supply chain compromise
   └── Malicious images used in CI/CD pipeline
```

#### OWASP and CWE Mapping

- **CWE-798**: Use of Hard-coded Credentials
- **CWE-259**: Use of Hard-coded Password
- **OWASP CI/CD Security Risks**:
  - **CICD-SEC-6**: Insufficient Credential Hygiene

### Technical Detection Mechanism

The rule analyzes YAML workflow files and checks container/service credential definitions:

```go
// Detection pattern
var isExpr = regexp.MustCompile(`^\$\{.+\}$`)

func (rule *CredentialRule) checkCredentials(where string, node *ast.Container) {
    if node.Credentials != nil &&
       node.Credentials.Password != nil &&
       !isExpr.MatchString(node.Credentials.Password.Value) {
        // Password is hardcoded - not a GitHub Actions expression
        rule.Errorf(node.Credentials.Password.Pos,
            "Password found in %s, do not paste password direct hardcode", where)
    }
}
```

### Detection Logic Explanation

#### What the Rule Checks

1. **Container Section**: Validates passwords in job container definitions
2. **Service Definitions**: Validates passwords in service container credentials
3. **Expression Detection**: Uses regex `^\$\{.+\}$` to identify GitHub Actions expressions

#### Safe vs Hardcoded Patterns

**Safe (will NOT trigger an error):**
```yaml
credentials:
  username: user
  password: ${{ secrets.REGISTRY_PASSWORD }}  # Uses secrets - safe
```

**Hardcoded (will trigger an error):**
```yaml
credentials:
  username: user
  password: "myPassword123"  # Literal string - unsafe
  password: myPassword123    # Unquoted literal - unsafe
```

### Safe Patterns

#### Pattern 1: Using GitHub Secrets (Recommended)

```yaml
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    container:
      image: "example.com/owner/image"
      credentials:
        username: ${{ secrets.REGISTRY_USERNAME }}
        password: ${{ secrets.REGISTRY_PASSWORD }}  # Safe: Uses secrets
    steps:
      - run: echo 'hello'
```

#### Pattern 2: Using Environment Variables

```yaml
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    container:
      image: "example.com/owner/image"
      credentials:
        username: ${{ vars.REGISTRY_USERNAME }}
        password: ${{ secrets.REGISTRY_PASSWORD }}  # Safe
    steps:
      - run: echo 'hello'
```

### Auto-Fix Support

The credentials rule supports auto-fixing by removing the hardcoded password field:

```bash
# Preview changes without applying
sisakulint -fix dry-run

# Apply fixes
sisakulint -fix on
```

**Before (Vulnerable):**
```yaml
container:
  image: "example.com/image"
  credentials:
    username: user
    password: "hardcodedPassword123"
```

**After Auto-Fix:**
```yaml
container:
  image: "example.com/image"
  credentials:
    username: user
    # password field removed - you must add secrets reference manually
```

**Note:** Auto-fix removes the password field entirely. You must manually add a proper secrets reference (`${{ secrets.PASSWORD }}`) after the fix.

### Best Practices

#### 1. Always Use GitHub Secrets

Store sensitive credentials in GitHub Secrets and reference them using expressions:

```yaml
credentials:
  password: ${{ secrets.MY_PASSWORD }}
```

#### 2. Use Organization-Level Secrets

For credentials used across multiple repositories, use organization-level secrets:

```yaml
credentials:
  password: ${{ secrets.ORG_REGISTRY_PASSWORD }}
```

#### 3. Rotate Credentials Regularly

Even when using secrets, implement regular credential rotation policies.

#### 4. Limit Secret Access

Use environment-scoped secrets for production credentials:

```yaml
jobs:
  deploy:
    environment: production
    steps:
      - name: Deploy
        env:
          DEPLOY_TOKEN: ${{ secrets.PRODUCTION_DEPLOY_TOKEN }}
```

### Related Rules

- **[permissions]({{< ref "permissions.md" >}})**: Ensures workflows follow least-privilege principle
- **[commit-sha]({{< ref "commitsharule.md" >}})**: Pins actions to prevent supply chain attacks

### References

#### GitHub Documentation
- [GitHub Docs: Encrypted Secrets](https://docs.github.com/en/actions/security-guides/encrypted-secrets)
- [GitHub Docs: Using Secrets in GitHub Actions](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-secrets)

#### Security Resources
- [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)
- [OWASP: Credential Management](https://owasp.org/www-community/attacks/Credential_stuffing)

{{< popup_link2 href="https://docs.github.com/en/actions/security-guides/encrypted-secrets" >}}

{{< popup_link2 href="https://cwe.mitre.org/data/definitions/798.html" >}}

### Testing

To test this rule:

```bash
# Detect hardcoded credentials
sisakulint .github/workflows/*.yml

# Apply auto-fix
sisakulint -fix on .github/workflows/*.yml
```

### Configuration

This rule is enabled by default. To disable it:

```bash
sisakulint -ignore credentials
```
