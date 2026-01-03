# Script Directory

This directory contains example workflows and utility scripts for the sisakulint project.

## Directory Structure

```
script/
├── actions/           # Example GitHub Actions workflow files
└── github_to_aws/     # AWS deployment infrastructure (Terraform)
```

## actions/

Contains example GitHub Actions workflow files that demonstrate various security issues and patterns that sisakulint can detect. These files are used for:

- **Testing**: Validating that sisakulint correctly identifies security vulnerabilities
- **Documentation**: Showing examples of vulnerable and safe workflow patterns
- **Development**: Testing new rules during development

### Example Files

| File | Description |
|------|-------------|
| `cache-poisoning.yaml` | Demonstrates cache poisoning vulnerabilities |
| `cache-poisoning-safe.yaml` | Safe cache configuration example |
| `credential.yaml` | Credential exposure patterns |
| `issueinjection.yaml` | Script injection via GitHub context |
| `issueinjection-multiline.yaml` | Multi-line injection patterns |
| `issueinjection-all-untrusted.yaml` | Comprehensive untrusted input examples |
| `pull_req_target_checkout.yaml` | `pull_request_target` checkout vulnerabilities |
| `permission.yaml` | Permission configuration examples |
| `timeout-minutes.yaml` | Timeout configuration patterns |
| `supply_chain_protection.yaml` | Supply chain security examples |
| `test-actionlist.yaml` | Action list rule testing |
| `test-actionlist-blacklist.yaml` | Blacklist validation testing |

### Usage

These workflows can be used to test sisakulint:

```bash
# Test a specific workflow file
sisakulint script/actions/issueinjection.yaml

# Test all example workflows
sisakulint script/actions/

# Test with debug output
sisakulint -debug script/actions/credential.yaml

# Test auto-fix functionality
sisakulint -fix dry-run script/actions/permission.yaml
```

### Adding New Examples

When adding new example workflows:

1. **Vulnerable patterns**: Name the file descriptively (e.g., `new-vulnerability.yaml`)
2. **Safe patterns**: Use `-safe` suffix (e.g., `new-vulnerability-safe.yaml`)
3. **Add comments**: Include inline comments explaining the security issue
4. **Update tests**: Add corresponding test cases in `pkg/core/*_test.go`

Example structure:

```yaml
# new-vulnerability.yaml
name: Example Vulnerability

on: [pull_request]

jobs:
  vulnerable:
    runs-on: ubuntu-latest
    steps:
      # VULNERABLE: This allows script injection
      - name: Unsafe use of PR title
        run: echo "${{ github.event.pull_request.title }}"
```

## github_to_aws/

Contains Terraform infrastructure code for deploying from GitHub Actions to AWS using OIDC authentication. This is used for the sisakulint project's own CI/CD pipeline.

### Features

- GitHub OIDC authentication with AWS
- IAM roles for S3, Lambda, and ECS deployments
- Least privilege access configuration

### Setup

See the [Terraform documentation](github_to_aws/) for setup instructions.

## Related Documentation

- [Main Documentation](https://sisaku-security.github.io/lint/)
- [Development Guide](../docs/DEVELOPMENT.md)
- [Rules Guide](../docs/RULES_GUIDE.md)
- [Architecture](../docs/ARCHITECTURE.md)
