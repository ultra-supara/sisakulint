---
title: "Credentials Rule"
weight: 1
# bookFlatSection: false
# bookToc: true
# bookHidden: false
# bookCollapseSection: false
# bookComments: false
# bookSearchExclude: false
---

**Rule Overview:**

This rule is designed to analyze YAML configuration files for hardcoded credentials, specifically focusing on passwords within container and service definitions. It aims to enhance security by identifying instances where sensitive information is directly embedded in the code. The rule identifies errors in the following cases:

1. **Hardcoded Passwords in Container Section**:
   - Checks for the presence of hardcoded passwords in the `credentials` section of a container definition.
   - Triggers an error if a password is found, as hardcoding passwords can lead to security vulnerabilities. Instead, credentials should be managed securely using environment variables or secret management tools.

2. **Hardcoded Passwords in Service Definitions**:
   - Analyzes service definitions for hardcoded passwords in their respective `credentials` sections.
   - Flags an error if a password is specified directly, emphasizing that sensitive information should not be hardcoded in service configurations.

3. **General Credential Management Best Practices**:
   - Encourages the use of secure methods for handling credentials, such as environment variables or secret management systems, to prevent accidental exposure of sensitive data.
   - Raises awareness about the risks associated with hardcoding credentials in source code, promoting adherence to best practices in security.

This rule helps enforce secure coding practices by identifying and flagging hardcoded credentials, thereby reducing the risk of security breaches and ensuring that sensitive information is handled appropriately.

The test sample `credentials.yaml` file is below.

```yaml
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    container:
      image: "example.com/owner/image"
      credentials:
        username: user
        password: "hardcodedPassword123"
    services:
      redis:
        image: redis
        credentials:
          username: user
          password: "anotherHardcodedPassword456"
    steps:
      - run: echo 'hello'
```

result

```bash
credentials.yaml:9:19: "Container" section: Password found in container section, do not paste password direct hardcode [credentials]
      9 👈|        password: "hardcodedPassword123"
                        
credentials.yaml:15:21: "Service" section for service redis: Password found in container section, do not paste password direct hardcode [credentials]
       15 👈|          password: "anotherHardcodedPassword456"
```

The credential linting rule is a crucial component of the security measures implemented in the codebase. By identifying hardcoded passwords in configuration files, it helps developers adhere to best practices in credential management, thereby reducing the risk of security breaches.

## Technical detection mechanism

`sisakulint/pkg/core/credential.go` file

```go
package core

import (
	"fmt"
	"regexp"

	"github.com/ultra-supara/sisakulint/pkg/ast"
)

type CredentialRule struct {
	BaseRule
}

var isExpr = regexp.MustCompile(`^\$\{.+\}$`)

func CredentialsRule() *CredentialRule {
	return &CredentialRule{
		BaseRule: BaseRule{
			RuleName: "credentials",
			RuleDesc: "This rule checks for credentials in the source code",
		},
	}
}

func (rule *CredentialRule) VisitJobPre(node *ast.Job) error {
	if node.Container != nil {
		rule.checkCredentials("\"Container\" section", node.Container)
	}
	for _, s := range node.Services {
		rule.checkCredentials(fmt.Sprintf("\"Service\" section for service %s", s.Name.Value), s.Container)
	}
	return nil
}

func (rule *CredentialRule) checkCredentials(where string, node *ast.Container) {
	if node.Credentials != nil && node.Credentials.Password != nil && !isExpr.MatchString(node.Credentials.Password.Value) {
		rule.Errorf(node.Credentials.Password.Pos, "Password found in %s, do not paste password direct hardcode", where)
		rule.AddAutoFixer(NewFuncFixer(rule.RuleName, func() error {
			return rule.FixCredentials(node.Credentials)
		}))
	}
}

func (rule *CredentialRule) FixCredentials(node *ast.Credentials) error {
	// remove password from container
	for i := 0; i < len(node.BaseNode.Content); i += 2 {
		if node.BaseNode.Content[i].Value == "password" {
			node.BaseNode.Content = append(node.BaseNode.Content[:i], node.BaseNode.Content[i+2:]...)
			break
		}
	}
	return nil
}
```

### Detection Logic Explanation

The credential rule uses a simple regex-based approach to detect hardcoded passwords:

1. **Pattern Matching**: The rule uses the regex pattern `^\$\{.+\}$` to identify GitHub Actions expressions (like `${{ secrets.PASSWORD }}`)
2. **Validation**: If a password value exists and does NOT match this expression pattern, it's flagged as a hardcoded credential
3. **Auto-fix Support**: When a hardcoded password is detected, the rule provides an auto-fixer that removes the password field from the YAML

### What's Considered Safe vs Hardcoded

**Safe (will NOT trigger an error):**
- GitHub Actions expressions: `${{ secrets.PASSWORD }}`
- Any value matching the pattern `${ ... }`

**Hardcoded (will trigger an error):**
- Plain text passwords: `"myPassword123"`
- Quoted strings: `"hardcodedPassword"`
- Any literal value that doesn't use the GitHub Actions expression syntax

**Example:**
```yaml
services:
  redis:
    image: redis
    credentials:
      username: user
      password: "hardcoded123"  # ❌ ERROR: Hardcoded password

  postgres:
    image: postgres
    credentials:
      username: user
      password: ${{ secrets.DB_PASSWORD }}  # ✅ OK: Uses GitHub Actions secrets
```

## Overview of Credential Detection Process
The credential detection process is straightforward and involves the following components:

```md
+---------------------+
|                     |
| GitHub Actions YAML |
|   (workflow file)   |
|                     |
+----------+----------+
           |
           v
+----------+----------+
|                     |
|   Go Application    |
|                     |
|  - Parses YAML to   |
|    AST              |
|  - Visits Job Nodes |
|                     |
+----------+----------+
           |
           v
+----------+----------+
|                     |
|  Credential Rule    |
|                     |
|  - Checks Container |
|  - Checks Services  |
|  - Applies Regex    |
|                     |
+----------+----------+
           |
           v
+----------+----------+
|                     |
|   Pattern Match     |
|                     |
|  - Is it a GitHub   |
|    Actions expr?    |
|    (^\$\{.+\}$)     |
|                     |
+----------+----------+
           |
           v
+----------+----------+
|                     |
|   Error Reporting   |
|   & Auto-fix        |
|                     |
|  - Reports errors   |
|  - Removes password |
|    field (if --fix) |
|                     |
+---------------------+
```

### Step-by-Step Explanation

1. **GitHub Actions Workflow File**:
   - The process begins with a GitHub Actions workflow YAML file that may contain hardcoded credentials in container or service definitions.

2. **YAML Parsing to AST**:
   - The Go application parses the YAML file into an Abstract Syntax Tree (AST), which allows structured traversal of the workflow configuration.

3. **Job Node Visiting**:
   - The `VisitJobPre` method is called for each job node in the workflow, checking both the job's container section and all service definitions.

4. **Credential Checking**:
   - For each container or service with credentials, the rule extracts the password value.
   - The password is checked against the regex pattern `^\$\{.+\}$` to determine if it's a GitHub Actions expression (like `${{ secrets.PASSWORD }}`).

5. **Error Detection**:
   - If the password value exists and does NOT match the expression pattern, it's considered a hardcoded credential and flagged as an error.
   - The error includes the exact position in the YAML file and a descriptive message.

6. **Auto-fix Capability**:
   - When a hardcoded password is detected, an auto-fixer is registered that can remove the password field from the YAML when run with the `--fix` flag.