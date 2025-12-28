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
	"context"
	_ "embed"
	"fmt"

	"github.com/open-policy-agent/opa/rego"
	"github.com/ultra-supara/sisakulint/pkg/ast"
)

type CredentialRule struct {
	BaseRule
	regoQuery rego.PreparedEvalQuery
}

//go:embed credential.rego
var credentialRego string

func CredentialsRule() *CredentialRule {
	query := mustPrepareRegoQuery("data.core.check_credentials", "credential.rego", credentialRego)

	return &CredentialRule{
		BaseRule: BaseRule{
			RuleName: "credentials",
			RuleDesc: "This rule checks for credentials in the source code",
		},
		regoQuery: query,
	}
}

func (rule *CredentialRule) VisitJobPre(node *ast.Job) error {
	if node.Container != nil {
		rule.checkCredentialsWithRego("\"Container\" section", node.Container)
	}
	for _, s := range node.Services {
		err := rule.checkCredentialsWithRego(fmt.Sprintf("\"Service\" section for service %s", s.Name.Value), s.Container)
		if err != nil {
			return err
		}
	}
	return nil
}

func (rule *CredentialRule) checkCredentialsWithRego(where string, node *ast.Container) error {
	containerData := map[string]interface{}{
		"credentials": map[string]interface{}{
			"password": node.Credentials.Password.Value,
		},
	}

	input := map[string]interface{}{
		"jobs": map[string]interface{}{
			"test": map[string]interface{}{
				"container": containerData,
			},
		},
	}

	results, err := rule.regoQuery.Eval(context.Background(), rego.EvalInput(input))
	if err != nil {
		rule.Errorf(nil, "Failed to evaluate policy: %v", err)
		return err
	}

	reportRegoError(rule, node.Credentials.Password.Pos, where, results)
	return nil
}
```

The detection query is `sisakulint/pkg/core/credential.rego` file
```rego
package core

check_credentials[violation] {
    container := input.jobs.test.container
    container.credentials.password
    not is_expression_assigned(container.credentials.password)
    violation := {
        "type": "credential_violation",
        "message": "Password found in container section, do not paste password direct hardcode",
        "position": "container.credentials.password"
    }
}

check_credentials[violation] {
    service := input.jobs.test.services[_]
    service.credentials.password
    not is_expression_assigned(service.credentials.password)
    violation := {
        "type": "credential_violation",
        "message": sprintf("Password found in service section %q, do not paste password direct hardcode", [service.name]),
        "position": "service.credentials.password"
    }
}

is_expression_assigned(password) {
    regex.match(`^\$\{.+\}$`, password)
}
```

## Overview of Credential Detection Process
The credential detection process involves several key components working together: the YAML configuration file, the Rego policy, the Go application, and the evaluation of the policy against the input data. The following diagram illustrates this workflow:

```md
+---------------------+
|                     |
|  YAML Configuration |
|      (credentials.yaml)      |
|                     |
+----------+----------+
           |
           v
+----------+----------+
|                     |
|   Go Application    |
|                     |
|  - Loads Rego Policy|
|  - Prepares Input   |
|  - Evaluates Policy  |
|                     |
+----------+----------+
           |
           v
+----------+----------+
|                     |
|     Rego Policy    |
|   (credential.rego)|
|                     |
+----------+----------+
           |
           v
+----------+----------+
|                     |
|   Evaluation Result |
|                     |
|  - Identifies       |
|    Hardcoded        |
|    Credentials      |
|                     |
+----------+----------+
           |
           v
+----------+----------+
|                     |
|   Error Reporting   |
|                     |
|  - Outputs Errors   |
|    to User          |
|                     |
+---------------------+
```

### Step-by-Step Explanation

1. **YAML Configuration File**:
   - The process begins with a YAML configuration file (e.g., `credentials.yaml`) that may contain hardcoded credentials. This file is the source of truth for the application's configuration.

2. **Go Application**:
   - The Go application is responsible for loading the Rego policy and preparing the input data for evaluation.
   - It reads the YAML file and extracts relevant sections, such as containers and services, particularly focusing on the `credentials` field.

3. **Rego Policy**:
   - The Rego policy (e.g., `credential.rego`) defines the rules for detecting hardcoded credentials. It specifies the conditions under which a password is considered hardcoded and thus a security risk.
   - The policy is embedded in the Go application, allowing it to be compiled and executed without external dependencies.

4. **Evaluation**:
   - The Go application prepares the input data in a structured format that the Rego policy can understand. This includes mapping the credentials found in the YAML file to the expected input structure.
   - The application then evaluates the Rego policy against this input data using the OPA engine. The evaluation checks for any violations based on the defined rules.

5. **Evaluation Result**:
   - The result of the evaluation indicates whether any hardcoded credentials were found. If violations are detected, the evaluation will return specific details about the errors, including their locations in the YAML file.