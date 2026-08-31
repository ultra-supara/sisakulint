---
title: "Expression Rule"
weight: 1
---

### Expression Rule Overview

This rule validates GitHub Actions expression syntax (`${{ }}`) throughout workflow files. It performs comprehensive checks including syntax validation, type checking, context availability, and semantic analysis to catch errors before workflows run.

#### Key Features:

- **Syntax Validation**: Parses and validates `${{ }}` expression syntax
- **Type Checking**: Verifies expression types match expected contexts (string, bool, number, object, array)
- **Context Availability**: Ensures contexts (github, env, secrets, matrix, steps, needs, inputs, jobs) are used in valid scopes
- **Semantic Analysis**: Validates property access, function calls, and operators
- **Matrix Type Inference**: Tracks matrix variable types across jobs
- **Steps/Needs Context Tracking**: Validates step outputs and job dependencies

### Security Impact

**Severity: Medium (5/10)**

Invalid expressions can lead to:

1. **Workflow Failures**: Syntax errors cause jobs to fail at runtime
2. **Logic Errors**: Type mismatches can cause unexpected behavior in conditionals
3. **Information Disclosure**: Incorrect context usage might expose unintended data
4. **Security Bypass**: Invalid conditions in security-critical jobs may be evaluated incorrectly
5. **Build Failures**: Expression errors in matrix configurations break parallel builds

### Understanding GitHub Actions Expressions

GitHub Actions uses expressions with `${{ }}` syntax for dynamic values:

```yaml
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Display context
        run: |
          echo "Repository: ${{ github.repository }}"
          echo "Branch: ${{ github.ref_name }}"
          echo "Actor: ${{ github.actor }}"
```

#### Available Contexts

| Context | Description | Availability |
|---------|-------------|--------------|
| `github` | Information about the workflow run | Always |
| `env` | Environment variables | Always |
| `vars` | Repository/organization variables | Always |
| `job` | Current job information | Jobs |
| `jobs` | Outputs from other jobs | `on.workflow_call.outputs` |
| `steps` | Step outputs and status | Steps |
| `runner` | Runner information | Jobs |
| `secrets` | Secret values | Jobs |
| `strategy` | Matrix strategy context | Jobs with matrix |
| `matrix` | Matrix values | Jobs with matrix |
| `needs` | Dependent job outputs | Jobs with `needs:` |
| `inputs` | Workflow inputs | `workflow_call`, `workflow_dispatch` |

### Example Vulnerable Workflow

Common expression errors:

```yaml
name: CI Build

on:
  push:
    branches: [main]
  workflow_dispatch:
    inputs:
      deploy:
        type: boolean
        default: false

jobs:
  build:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        os: [ubuntu-latest, windows-latest]

    steps:
      - uses: actions/checkout@v4

      # ❌ Type error: object/array in template
      - run: echo "${{ github.event }}"

      # ❌ Undefined property access
      - run: echo "${{ github.undefined_property }}"

      # ❌ Wrong context scope
      - run: echo "${{ jobs.other.outputs.result }}"

      - id: build
        run: echo "version=1.0.0" >> "$GITHUB_OUTPUT"

  deploy:
    needs: build
    runs-on: ubuntu-latest
    if: ${{ inputs.deploy == true }}
    steps:
      # ❌ Undefined step reference
      - run: echo "${{ steps.nonexistent.outputs.value }}"

      # ❌ Using steps from another job
      - run: echo "${{ steps.build.outputs.version }}"
```

### What the Rule Detects

#### 1. Syntax Errors

Invalid expression syntax:

```yaml
# ❌ Missing closing bracket
- run: echo "${{ github.actor }"

# ❌ Invalid operators
- run: echo "${{ github.actor AND github.repository }}"

# ❌ Unclosed string
- run: echo "${{ 'hello }}"
```

**Error Output:**

```bash
workflow.yml:10:15: unexpected token "}" while parsing expression [expression]
```

#### 2. Type Mismatches

Using wrong types in contexts:

```yaml
# ❌ Object cannot be evaluated in template
- run: echo "Event: ${{ github.event }}"

# ❌ Array cannot be evaluated in template
- run: echo "Labels: ${{ github.event.pull_request.labels }}"

# ❌ Null value in template
- run: echo "Value: ${{ null }}"
```

**Error Output:**

```bash
workflow.yml:10:15: object, array, and null values should not be evaluated in template with ${{ }} but evaluating the value of type object [expression]
```

#### 3. Invalid Context Usage

Using contexts outside their valid scope:

```yaml
# ❌ 'jobs' context only available in on.workflow_call.outputs
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ jobs.test.outputs.result }}"

# ❌ 'matrix' context only available when strategy.matrix is defined
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ matrix.os }}"
```

**Error Output:**

```bash
workflow.yml:8:21: context "jobs" is not available here [expression]
```

#### 4. Invalid Property Access

Accessing undefined properties:

```yaml
# ❌ Undefined property
- run: echo "${{ github.nonexistent }}"

# ❌ Typo in property name
- run: echo "${{ github.repositry }}"

# ❌ Wrong context structure
- run: echo "${{ steps.build.output.version }}"  # Should be 'outputs'
```

**Error Output:**

```bash
workflow.yml:10:21: property "nonexistent" is not defined in object type {repository: string, ...} [expression]
```

#### 5. Type Errors in Conditions

Invalid types in `if` conditions:

```yaml
# ❌ String type in condition (should be bool)
- name: Deploy
  if: ${{ github.ref }}
  run: ./deploy.sh

# ❌ Number type in condition
- name: Check
  if: ${{ steps.count.outputs.total }}
  run: echo "Has items"
```

**Error Output:**

```bash
workflow.yml:10:7: "if" condition should be type "bool" but got type "string" [expression]
```

#### 6. Invalid Function Usage

Incorrect function calls:

```yaml
# ❌ Wrong number of arguments
- run: echo "${{ contains(github.ref) }}"

# ❌ Invalid argument types
- run: echo "${{ startsWith(123, 'test') }}"

# ❌ Undefined function
- run: echo "${{ lowercase(github.actor) }}"
```

**Error Output:**

```bash
workflow.yml:10:21: function "contains" requires 2 arguments but got 1 [expression]
```

#### 7. Matrix Type Validation

Invalid matrix expressions:

```yaml
strategy:
  matrix:
    os: [ubuntu-latest, windows-latest]
    node: [14, 16, 18]

steps:
  # ❌ Undefined matrix property
  - run: echo "${{ matrix.version }}"

  # ❌ Type mismatch in matrix
  - run: echo "${{ matrix.os + 1 }}"  # os is string, not number
```

**Error Output:**

```bash
workflow.yml:15:21: property "version" is not defined in object type {os: string, node: number} [expression]
```

#### 8. Needs Context Validation

Invalid job dependency references:

```yaml
jobs:
  build:
    runs-on: ubuntu-latest
    outputs:
      version: ${{ steps.ver.outputs.version }}
    steps:
      - id: ver
        run: echo "version=1.0.0" >> "$GITHUB_OUTPUT"

  deploy:
    needs: build
    runs-on: ubuntu-latest
    steps:
      # ❌ Undefined output from dependency
      - run: echo "${{ needs.build.outputs.nonexistent }}"

      # ❌ Reference to job not in needs
      - run: echo "${{ needs.test.outputs.result }}"
```

**Error Output:**

```bash
workflow.yml:18:21: property "nonexistent" is not defined in object type {version: string} [expression]
```

### Safe Patterns

#### Pattern 1: Correct Property Access

```yaml
steps:
  - name: Display info
    run: |
      echo "Repository: ${{ github.repository }}"
      echo "Ref: ${{ github.ref }}"
      echo "SHA: ${{ github.sha }}"
      echo "Actor: ${{ github.actor }}"
```

#### Pattern 2: Proper Type Handling

```yaml
steps:
  # Convert object to JSON string
  - run: echo '${{ toJSON(github.event) }}'

  # Access specific properties
  - run: echo "${{ github.event.pull_request.title }}"
```

#### Pattern 3: Valid Conditionals

```yaml
steps:
  - name: Deploy on main
    if: github.ref == 'refs/heads/main'
    run: ./deploy.sh

  - name: Skip on PR
    if: github.event_name != 'pull_request'
    run: ./full-build.sh

  - name: Check success
    if: success() && github.actor != 'dependabot[bot]'
    run: ./notify.sh
```

#### Pattern 4: Matrix with Type Safety

```yaml
strategy:
  matrix:
    os: [ubuntu-latest, macos-latest]
    node: [16, 18, 20]

steps:
  - name: Setup Node
    uses: actions/setup-node@v4
    with:
      node-version: ${{ matrix.node }}

  - name: Display OS
    run: echo "Running on ${{ matrix.os }}"
```

#### Pattern 5: Steps and Needs References

```yaml
jobs:
  build:
    runs-on: ubuntu-latest
    outputs:
      version: ${{ steps.version.outputs.version }}
    steps:
      - id: version
        run: echo "version=1.0.0" >> "$GITHUB_OUTPUT"

  deploy:
    needs: build
    runs-on: ubuntu-latest
    steps:
      - run: echo "Deploying version ${{ needs.build.outputs.version }}"
```

#### Pattern 6: Workflow Inputs Validation

```yaml
on:
  workflow_dispatch:
    inputs:
      environment:
        type: choice
        options: [dev, staging, prod]
      debug:
        type: boolean
        default: false

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - name: Deploy
        if: inputs.debug == false
        run: ./deploy.sh --env ${{ inputs.environment }}
```

### Technical Detection Mechanism

The rule uses a multi-pass analysis approach:

```go
// Expression syntax validation
func (rule *ExprRule) checkExprsIn(s string, pos *ast.Position, ...) ([]typedExpression, bool) {
    // Parse ${{ }} expressions
    for {
        idx := strings.Index(s, "${{")
        if idx == -1 {
            break
        }
        // Tokenize and parse expression
        ty, offsetAfter, ok := rule.checkSemantics(s, Line, col, checkUntrusted, workflowKey)
        // ...
    }
    return ts, true
}

// Semantic analysis with type inference
func (rule *ExprRule) checkSemanticsOfExprNode(expr expressions.ExprNode, ...) (expressions.ExprType, bool) {
    c := expressions.NewExprSemanticsChecker(checkUntrusted, v)

    // Update context availability based on workflow location
    if rule.MatrixType != nil {
        c.UpdateMatrix(rule.MatrixType)
    }
    if rule.StepsType != nil {
        c.UpdateSteps(rule.StepsType)
    }
    // ... more context updates

    ty, errs := c.Check(expr)
    // Report errors
    return ty, len(errs) == 0
}
```

### Context Availability by Workflow Location

| Location | Available Contexts |
|----------|-------------------|
| `env:` (workflow level) | github, inputs, vars, secrets |
| `jobs.<job_id>.env:` | github, needs, strategy, matrix, inputs, vars, secrets, env |
| `jobs.<job_id>.steps[*].env:` | github, needs, strategy, matrix, inputs, vars, secrets, env, steps, job |
| `jobs.<job_id>.if:` | github, needs, inputs, vars, always, cancelled, success, failure |
| `jobs.<job_id>.steps[*].if:` | github, needs, strategy, matrix, inputs, vars, secrets, env, steps, job, runner |
| `on.workflow_call.outputs` | github, inputs, jobs |

### Best Practices

#### 1. Use Proper Type Conversions

```yaml
# Convert objects to JSON for display
- run: echo '${{ toJSON(github.event.inputs) }}'

# Convert to string explicitly
- run: echo "Count: ${{ format('{0}', steps.count.outputs.total) }}"
```

#### 2. Validate Input Types

```yaml
on:
  workflow_dispatch:
    inputs:
      count:
        type: number
        required: true

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      # Type-safe comparison
      - if: inputs.count > 0
        run: echo "Processing ${{ inputs.count }} items"
```

#### 3. Use Functions Correctly

```yaml
steps:
  # contains() with proper types
  - if: contains(github.event.pull_request.labels.*.name, 'urgent')
    run: echo "Urgent PR"

  # startsWith() for branch checks
  - if: startsWith(github.ref, 'refs/tags/')
    run: echo "Tag push"

  # format() for string building
  - run: echo "${{ format('Hello {0}!', github.actor) }}"
```

### Relationship to Other Rules

- **[conditional]({{< ref "conditionalrule.md" >}})**: Validates specific conditional expression patterns
- **[code-injection-critical]({{< ref "codeinjectioncritical.md" >}})**: Detects untrusted input in expressions
- **[envvar-injection-critical]({{< ref "envvarinjectioncritical.md" >}})**: Detects untrusted input written to environment files

### Detection Example

Running sisakulint on a workflow with expression errors:

```bash
$ sisakulint .github/workflows/ci.yml

.github/workflows/ci.yml:15:21: object, array, and null values should not be evaluated in template with ${{ }} but evaluating the value of type object [expression]
    15 👈|      - run: echo "${{ github.event }}"

.github/workflows/ci.yml:20:7: "if" condition should be type "bool" but got type "string" [expression]
    20 👈|    if: ${{ github.ref }}

.github/workflows/ci.yml:25:21: property "nonexistent" is not defined in object type {repository: string, ...} [expression]
    25 👈|      - run: echo "${{ github.nonexistent }}"
```

### References

- [GitHub Docs: Expressions](https://docs.github.com/en/actions/learn-github-actions/expressions)
- [GitHub Docs: Contexts](https://docs.github.com/en/actions/learn-github-actions/contexts)
- [GitHub Docs: Workflow Syntax](https://docs.github.com/en/actions/using-workflows/workflow-syntax-for-github-actions)

### Testing

To test this rule:

```bash
# Detect expression errors
sisakulint .github/workflows/*.yml

# Debug mode for detailed type information
sisakulint -debug .github/workflows/*.yml
```

### Configuration

This rule is enabled by default. To disable it:

```bash
sisakulint -ignore expression
```

Disabling this rule is **strongly discouraged** as expression validation catches many common errors before runtime.
