---
title: "Job Needs Rule"
weight: 1
---

### Job Needs Rule Overview

This rule validates job dependencies in GitHub Actions workflows by checking the `needs:` configuration. It detects duplicate dependencies, references to undefined jobs, and cyclic dependency chains that would cause workflow failures.

#### Key Features:

- **Duplicate Detection**: Identifies repeated job IDs in the `needs:` section
- **Undefined Job Detection**: Catches references to jobs that don't exist in the workflow
- **Cyclic Dependency Detection**: Finds circular dependency chains using DAG (Directed Acyclic Graph) analysis
- **Job ID Collision Detection**: Warns when the same job ID is defined multiple times

### Security Impact

**Severity: Low (3/10)**

While not a direct security issue, invalid job dependencies can lead to:

1. **Workflow Failures**: Workflows with invalid dependencies won't run, potentially blocking CI/CD pipelines
2. **Skipped Security Checks**: If security-related jobs have broken dependencies, they may be silently skipped
3. **Pipeline Bypass**: Attackers might exploit misconfigured dependencies to skip mandatory checks
4. **Deployment Without Testing**: Broken dependency chains can lead to deployments without proper validation

### Understanding Job Dependencies

GitHub Actions uses the `needs:` keyword to define job dependencies. Jobs run in parallel by default, but `needs:` creates explicit execution order.

#### Basic Dependency Syntax

```yaml
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: npm build

  test:
    needs: build  # Runs after 'build' completes
    runs-on: ubuntu-latest
    steps:
      - run: npm test

  deploy:
    needs: [build, test]  # Runs after both 'build' and 'test' complete
    runs-on: ubuntu-latest
    steps:
      - run: npm deploy
```

### Example Vulnerable Workflow

Common dependency misconfigurations:

```yaml
name: CI Pipeline

on: [push]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: npm build

  test:
    needs: [build, build]  # ❌ Duplicate: 'build' appears twice
    runs-on: ubuntu-latest
    steps:
      - run: npm test

  deploy:
    needs: release  # ❌ Undefined: 'release' job doesn't exist
    runs-on: ubuntu-latest
    steps:
      - run: npm deploy

  # ❌ Cyclic dependency: a -> b -> c -> a
  job-a:
    needs: job-c
    runs-on: ubuntu-latest
    steps:
      - run: echo "A"

  job-b:
    needs: job-a
    runs-on: ubuntu-latest
    steps:
      - run: echo "B"

  job-c:
    needs: job-b
    runs-on: ubuntu-latest
    steps:
      - run: echo "C"
```

### What the Rule Detects

#### 1. Duplicate Job IDs in Needs

When the same job ID appears multiple times in a `needs:` array:

```yaml
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: make build

  test:
    needs: [build, lint, build]  # ❌ 'build' duplicated
    runs-on: ubuntu-latest
    steps:
      - run: make test
```

**Error Output:**

```bash
workflow.yml:10:5: job ID "build" duplicates in needs section [needs]
```

#### 2. References to Undefined Jobs

When `needs:` references a job that doesn't exist:

```yaml
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: make build

  deploy:
    needs: testing  # ❌ 'testing' job doesn't exist
    runs-on: ubuntu-latest
    steps:
      - run: make deploy
```

**Error Output:**

```bash
workflow.yml:9:5: job ID "deploy" needs job "testing" is not defined [needs]
```

#### 3. Duplicate Job Definitions

When the same job ID is defined multiple times:

```yaml
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: make build

  build:  # ❌ Duplicate job ID
    runs-on: ubuntu-latest
    steps:
      - run: npm build
```

**Error Output:**

```bash
workflow.yml:10:3: job ID "build" is already defined at line:4,col:3 [needs]
```

#### 4. Cyclic Dependencies

When jobs form a circular dependency chain:

```yaml
jobs:
  job-a:
    needs: job-c
    runs-on: ubuntu-latest
    steps:
      - run: echo "A"

  job-b:
    needs: job-a
    runs-on: ubuntu-latest
    steps:
      - run: echo "B"

  job-c:
    needs: job-b  # ❌ Creates cycle: a -> b -> c -> a
    runs-on: ubuntu-latest
    steps:
      - run: echo "C"
```

**Error Output:**

```bash
workflow.yml:4:3: cyclic dependency in needs section found: "job-a" -> "job-c", "job-b" -> "job-a", "job-c" -> "job-b" is detected cycle [needs]
```

### Safe Patterns

#### Pattern 1: Linear Dependency Chain

```yaml
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: npm ci
      - run: npm run build

  test:
    needs: build
    runs-on: ubuntu-latest
    steps:
      - run: npm test

  deploy:
    needs: test
    runs-on: ubuntu-latest
    steps:
      - run: npm run deploy
```

#### Pattern 2: Fan-Out Pattern

Multiple jobs depending on a single job:

```yaml
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: npm run build

  unit-tests:
    needs: build
    runs-on: ubuntu-latest
    steps:
      - run: npm run test:unit

  integration-tests:
    needs: build
    runs-on: ubuntu-latest
    steps:
      - run: npm run test:integration

  e2e-tests:
    needs: build
    runs-on: ubuntu-latest
    steps:
      - run: npm run test:e2e
```

#### Pattern 3: Fan-In Pattern

Single job depending on multiple jobs:

```yaml
jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - run: npm run lint

  test:
    runs-on: ubuntu-latest
    steps:
      - run: npm test

  security-scan:
    runs-on: ubuntu-latest
    steps:
      - run: npm audit

  deploy:
    needs: [lint, test, security-scan]  # Waits for all three
    runs-on: ubuntu-latest
    steps:
      - run: npm run deploy
```

#### Pattern 4: Diamond Pattern

```yaml
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: npm run build

  lint:
    needs: build
    runs-on: ubuntu-latest
    steps:
      - run: npm run lint

  test:
    needs: build
    runs-on: ubuntu-latest
    steps:
      - run: npm test

  deploy:
    needs: [lint, test]  # Waits for both branches
    runs-on: ubuntu-latest
    steps:
      - run: npm run deploy
```

### Technical Detection Mechanism

The rule uses a Directed Acyclic Graph (DAG) algorithm to detect cyclic dependencies:

```go
// Check cyclic dependency using DAG traversal
func CheckCyclicDependency(nodes map[string]*jobNode) *edge {
    for _, v := range nodes {
        if v.status == nodeStatusNew {
            if e := CheckCyclicNode(v); e != nil {
                return e
            }
        }
    }
    return nil
}

func CheckCyclicNode(v *jobNode) *edge {
    v.status = nodeStatusActive
    for _, w := range v.resolved {
        switch w.status {
        case nodeStatusActive:
            return &edge{v, w}  // Cycle detected
        case nodeStatusNew:
            if e := CheckCyclicNode(w); e != nil {
                return e
            }
        }
    }
    v.status = nodeStatusInactive
    return nil
}
```

### Best Practices

#### 1. Keep Dependencies Explicit and Minimal

Only add dependencies that are truly necessary:

```yaml
# Good: Explicit, minimal dependencies
jobs:
  build:
    runs-on: ubuntu-latest
    steps: [...]

  test:
    needs: build  # Only depends on build
    steps: [...]

# Avoid: Unnecessary transitive dependencies
jobs:
  test:
    needs: [build, lint, setup]  # If 'lint' already needs 'build', don't repeat
```

#### 2. Document Complex Dependencies

Add comments for non-obvious dependency relationships:

```yaml
jobs:
  deploy:
    # Requires both security scan and tests to pass before deployment
    needs: [security-scan, integration-tests]
    runs-on: ubuntu-latest
```

#### 3. Use Conditional Dependencies Carefully

```yaml
jobs:
  deploy:
    needs: test
    if: needs.test.result == 'success'  # Only deploy if tests passed
    runs-on: ubuntu-latest
```

#### 4. Visualize Dependencies

For complex workflows, document the dependency graph:

```yaml
# Dependency Graph:
#
#   build
#   /   \
# lint  test
#   \   /
#   deploy

jobs:
  build: ...
  lint:
    needs: build
  test:
    needs: build
  deploy:
    needs: [lint, test]
```

### Common Mistakes

#### Mistake 1: Typos in Job References

```yaml
# ❌ Wrong: Typo in job name
jobs:
  build:
    runs-on: ubuntu-latest
    steps: [...]

  test:
    needs: buidl  # Typo: should be 'build'
```

#### Mistake 2: Case Sensitivity Confusion

Job IDs are case-insensitive for dependency resolution:

```yaml
# This works but can be confusing
jobs:
  Build:
    runs-on: ubuntu-latest
    steps: [...]

  test:
    needs: build  # Works, but lowercase doesn't match definition
```

#### Mistake 3: Self-Reference

```yaml
# ❌ Wrong: Job cannot depend on itself
jobs:
  build:
    needs: build  # Invalid self-reference
    runs-on: ubuntu-latest
```

### Relationship to Other Rules

- **[id]({{< ref "idrule.md" >}})**: Invalid job IDs will cause dependency resolution to fail
- **[workflow-call]({{< ref "workflowcall.md" >}})**: Reusable workflows have their own dependency considerations

### Detection Example

Running sisakulint on a workflow with dependency issues:

```bash
$ sisakulint .github/workflows/ci.yml

.github/workflows/ci.yml:10:5: job ID "build" duplicates in needs section [needs]
    10 👈|    needs: [build, build]

.github/workflows/ci.yml:15:5: job ID "deploy" needs job "release" is not defined [needs]
    15 👈|    needs: release

.github/workflows/ci.yml:20:3: cyclic dependency in needs section found: "job-a" -> "job-c", "job-b" -> "job-a", "job-c" -> "job-b" is detected cycle [needs]
    20 👈|  job-a:
```

### References

- [GitHub Docs: Workflow Syntax - needs](https://docs.github.com/en/actions/using-workflows/workflow-syntax-for-github-actions#jobsjob_idneeds)
- [GitHub Docs: Using jobs in a workflow](https://docs.github.com/en/actions/using-jobs/using-jobs-in-a-workflow)

### Testing

To test this rule:

```bash
# Detect dependency issues
sisakulint .github/workflows/*.yml

# Focus on needs rule only
sisakulint -ignore ".*" .github/workflows/*.yml 2>&1 | grep needs
```

### Configuration

This rule is enabled by default. To disable it:

```bash
sisakulint -ignore needs
```

Disabling this rule is **not recommended** as invalid job dependencies will cause workflow failures on GitHub.
