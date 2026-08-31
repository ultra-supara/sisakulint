---
title: "Deprecated Commands Rule"
weight: 1
---

### Deprecated Commands Rule Overview

This rule detects deprecated GitHub Actions workflow commands in `run:` scripts. These commands have been deprecated due to security vulnerabilities and should be replaced with safer alternatives using environment files.

#### Key Features:

- **Deprecated Command Detection**: Identifies `set-output`, `save-state`, `set-env`, and `add-path` commands
- **Migration Guidance**: Provides the recommended replacement for each deprecated command
- **Pattern-Based Detection**: Uses regex to find deprecated commands in shell scripts

### Security Impact

**Severity: High (7/10)**

Deprecated workflow commands were deprecated specifically due to security vulnerabilities:

1. **Command Injection**: The `set-env` and `add-path` commands were vulnerable to injection attacks
2. **Log Poisoning**: Malicious data in logs could inject environment variables or paths
3. **Untrusted Input Exploitation**: Attackers could manipulate workflow behavior through log output
4. **Privilege Escalation**: Injected environment variables could alter subsequent steps' behavior
5. **Supply Chain Risk**: Compromised dependencies could inject malicious values

This aligns with **OWASP CI/CD Security Risk CICD-SEC-04: Poisoned Pipeline Execution (PPE)**.

### Deprecated Commands History

GitHub deprecated these commands in two phases:

#### October 2020: `set-env` and `add-path`

```bash
# Deprecated (vulnerable to injection)
echo "::set-env name=MY_VAR::value"
echo "::add-path::/custom/path"
```

These commands allowed attackers to inject arbitrary environment variables and PATH modifications through workflow logs.

#### October 2022: `set-output` and `save-state`

```bash
# Deprecated
echo "::set-output name=result::value"
echo "::save-state name=data::value"
```

These were deprecated as part of a security hardening initiative and to standardize the output mechanism.

### Example Vulnerable Workflow

Workflow using deprecated commands:

```yaml
name: CI Build

on: [push]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      # ❌ Deprecated: set-output
      - name: Set version
        id: version
        run: echo "::set-output name=version::1.0.0"

      # ❌ Deprecated: save-state
      - name: Save state
        run: echo "::save-state name=build_id::12345"

      # ❌ Deprecated: set-env (SECURITY RISK)
      - name: Set environment
        run: echo "::set-env name=MY_VAR::my_value"

      # ❌ Deprecated: add-path (SECURITY RISK)
      - name: Add to path
        run: echo "::add-path::/custom/bin"

      - name: Use outputs
        run: echo "Version: ${{ steps.version.outputs.version }}"
```

### What the Rule Detects

#### 1. Deprecated `set-output` Command

```yaml
- name: Set output
  id: example
  run: echo "::set-output name=result::success"  # ❌ Deprecated
```

**Error Output:**

```bash
workflow.yml:10:13: workflow command "set-output" was deprecated. You should use `echo "{name}={value}" >> $GITHUB_OUTPUT` reference: https://docs.github.com/en/actions/using-workflows/workflow-commands-for-github-actions [deprecated-commands]
```

#### 2. Deprecated `save-state` Command

```yaml
- name: Save state
  run: echo "::save-state name=data::value"  # ❌ Deprecated
```

**Error Output:**

```bash
workflow.yml:10:13: workflow command "save-state" was deprecated. You should use `echo "{name}={value}" >> $GITHUB_STATE` reference: https://docs.github.com/en/actions/using-workflows/workflow-commands-for-github-actions [deprecated-commands]
```

#### 3. Deprecated `set-env` Command (Security Critical)

```yaml
- name: Set environment variable
  run: echo "::set-env name=API_KEY::secret123"  # ❌ Security risk
```

**Error Output:**

```bash
workflow.yml:10:13: workflow command "set-env" was deprecated. You should use `echo "{name}={value}" >> $GITHUB_ENV` reference: https://docs.github.com/en/actions/using-workflows/workflow-commands-for-github-actions [deprecated-commands]
```

#### 4. Deprecated `add-path` Command (Security Critical)

```yaml
- name: Add path
  run: echo "::add-path::/usr/local/custom/bin"  # ❌ Security risk
```

**Error Output:**

```bash
workflow.yml:10:13: workflow command "add-path" was deprecated. You should use `echo "{path}" >> $GITHUB_PATH` reference: https://docs.github.com/en/actions/using-workflows/workflow-commands-for-github-actions [deprecated-commands]
```

### Safe Patterns

#### Pattern 1: Setting Step Outputs (Modern)

```yaml
- name: Set version
  id: version
  run: echo "version=1.0.0" >> "$GITHUB_OUTPUT"

- name: Use output
  run: echo "Version: ${{ steps.version.outputs.version }}"
```

#### Pattern 2: Saving State (Modern)

```yaml
- name: Save state
  run: echo "build_id=12345" >> "$GITHUB_STATE"
```

#### Pattern 3: Setting Environment Variables (Modern)

```yaml
- name: Set environment variable
  run: echo "MY_VAR=my_value" >> "$GITHUB_ENV"

- name: Use environment variable
  run: echo "MY_VAR is $MY_VAR"
```

#### Pattern 4: Adding to PATH (Modern)

```yaml
- name: Add to PATH
  run: echo "/custom/bin" >> "$GITHUB_PATH"

- name: Use new path
  run: custom-command  # Now available in PATH
```

#### Pattern 5: Multi-line Outputs

For values containing newlines or special characters:

```yaml
- name: Set multi-line output
  id: changelog
  run: |
    {
      echo 'changelog<<EOF'
      cat CHANGELOG.md
      echo 'EOF'
    } >> "$GITHUB_OUTPUT"

- name: Display changelog
  run: echo "${{ steps.changelog.outputs.changelog }}"
```

#### Pattern 6: Dynamic Output Names

```yaml
- name: Set dynamic output
  id: dynamic
  run: |
    name="result_$(date +%Y%m%d)"
    echo "${name}=success" >> "$GITHUB_OUTPUT"
```

### Migration Guide

| Deprecated Command | Modern Replacement |
|-------------------|-------------------|
| `echo "::set-output name=NAME::VALUE"` | `echo "NAME=VALUE" >> "$GITHUB_OUTPUT"` |
| `echo "::save-state name=NAME::VALUE"` | `echo "NAME=VALUE" >> "$GITHUB_STATE"` |
| `echo "::set-env name=NAME::VALUE"` | `echo "NAME=VALUE" >> "$GITHUB_ENV"` |
| `echo "::add-path::PATH"` | `echo "PATH" >> "$GITHUB_PATH"` |

### Technical Detection Mechanism

The rule uses regex pattern matching to detect deprecated commands:

```go
// Pattern to detect deprecated workflow commands
var deprecatedCommandsPattern = regexp.MustCompile(
    `(?:::(save-state|set-output|set-env)\s+name=[a-zA-Z][a-zA-Z_-]*::\S+|::(add-path)::\S+)`)

func (rule *RuleDeprecatedCommands) VisitStep(step *ast.Step) error {
    if execRun, isExecRun := step.Exec.(*ast.ExecRun); isExecRun && execRun.Run != nil {
        for _, matches := range deprecatedCommandsPattern.FindAllStringSubmatch(execRun.Run.Value, -1) {
            command := matches[1]
            if len(command) == 0 {
                command = matches[2]
            }
            // Report error with migration guidance
            rule.Errorf(execRun.Run.Pos,
                "workflow command %q was deprecated. You should use `%s`...",
                command, replacement)
        }
    }
    return nil
}
```

### Security Vulnerability Background

#### The `set-env` and `add-path` Vulnerability

In 2020, GitHub discovered that `set-env` and `add-path` commands were vulnerable to log injection attacks:

1. **Attack Vector**: Untrusted data written to workflow logs could contain `::set-env` commands
2. **Impact**: Attackers could inject arbitrary environment variables
3. **Exploitation**: A malicious package dependency could set dangerous environment variables
4. **Example Attack**:

```bash
# Malicious package output during npm install:
# ::set-env name=NODE_OPTIONS::--require=/tmp/malicious.js
```

This could cause all subsequent Node.js operations to execute malicious code.

#### Why Environment Files Are Safer

The new environment file approach (`$GITHUB_ENV`, `$GITHUB_OUTPUT`, etc.) is safer because:

1. **Explicit File Operations**: Writing to files is explicit and auditable
2. **No Log Parsing**: The runner doesn't parse log output for commands
3. **Controlled Access**: Environment files have controlled permissions
4. **Clear Intent**: File-based approach makes intentions clear in code reviews

### Best Practices

#### 1. Always Quote Variables

```yaml
# Good: Properly quoted
- run: echo "version=${{ steps.get.outputs.version }}" >> "$GITHUB_OUTPUT"

# Bad: Unquoted, may cause issues
- run: echo version=$VERSION >> $GITHUB_OUTPUT
```

#### 2. Handle Special Characters

```yaml
# Use heredoc for complex values
- run: |
    {
      echo 'message<<EOF'
      echo "$COMPLEX_MESSAGE"
      echo 'EOF'
    } >> "$GITHUB_OUTPUT"
```

#### 3. Check for Empty Values

```yaml
- name: Set output safely
  run: |
    if [ -n "$VALUE" ]; then
      echo "result=$VALUE" >> "$GITHUB_OUTPUT"
    else
      echo "result=default" >> "$GITHUB_OUTPUT"
    fi
```

### Common Mistakes

#### Mistake 1: Missing File Redirect

```yaml
# ❌ Wrong: Missing >> operator
- run: echo "version=1.0.0" > "$GITHUB_OUTPUT"  # Overwrites!

# ✅ Correct: Append to file
- run: echo "version=1.0.0" >> "$GITHUB_OUTPUT"
```

#### Mistake 2: Wrong Environment Variable

```yaml
# ❌ Wrong: Using wrong file
- run: echo "version=1.0.0" >> "$GITHUB_ENV"  # Creates env var, not output

# ✅ Correct: Using output file
- run: echo "version=1.0.0" >> "$GITHUB_OUTPUT"
```

#### Mistake 3: Forgetting Quotes

```yaml
# ❌ Wrong: Spaces in value without quotes
- run: echo "message=Hello World" >> $GITHUB_OUTPUT  # May fail

# ✅ Correct: Properly quoted
- run: echo "message=Hello World" >> "$GITHUB_OUTPUT"
```

### Relationship to Other Rules

- **[envvar-injection-critical]({{< ref "envvarinjectioncritical.md" >}})**: Detects injection vulnerabilities when writing to `$GITHUB_ENV`
- **[envvar-injection-medium]({{< ref "envvarinjectionmedium.md" >}})**: Similar detection for normal triggers
- **[expression]({{< ref "expressionrule.md" >}})**: Validates expressions used in output values

### Detection Example

Running sisakulint on a workflow with deprecated commands:

```bash
$ sisakulint .github/workflows/ci.yml

.github/workflows/ci.yml:12:13: workflow command "set-output" was deprecated. You should use `echo "{name}={value}" >> $GITHUB_OUTPUT` reference: https://docs.github.com/en/actions/using-workflows/workflow-commands-for-github-actions [deprecated-commands]
    12 👈|        run: echo "::set-output name=version::1.0.0"

.github/workflows/ci.yml:16:13: workflow command "set-env" was deprecated. You should use `echo "{name}={value}" >> $GITHUB_ENV` reference: https://docs.github.com/en/actions/using-workflows/workflow-commands-for-github-actions [deprecated-commands]
    16 👈|        run: echo "::set-env name=MY_VAR::value"
```

### References

- [GitHub Blog: set-env and add-path Deprecation (Oct 2020)](https://github.blog/changelog/2020-10-01-github-actions-deprecating-set-env-and-add-path-commands/)
- [GitHub Blog: save-state and set-output Deprecation (Oct 2022)](https://github.blog/changelog/2022-10-11-github-actions-deprecating-save-state-and-set-output-commands/)
- [GitHub Docs: Workflow Commands](https://docs.github.com/en/actions/using-workflows/workflow-commands-for-github-actions)
- [GitHub Docs: Setting Outputs](https://docs.github.com/en/actions/using-jobs/defining-outputs-for-jobs)

### Testing

To test this rule:

```bash
# Detect deprecated commands
sisakulint .github/workflows/*.yml
```

### Configuration

This rule is enabled by default. To disable it:

```bash
sisakulint -ignore deprecated-commands
```

Disabling this rule is **strongly discouraged** as deprecated commands represent security vulnerabilities and will eventually stop working.
