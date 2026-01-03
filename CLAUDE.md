# CLAUDE.md

This file provides guidance to Claude Code when working with this repository.

## What is sisakulint?

sisakulint is a static analysis tool for GitHub Actions workflow files. It analyzes `.github/workflows/*.yml` files for security issues and best practices, implementing OWASP Top 10 CI/CD Security Risks checks.

**Key Features:**
- Detects injection vulnerabilities, credential exposure, and supply chain attacks
- Validates permissions, timeouts, and workflow configurations
- Supports auto-fixing for many security issues
- SARIF output format for CI/CD integration (e.g., reviewdog)
- Fast parallel analysis with Go concurrency

## Quick Start

```bash
# Build and run
go build ./cmd/sisakulint
sisakulint

# Run with debug output
sisakulint -debug

# Run tests
go test ./...

# Auto-fix issues (dry-run shows changes without modifying files)
sisakulint -fix dry-run
sisakulint -fix on

# SARIF output for CI/CD
sisakulint -format "{{sarif .}}"

# Analyze specific files
sisakulint .github/workflows/ci.yml

# Generate config file
sisakulint -init
```

## Core Concepts

### Architecture

1. **Entry point**: `cmd/sisakulint/main.go` → `pkg/core/command.go`
2. **Workflow files** are parsed into **AST** (`pkg/ast/`)
3. **Rules** (`pkg/core/*rule.go`) visit the AST using the **Visitor pattern**
4. **Issues** are collected and reported (optionally in SARIF format)
5. **Auto-fix** can apply corrections to the AST

### The Rule Interface

All rules embed `BaseRule` and implement the `TreeVisitor` interface:

```go
type Rule interface {
    TreeVisitor                      // Visit AST nodes
    Errors() []*LintingError        // Return collected errors
    RuleNames() string              // Return rule identifier
    AddAutoFixer(AutoFixer)         // Add auto-fixer (optional)
    // ... other methods
}
```

### The Visitor Pattern

Rules implement visitor methods for depth-first AST traversal:

- `VisitWorkflowPre/Post(*Workflow)` - Visit workflow node
- `VisitJobPre/Post(*Job)` - Visit job node (Pre/Post for setup/validation)
- `VisitStep(*Step)` - Visit step node

The `SyntaxTreeVisitor` (`pkg/core/visitor.go`) orchestrates traversal and calls each rule's visitor methods.

## Adding a New Rule

1. Create `pkg/core/myrule.go`:
```go
type MyRule struct {
    BaseRule
}

func (rule *MyRule) VisitJobPre(node *ast.Job) error {
    if /* condition */ {
        rule.Errorf(node.Pos, "error message")
    }
    return nil
}
```

2. Register rule in `pkg/core/linter.go`
3. Add tests in `pkg/core/myrule_test.go`
4. Optional: Implement `StepFixer` or `JobFixer` for auto-fix

See `docs/RULES_GUIDE.md` for detailed guide.

## Implemented Rules

sisakulint includes the following security rules (as of pkg/core/linter.go:500-519):

1. **CredentialsRule** - Detects hardcoded credentials and tokens
2. **JobNeedsRule** - Validates job dependencies
3. **EnvironmentVariableRule** - Checks environment variable usage
4. **IDRule** - Validates workflow/job/step IDs
5. **PermissionsRule** - Enforces least privilege permissions
6. **WorkflowCall** - Validates reusable workflow calls
7. **ExpressionRule** - Parses and validates `${{ }}` expressions
8. **DeprecatedCommandsRule** - Detects deprecated GitHub Actions commands
9. **ConditionalRule** - Validates conditional expressions
10. **TimeoutMinuteRule** - Enforces timeout configurations
11. **IssueInjectionRule** - Detects script injection vulnerabilities
12. **CommitShaRule** - Validates action version pinning
13. **ArtifactPoisoningRule** - Detects artifact poisoning risks
14. **ActionListRule** - Validates allowed/blocked actions
15. **CachePoisoningRule** - Detects cache poisoning vulnerabilities

## Key Files

- `pkg/core/rule.go` - Rule interface and BaseRule
- `pkg/core/visitor.go` - SyntaxTreeVisitor orchestration
- `pkg/core/linter.go` - Main linting engine (rule registration at line ~500)
- `pkg/core/command.go` - CLI handling
- `pkg/ast/ast_type.go` - AST node definitions
- `pkg/expressions/` - GitHub Actions expression parser (`${{ }}` syntax)
- `script/actions/` - Example vulnerable/safe workflow files for testing

## Common Commands

```bash
# Build
go build ./cmd/sisakulint

# Test
go test ./...
go test -v ./pkg/core -run TestSpecificFunction
go test -coverprofile=coverage.out ./...

# Test with example workflows
sisakulint script/actions/
sisakulint script/actions/issueinjection.yaml

# Debug
sisakulint -debug
sisakulint -fix dry-run -debug

# Generate config
sisakulint -init

# Ignore specific errors
sisakulint -ignore "SC2086" -ignore "permissions"

# Generate boilerplate workflow
sisakulint -boilerplate
```

## Exit Codes

- **0** - Success, no problems found
- **1** - Success, problems found
- **2** - Invalid command-line options
- **3** - Fatal error

## Project Structure

```
.
├── cmd/sisakulint/        # CLI entry point
├── pkg/
│   ├── ast/               # AST definitions (workflow, job, step nodes)
│   ├── core/              # Linting engine + rules implementation
│   ├── expressions/       # ${{ }} expression parser
│   └── remote/            # Remote repository analysis
├── script/
│   ├── actions/           # Example vulnerable/safe workflows for testing
├── docs/                  # Rule-specific documentation
└── .github/workflows/     # CI/CD workflows
```

## Development Workflow

### Testing a New Rule

1. Create example workflows in `script/actions/`
   - `myrule.yaml` - Demonstrates the vulnerability
   - `myrule-safe.yaml` - Shows the correct pattern

2. Implement the rule in `pkg/core/myrule.go`

3. Add tests in `pkg/core/myrule_test.go`

4. Register the rule in `pkg/core/linter.go` (around line 500)

5. Test with: `sisakulint script/actions/myrule.yaml`

### Debugging Tips

- Use `-debug` flag to see AST traversal
- Check `pkg/core/visitor.go` to understand visitor pattern execution
- Use `script/actions/` examples to test edge cases
- Run specific tests: `go test -v ./pkg/core -run TestYourRule`

## Auto-Fix System

Rules can implement auto-fix by:

1. Implementing `StepFixer` or `JobFixer` interface
2. Registering the fixer: `rule.AddAutoFixer(fixer)`
3. Testing with: `sisakulint -fix dry-run`

See `pkg/core/permissionrule.go` for auto-fix example.

## Additional Documentation

- **Rule-specific docs**: `docs/*.md` (cachepoisoningrule.md, credentialrules.md, etc.)
- **Example workflows**: `script/actions/` (see script/README.md)
- **Main website**: https://sisaku-security.github.io/lint/
- **GitHub Actions docs**: https://docs.github.com/en/actions
- **OWASP CI/CD Top 10**: https://owasp.org/www-project-top-10-ci-cd-security-risks/

## Important Notes for Claude Code

- When adding/modifying rules, ALWAYS update the rule list in this file
- When adding example workflows to `script/actions/`, document them in `script/README.md`
- Rule registration happens in `pkg/core/linter.go` around line 500-519
- The visitor pattern is depth-first: WorkflowPre → JobPre → Step → JobPost → WorkflowPost
- Auto-fix is optional but highly recommended for actionable rules
