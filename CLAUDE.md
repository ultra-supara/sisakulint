# CLAUDE.md

This file provides guidance to Claude Code when working with this repository.

## What is sisakulint?

sisakulint is a static analysis tool for GitHub Actions workflow files. It analyzes `.github/workflows/*.yml` files for security issues and best practices, implementing OWASP Top 10 CI/CD Security Risks checks.

## Quick Start

```bash
# Build and run
go build ./cmd/sisakulint
sisakulint

# Run with debug output
sisakulint -debug

# Run tests
go test ./...

# Auto-fix issues
sisakulint -fix on
```

## Core Concepts

### Architecture


## Code Architecture

sisakulint is a static analysis tool for GitHub Actions workflow files (.github/workflows/*.yml or .yaml). It analyzes these files for security issues and best practices.

### Key Components

1. **Command Structure**:
   - Entry point is in `cmd/sisakulint/main.go`
   - Core command handling in `pkg/core/command.go`

2. **Linting Engine**:
   - `pkg/core/linter.go` - Main linting logic
   - `pkg/core/validate.go` - Workflow validation

3. **Rules System**:
   - Each rule is implemented in a separate file (all implementing the `Rule` interface):
     - `pkg/core/idrule.go` - **RuleID**: ID collision detection for jobs and environment variables
     - `pkg/core/credential.go` - **CredentialRule**: Hardcoded credentials detection
     - `pkg/core/permissionrule.go` - **PermissionRule**: Permissions scope and value validation
     - `pkg/core/commitsha.go` - **CommitSHARule**: Validates commit SHA usage in actions (not visible in struct grep but exists)
     - `pkg/core/workflowcall.go` - **RuleWorkflowCall**: Reusable workflow call validation
     - `pkg/core/timeout_minutes.go` - **TimeoutMinutesRule**: Ensures timeout-minutes is set
     - `pkg/core/environmentvariablerule.go` - **EnvironmentVariableRule**: Environment variable name formatting (not visible in struct grep but exists)
     - `pkg/core/exprrule.go` - **ExprRule**: GitHub Actions expression syntax validation
     - `pkg/core/conditionalrule.go` - **ConditionalRule**: Conditional expression validation
     - `pkg/core/issueinjection.go` - **IssueInjection**: Script injection and untrusted input detection
     - `pkg/core/untrustedcheckout.go` - **UntrustedCheckoutRule**: Detects checkout of untrusted PR code in privileged workflow contexts (pull_request_target, issue_comment, workflow_run)
     - `pkg/core/duprecate_commands_pattern.go` - **RuleDeprecatedCommands**: Deprecated workflow commands detection
     - `pkg/core/actionlist.go` - **ActionList**: Action whitelist/blacklist enforcement
     - `pkg/core/rule_add_temp_normal.go` - **AddRule**: Template rule for adding new rules

4. **AST Processing**:
   - `pkg/ast/ast_type.go` - AST node type definitions (Workflow, Job, Step, etc.)
   - `pkg/ast/ast_func.go` - AST utility functions
   - `pkg/core/visitor.go` - **SyntaxTreeVisitor**: Orchestrates tree traversal with depth-first order
   - `pkg/core/visit.go` - Visit helper functions
   - `pkg/core/parse_main.go` - Main workflow file parsing
   - `pkg/core/parse_sub.go` - Sub-component parsing (jobs, steps, etc.)
   - `pkg/core/parse_sbom.go` - SBOM (Software Bill of Materials) parsing

5. **Expression Handling**:
   - `pkg/expressions/parser.go` - Expression parser for `${{ }}` syntax
   - `pkg/expressions/expression.go` - Expression evaluation logic
   - `pkg/expressions/semantic.go` - Semantic analysis
   - `pkg/expressions/tokenizer.go` - Tokenization of expressions
   - `pkg/expressions/ast.go` - Expression AST nodes
   - `pkg/expressions/anti_untrustedchecker.go` - Untrusted input detection
   - `pkg/expressions/anti_untrustedmap.go` - Mapping of untrusted contexts
   - `pkg/core/exprchecker.go` - Expression validation logic
   - `pkg/core/needs.go` - Job dependency (needs) validation

6. **Output Handling**:
   - `pkg/core/errorformatter.go` - Formatting error output
   - `pkg/core/sarif.go` - SARIF output support for reviewdog integration

7. **Auto-fixing**:
   - `pkg/core/autofixer.go` - Auto-fixing framework with three fixer types:
     - **AutoFixer** interface - Base interface for all fixers
     - **StepFixer** interface - Fixes issues at the step level
     - **JobFixer** interface - Fixes issues at the job level
     - **funcFixer** - Generic function-based fixer
   - Rules implementing auto-fix: TimeoutMinutesRule, CommitSHARule, CredentialRule

8. **Remote Analysis**:
   - `pkg/remote/fetcher.go` - GitHub API integration for fetching workflows
   - `pkg/remote/scanner.go` - Remote repository scanning logic
   - `pkg/remote/input.go` - Input parsing for remote repository specifications
   - Supports multiple input formats:
     - `owner/repo` - Single repository
     - `org:organization` - All repositories in an organization
     - With flags for recursive scanning and depth control

### Data Flow

1. The tool scans a directory for GitHub Actions workflow files
2. Files are parsed into AST representation
3. Rules are applied to the AST
4. Issues are collected and reported
5. Auto-fix is applied if requested

## Configuration

The tool can be configured using a `.github/action.yaml` file (created using `sisakulint -init`).

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

## Key Files

- `pkg/core/rule.go` - Rule interface and BaseRule
- `pkg/core/visitor.go` - SyntaxTreeVisitor orchestration
- `pkg/core/linter.go` - Main linting engine
- `pkg/core/command.go` - CLI handling
- `pkg/ast/ast_type.go` - AST node definitions
- `pkg/expressions/` - GitHub Actions expression parser (`${{ }}` syntax)

## Common Commands

```bash
# Build
go build ./cmd/sisakulint

# Test
go test ./...
go test -v ./pkg/core -run TestSpecificFunction
go test -coverprofile=coverage.out ./...

# Debug
sisakulint -debug
sisakulint -fix dry-run -debug

# Generate config
sisakulint -init
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
│   ├── ast/               # AST definitions
│   ├── core/              # Linting engine + rules
│   ├── expressions/       # ${{ }} expression parser
│   └── remote/            # Remote repo analysis
└── .github/workflows/     # Test workflows
```

## Additional Documentation

- **Architecture Details**: `docs/ARCHITECTURE.md`
- **Development Guide**: `docs/DEVELOPMENT.md`
- **Rule Development**: `docs/RULES_GUIDE.md`
- **Main Docs**: https://sisaku-security.github.io/lint/
- **GitHub Actions**: https://docs.github.com/en/actions
