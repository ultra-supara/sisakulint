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
