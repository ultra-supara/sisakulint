# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

### Building and Running

```bash
# Build the project
go build ./cmd/sisakulint

# Run tests
go test ./...

# Run specific test
go test ./pkg/core/[test_file_test.go]

# Install dependencies
go mod tidy
```

### Development Commands

```bash
# Run sisakulint without parameters (auto-detect .github/workflows)
sisakulint

# Run with debug output
sisakulint -debug

# Output in SARIF format (for reviewdog)
sisakulint -format "{{sarif .}}"

# Generate default config
sisakulint -init

# Generate boilerplate template
sisakulint -boilerplate

# Auto-fix issues
sisakulint -fix on

# Dry-run auto-fix
sisakulint -fix dry-run
```

### Release Process

```bash
# Create a new release tag
git tag v[version]
git push origin v[version]
```

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
   - Each rule is implemented in a separate file:
     - `pkg/core/idrule.go` - ID collision detection
     - `pkg/core/credentialsrule.go` - Hardcoded credentials detection
     - `pkg/core/permissionrule.go` - Permissions validation
     - `pkg/core/commitsharule.go` - Commit SHA usage validation
     - `pkg/core/workflowcall.go` - Workflow call validation
     - `pkg/core/timeout_minutes.go` - Timeout minutes validation

4. **AST Processing**:
   - `pkg/ast/` - Abstract Syntax Tree representation
   - `pkg/core/visit.go` and `pkg/core/visitor.go` - AST traversal

5. **Output Handling**:
   - `pkg/core/errorformatter.go` - Formatting error output
   - SARIF output support in `pkg/core/sarif.go`

6. **Auto-fixing**:
   - `pkg/core/autofixer.go` - Auto-fixing issues

### Data Flow

1. The tool scans a directory for GitHub Actions workflow files
2. Files are parsed into AST representation
3. Rules are applied to the AST
4. Issues are collected and reported
5. Auto-fix is applied if requested

## Configuration

The tool can be configured using a `.github/action.yaml` file (created using `sisakulint -init`).

## Project Structure

```
.
├── cmd/sisakulint     # Command line tool entry point
│   ├── main.go
│
├── pkg/               # Core code
│   ├── ast/           # Abstract Syntax Tree
│   └── core/          # Core functionality
│       ├── linter.go  # Main linting logic
│       ├── rule.go    # Base rule interface
│       └── ...        # Individual rules
│
└── script/            # Utility scripts
```